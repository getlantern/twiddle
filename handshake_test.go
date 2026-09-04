package twiddle

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func pool(t *testing.T) [][]byte {
	t.Helper()
	var out [][]byte
	for _, rec := range realHellos(t) {
		out = append(out, rec)
	}
	return out
}

func mustCover(t *testing.T, host string) CoverProfile {
	t.Helper()
	p, err := CoverFor(host)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestEndToEndOverSocket is the Phase 0 goal: a client and server complete the
// opening over a real socket and pass bytes through the record layer.
func TestEndToEndOverSocket(t *testing.T) {
	k := ticketKey(t)
	cover := mustCover(t, "www.microsoft.com")
	cred, err := k.Issue(99, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		conn *Conn
		err  error
	}
	srvCh := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvCh <- result{nil, err}
			return
		}
		sc, err := Server(c, ServerConfig{
			TicketKey: k, Cover: cover,
			MaxAge: time.Hour, Replay: NewReplayCache(16, time.Hour),
		})
		srvCh <- result{sc, err}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cc, next, err := Client(raw, ClientConfig{
		Pool: pool(t), Cover: cover, Credential: cred,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	r := <-srvCh
	if r.err != nil {
		t.Fatalf("server: %v", r.err)
	}

	// the flight rotated the credential, as NewSessionTicket would
	if next == nil || bytes.Equal(next.Ticket, cred.Ticket) {
		t.Fatal("server did not issue a fresh credential in the flight")
	}
	if _, _, _, err := k.Open(next.Ticket); err != nil {
		t.Fatalf("rotated ticket does not open: %v", err)
	}
	// Rotation must carry BOTH tickets. Rotating only the resumption ticket
	// would let the full-handshake companion age out of MaxAge while the
	// client kept working, silently collapsing it back to resumption-only.
	if len(next.FullTicket) != FullTicketLen {
		t.Fatalf("rotated credential carries a %d-byte full ticket, want %d", len(next.FullTicket), FullTicketLen)
	}
	if _, _, _, err := k.Open(next.FullTicket); err != nil {
		t.Fatalf("rotated full ticket does not open: %v", err)
	}

	payload := make([]byte, 60000)
	rand.Read(payload)
	go func() {
		r.conn.Write(payload)
		r.conn.Close()
	}()
	got, err := io.ReadAll(cc)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	t.Logf("opened, rotated credential, and carried %d bytes", len(got))
}

// TestServerRejectsUnauthenticated: anything that fails auth must come back as
// ErrNotOurs so the adapter can forward it to the cover site.
func TestServerRejectsUnauthenticated(t *testing.T) {
	k := ticketKey(t)
	other := ticketKey(t)
	cover := mustCover(t, "www.microsoft.com")
	badCred, _ := other.Issue(1, cover.TicketLen)

	// Each case returns its write error. Swallowing it let a case "pass" on a
	// failed write: Server sees EOF, returns ErrNotOurs, and the assertion holds
	// without the case's input ever reaching the wire.
	cases := map[string]func(net.Conn) error{
		"garbage": func(c net.Conn) error {
			_, err := c.Write([]byte("not a tls record at all"))
			return err
		},
		"bare TLS hello": func(c net.Conn) error {
			_, err := c.Write(pool(t)[0])
			return err
		},
		"wrong ticket key": func(c net.Conn) error {
			w, _, err := Twiddle(pool(t)[0], Options{
				CoverSNI: cover.Host, Credential: badCred, BinderLen: cover.BinderLen,
			})
			if err != nil {
				return err
			}
			_, err = c.Write(w)
			return err
		},
		"truncated": func(c net.Conn) error {
			w, _, err := Twiddle(pool(t)[0], Options{
				CoverSNI: cover.Host, Credential: badCred, BinderLen: cover.BinderLen,
			})
			if err != nil {
				return err
			}
			_, err = c.Write(w[:40])
			return err
		},
	}
	for name, send := range cases {
		t.Run(name, func(t *testing.T) {
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			defer ln.Close()
			errCh := make(chan error, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					errCh <- err
					return
				}
				c.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, err = Server(c, ServerConfig{
					TicketKey: k, Cover: cover,
					MaxAge: time.Hour, Replay: NewReplayCache(16, time.Hour),
				})
				errCh <- err
			}()
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if err := send(c); err != nil {
				t.Fatalf("case input never reached the wire: %v", err)
			}
			if err := <-errCh; err != ErrNotOurs {
				t.Fatalf("got %v, want ErrNotOurs", err)
			}
			c.Close()
		})
	}
}

// TestOpeningLooksLikeTLS checks the bytes a censor actually sees.
func TestOpeningLooksLikeTLS(t *testing.T) {
	k := ticketKey(t)
	cover := mustCover(t, "www.microsoft.com")
	cred, _ := k.Issue(1, cover.TicketLen)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	captured := make(chan []byte, 1)
	go func() {
		c, _ := ln.Accept()
		defer c.Close()
		var seen []byte
		buf := make([]byte, 8192)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		for len(seen) < 5 {
			n, err := c.Read(buf)
			seen = append(seen, buf[:n]...)
			if err != nil {
				break
			}
		}
		captured <- seen
	}()
	raw, _ := net.Dial("tcp", ln.Addr().String())
	go Client(raw, ClientConfig{Pool: pool(t), Cover: cover, Credential: cred})
	first := <-captured

	if len(first) < 5 {
		t.Fatal("nothing captured")
	}
	if first[0] != 0x16 || first[1] != 0x03 || first[2] != 0x01 {
		t.Errorf("opening bytes are % x, want a TLS handshake record 16 03 01", first[:3])
	}
	n := int(binary.BigEndian.Uint16(first[3:5]))
	if n < 1400 || n > 2600 {
		t.Errorf("ClientHello length %d is outside the range real Chrome produces", n)
	}
	t.Logf("first bytes on the wire: % x ... (%d-byte ClientHello)", first[:5], n)
}

func TestSynthesizedServerHelloMatchesMeasuredLength(t *testing.T) {
	k := ticketKey(t)
	cred, _ := k.Issue(1, DefaultTicketLen)
	wire, _, err := Twiddle(pool(t)[0], Options{Credential: cred, BinderLen: 32})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := ParseClientHello(wire)
	eph, _ := h.KeyShare()

	// The full variant omits pre_shared_key, and that omission is the ENTIRE
	// difference between the two measured lengths -- 6 bytes: type, length and
	// selected_identity. Both are point targets from
	// harvest/testdata/postflight-full-vs-resumed.log, not ranges.
	if ServerHelloResumedLen-ServerHelloFullLen != 6 {
		t.Errorf("the measured lengths differ by %d, not the 6 bytes pre_shared_key occupies",
			ServerHelloResumedLen-ServerHelloFullLen)
	}
	for _, full := range []bool{false, true} {
		for _, pskFirst := range []bool{false, true} {
			sh, err := SynthesizeServerHello(ServerHelloParams{
				SessionIDEcho: h.SessionID, ServerEphemeral: eph,
				PSKFirst: pskFirst, FullHandshake: full,
			})
			if err != nil {
				t.Fatal(err)
			}
			want := ServerHelloResumedLen
			if full {
				want = ServerHelloFullLen
			}
			if len(sh) != want {
				t.Errorf("full=%v PSKFirst=%v: ServerHello is %d bytes, measured %d",
					full, pskFirst, len(sh), want)
			}
		}
	}

	for _, pskFirst := range []bool{false, true} {
		sh, err := SynthesizeServerHello(ServerHelloParams{
			SessionIDEcho: h.SessionID, ServerEphemeral: eph, PSKFirst: pskFirst,
		})
		if err != nil {
			t.Fatal(err)
		}
		// Every one of five real servers produced exactly this for a resumed
		// handshake; it is a point target, not a range.
		if len(sh) != ServerHelloResumedLen {
			t.Errorf("PSKFirst=%v: ServerHello is %d bytes, measured %d",
				pskFirst, len(sh), ServerHelloResumedLen)
		}
		if sh[0] != 0x16 || sh[5] != 0x02 {
			t.Errorf("not a ServerHello record: % x", sh[:6])
		}
		if !bytes.Equal(sh[9+2+32+1:9+2+32+1+len(h.SessionID)], h.SessionID) {
			t.Error("ServerHello does not echo legacy_session_id")
		}
		back, err := ServerEphemeralFromShare(sh)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(back.Bytes(), eph.Bytes()) {
			t.Error("server ephemeral does not survive the hybrid share")
		}
	}
	t.Logf("synthesised ServerHello is exactly %d B in both extension orders", ServerHelloResumedLen)
}

// TestEmittedHelloMatchesHarvestedLength: with the ticket length chosen to match
// the one the harvested hello already carried, our emission must be the same
// size as what the browser produced -- differing only by the ECH GREASE bucket,
// which Chrome itself varies per connection.
func TestEmittedHelloMatchesHarvestedLength(t *testing.T) {
	k := ticketKey(t)
	checked := 0
	for name, rec := range realHellos(t) {
		h, err := ParseClientHello(rec)
		if err != nil {
			t.Fatal(err)
		}
		e := h.Find(ExtPreSharedKey)
		if e == nil {
			continue // only resumption hellos carry a ticket to match
		}
		origTicket, _, origBinder, err := parsePSK(e.Data)
		if err != nil {
			continue
		}
		cred, err := k.Issue(1, len(origTicket))
		if err != nil {
			continue // ticket shorter than our minimum; nothing to compare
		}
		wire, _, err := Twiddle(rec, Options{
			CoverSNI:   h.SNI(), // same SNI, so no length change from that
			Credential: cred,
			BinderLen:  len(origBinder),
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		delta := len(wire) - len(rec)
		// ECH GREASE moves in 32-byte buckets across a 96-byte span.
		if delta%32 != 0 || delta < -96 || delta > 96 {
			t.Errorf("%s: emitted %d B vs harvested %d B (delta %+d) -- not explained by the ECH bucket",
				name, len(wire), len(rec), delta)
		}
		checked++
	}
	if checked == 0 {
		t.Skip("no resumption hellos with a long enough ticket in the corpus")
	}
	t.Logf("length parity holds for %d harvested resumption hellos (ECH bucket only)", checked)
}

func TestTicketLenForCover(t *testing.T) {
	for host, want := range map[string]int{
		"www.cloudflare.com": 176, "www.google.com": 230,
		"www.microsoft.com": 256, "unknown.example": DefaultTicketLen,
	} {
		if got := TicketLenForCover(host); got != want {
			t.Errorf("%s: got %d, want %d", host, got, want)
		}
	}
}

// TestServerConfigPSKFirstReachesTheWire guards a dead-option bug: PSKFirst was
// exposed in configuration but never threaded into the synthesised ServerHello,
// so setting it did nothing at all.
func TestServerConfigPSKFirstReachesTheWire(t *testing.T) {
	h, err := ParseClientHello(pool(t)[0])
	if err != nil {
		t.Fatal(err)
	}
	eph, err := h.SetKeyShare()
	if err != nil {
		t.Fatal(err)
	}
	for _, first := range []bool{false, true} {
		sh, err := SynthesizeServerHello(ServerHelloParams{
			SessionIDEcho: h.SessionID, ServerEphemeral: eph.PublicKey(), PSKFirst: first,
		})
		if err != nil {
			t.Fatal(err)
		}
		exts := serverHelloExtOrder(t, sh)
		if len(exts) < 2 {
			t.Fatalf("ServerHello has %d extensions", len(exts))
		}
		if first && exts[0] != ExtPreSharedKey {
			t.Errorf("PSKFirst=true but the first extension is %#04x", exts[0])
		}
		if !first && exts[len(exts)-1] != ExtPreSharedKey {
			t.Errorf("PSKFirst=false but the last extension is %#04x", exts[len(exts)-1])
		}
		if len(sh) != ServerHelloResumedLen {
			t.Errorf("PSKFirst=%v changed the length to %d", first, len(sh))
		}
	}
}

func serverHelloExtOrder(t *testing.T, sh []byte) []uint16 {
	t.Helper()
	b := sh[9:]
	p := 2 + 32
	p += 1 + int(b[p])
	p += 3
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	p += 2
	var out []uint16
	for p+4 <= end && p+4 <= len(b) {
		out = append(out, binary.BigEndian.Uint16(b[p:p+2]))
		p += 4 + int(binary.BigEndian.Uint16(b[p+2:p+4]))
	}
	return out
}

// writeTickets emits contentHandshake and nothing else. Accepting
// application_data would widen what can be mistaken for a rotated credential:
// after the opening the tunnel carries app-data records, so a lenient check
// would parse the first of them as a ticket instead of failing.
func TestReadTicketsRejectsNonHandshakeRecords(t *testing.T) {
	cover := mustCover(t, "www.microsoft.com")
	sess, err := DeriveSession(make([]byte, 32), make([]byte, 32), cover.CipherSuite)
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	wSess, err := DeriveSession(make([]byte, 32), make([]byte, 32), cover.CipherSuite)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewConn(server, wSess, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewConn(client, sess, true, nil)
	if err != nil {
		t.Fatal(err)
	}

	// A well-formed credential body, but sent as application_data.
	body := make([]byte, 2+16+32)
	body[1] = 16
	go func() { _ = w.writeSized(contentAppData, body, sessionTicketWire) }()

	if _, err := readTickets(r); err == nil {
		t.Error("readTickets accepted an application_data record as a rotated credential")
	}
}

// fullCover returns a microsoft profile with a full-handshake shape adopted.
// The table ships none on purpose -- the certificate flight cannot be a
// constant -- so a test that needs one must supply it the way an egress does,
// through Adopt, which also exercises the adoption path.
func fullCover(t *testing.T) CoverProfile {
	t.Helper()
	base := mustCover(t, "www.microsoft.com")
	// harvest/testdata/postflight-full-vs-resumed.log
	remainder := []int{32, 8273, 286, 74}
	burst := ServerHelloFullLen + len(ChangeCipherSpec())
	for _, n := range remainder {
		burst += n
	}
	p, err := base.Adopt(ProbeResult{
		Host: base.Host, Full: true,
		ServerHello:     ServerHelloFullLen,
		Remainder:       remainder,
		RemainderJitter: []int{0, 1, 0, 0},
		OpeningBurst:    burst,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !p.CanEmitFullHandshake() {
		t.Fatal("adopted profile still cannot emit a full handshake")
	}
	return p
}

// The full-handshake path end to end: no pre_shared_key anywhere, a 1215-byte
// ServerHello, a certificate-sized remainder, and bytes through the tunnel.
func TestEndToEndFullHandshake(t *testing.T) {
	k := ticketKey(t)
	cover := fullCover(t)
	cred, err := k.Issue(77, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		conn *Conn
		err  error
	}
	srvCh := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srvCh <- result{nil, err}
			return
		}
		sc, err := Server(c, ServerConfig{
			TicketKey: k, Cover: cover,
			MaxAge: time.Hour, Replay: NewReplayCache(16, time.Hour),
		})
		srvCh <- result{sc, err}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cc, next, err := Client(raw, ClientConfig{
		Pool: pool(t), Cover: cover, Credential: cred, FullHandshake: true,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	r := <-srvCh
	if r.err != nil {
		t.Fatalf("server: %v", r.err)
	}
	if next == nil || len(next.FullTicket) != FullTicketLen {
		t.Fatal("the full-handshake flight did not rotate both tickets")
	}

	payload := make([]byte, 40000)
	rand.Read(payload)
	go func() {
		r.conn.Write(payload)
		r.conn.Close()
	}()
	got, err := io.ReadAll(cc)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	t.Logf("opened a full handshake and carried %d bytes", len(got))
}

// What the censor counts. The server's answer to a full handshake must be a
// 1215-byte ServerHello, a ChangeCipherSpec, and one record per FullRemainder
// entry -- microsoft's four, not a single coalesced blob. A fixed record count
// here was the bug the resumed path already hit from the other side.
func TestServerAnswersAFullHandshakeWithTheMeasuredShape(t *testing.T) {
	k := ticketKey(t)
	cover := fullCover(t)
	cred, err := k.Issue(78, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		Server(c, ServerConfig{
			TicketKey: k, Cover: cover,
			MaxAge: time.Hour, Replay: NewReplayCache(16, time.Hour),
		})
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))

	wire, _, err := Twiddle(pool(t)[0], Options{
		CoverSNI: cover.Host, Credential: cred, FullHandshake: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The opening itself must read as a full handshake.
	h, err := ParseClientHello(wire)
	if err != nil {
		t.Fatal(err)
	}
	if h.Find(ExtPreSharedKey) != nil {
		t.Fatal("the emitted opening carries pre_shared_key; it still reads as a resumption")
	}
	if _, err := raw.Write(wire); err != nil {
		t.Fatal(err)
	}

	sh, err := readRecord(raw)
	if err != nil {
		t.Fatalf("ServerHello: %v", err)
	}
	if len(sh) != ServerHelloFullLen {
		t.Errorf("ServerHello is %d bytes, want the full-handshake %d", len(sh), ServerHelloFullLen)
	}
	if _, err := readRecord(raw); err != nil { // ChangeCipherSpec
		t.Fatalf("ChangeCipherSpec: %v", err)
	}

	var got []int
	for range cover.FullRemainder {
		rec, err := readRecord(raw)
		if err != nil {
			t.Fatalf("remainder record %d of %d: %v", len(got)+1, len(cover.FullRemainder), err)
		}
		got = append(got, len(rec))
	}
	if len(got) != len(cover.FullRemainder) {
		t.Fatalf("read %d remainder records, want %d", len(got), len(cover.FullRemainder))
	}
	for i, n := range got {
		lo := cover.FullRemainder[i]
		hi := lo + cover.FullRemainderJitter[i]
		if n < lo || n > hi {
			t.Errorf("remainder record %d is %d bytes, outside the sampled [%d, %d]", i, n, lo, hi)
		}
	}
	// A fifth record would mean the server coalesced or split differently than
	// the identity it claims.
	raw.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if extra, err := readRecord(raw); err == nil {
		t.Errorf("server sent an unexpected %d-byte record after the remainder", len(extra))
	}
	t.Logf("full opening: SH %d, ccs %d, remainder %v", len(sh), len(ChangeCipherSpec()), got)
}

// The two ways a client can ask for a shape it cannot produce.
func TestFullHandshakeRefusesWhatItCannotBack(t *testing.T) {
	k := ticketKey(t)

	t.Run("cover has no measured full profile", func(t *testing.T) {
		cover := mustCover(t, "www.microsoft.com") // table default: no FullRemainder
		cred, _ := k.Issue(79, cover.TicketLen)
		_, _, err := Client(nil, ClientConfig{
			Pool: pool(t), Cover: cover, Credential: cred, FullHandshake: true,
		})
		if err == nil {
			t.Fatal("a full handshake was attempted against a cover with no measured profile")
		}
		if !contains(err.Error(), "full-handshake profile") {
			t.Errorf("unhelpful error: %v", err)
		}
	})

	t.Run("server has no measured full profile", func(t *testing.T) {
		// The client gate is not the only one that matters: a server whose cover
		// was never probed must refuse rather than answer with a guessed
		// certificate flight, which would be a distinguisher of its own.
		emit := fullCover(t)
		serve := mustCover(t, "www.microsoft.com") // table default
		cred, _ := k.Issue(81, emit.TicketLen)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		errCh := make(chan error, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				errCh <- err
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			_, err = Server(c, ServerConfig{
				TicketKey: k, Cover: serve,
				MaxAge: time.Hour, Replay: NewReplayCache(16, time.Hour),
			})
			errCh <- err
		}()
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		wire, _, err := Twiddle(pool(t)[0], Options{
			CoverSNI: emit.Host, Credential: cred, FullHandshake: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Write(wire); err != nil {
			t.Fatal(err)
		}
		if err := <-errCh; err != ErrNotOurs {
			t.Fatalf("got %v, want ErrNotOurs -- the server answered a shape it has not measured", err)
		}
	})

	t.Run("credential has no companion ticket", func(t *testing.T) {
		cover := fullCover(t)
		cred, _ := k.Issue(80, cover.TicketLen)
		cred.FullTicket = nil // as CredentialFromWire would leave it
		_, _, err := Twiddle(pool(t)[0], Options{
			CoverSNI: cover.Host, Credential: cred, FullHandshake: true,
		})
		if err == nil {
			t.Fatal("a full handshake was emitted from a resumption-only credential")
		}
		if !contains(err.Error(), "full ticket") {
			t.Errorf("unhelpful error: %v", err)
		}
	})
}

// The regression the pool filter exists for. With one carrier among many
// hellos that cannot carry a ticket, a client drawing uniformly succeeds only
// about a sixth of the time; the failure depends on the draw, so it would
// present as a flaky connection rather than a broken configuration.
func TestClientAlwaysPicksACarrierFromAMixedPool(t *testing.T) {
	k := ticketKey(t)
	cover := fullCover(t)
	base := DefaultPool()[0]
	mixed := [][]byte{
		stripECH(t, base),
		shrinkECH(t, base, FullTicketLen-1),
		shrinkECH(t, base, 16),
		shrinkECH(t, base, 100),
		stripECH(t, base),
		base, // the only carrier
	}

	for i := 0; i < 12; i++ {
		cred, err := k.Issue(uint64(200+i), cover.TicketLen)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			Server(c, ServerConfig{
				TicketKey: k, Cover: cover,
				MaxAge: time.Hour, Replay: NewReplayCache(16, time.Hour),
			})
		}()
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			ln.Close()
			t.Fatal(err)
		}
		_, _, err = Client(raw, ClientConfig{
			Pool: mixed, Cover: cover, Credential: cred, FullHandshake: true,
		})
		raw.Close()
		ln.Close()
		if err != nil {
			t.Fatalf("attempt %d of 12 failed: %v -- the pool draw is not restricted to carriers", i+1, err)
		}
	}
}

// And a pool with no carrier at all must fail clearly, not on the draw.
func TestFullHandshakeWithNoCarrierInThePoolFailsClearly(t *testing.T) {
	k := ticketKey(t)
	cover := fullCover(t)
	cred, _ := k.Issue(210, cover.TicketLen)
	none := [][]byte{stripECH(t, DefaultPool()[0]), shrinkECH(t, DefaultPool()[0], 32)}

	_, _, err := Client(nil, ClientConfig{
		Pool: none, Cover: cover, Credential: cred, FullHandshake: true,
	})
	if err == nil {
		t.Fatal("a full handshake was attempted from a pool with no carrier")
	}
	if !contains(err.Error(), "ECH payload") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// dialOnce runs one full client/server exchange and reports the shape each end
// believes it used. Both are returned because a disagreement is the failure
// worth catching: the two ends would then be reading different record counts.
func dialOnce(t *testing.T, k *TicketKey, cover CoverProfile, cfg ClientConfig, replay *ReplayCache) (clientFull, serverFull bool, err error) {
	t.Helper()
	ln, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatal(lerr)
	}
	defer ln.Close()

	type sres struct {
		full bool
		err  error
	}
	srvCh := make(chan sres, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			srvCh <- sres{false, aerr}
			return
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		sc, serr := Server(c, ServerConfig{
			TicketKey: k, Cover: cover, MaxAge: time.Hour, Replay: replay,
		})
		if serr != nil {
			srvCh <- sres{false, serr}
			return
		}
		srvCh <- sres{sc.FullHandshake(), nil}
	}()

	raw, derr := net.Dial("tcp", ln.Addr().String())
	if derr != nil {
		t.Fatal(derr)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	cc, _, cerr := Client(raw, cfg)
	r := <-srvCh
	if cerr != nil {
		return false, false, cerr
	}
	if r.err != nil {
		return false, false, r.err
	}
	return cc.FullHandshake(), r.full, nil
}

// The mix policy end to end: the first connection to an egress is a full
// handshake, and the next one resumes. That is the whole point -- a resumption
// with no observable predecessor is the distinguisher, and one full handshake
// per egress removes it.
func TestContactsMakeFirstContactFullAndTheNextResumed(t *testing.T) {
	k := ticketKey(t)
	cover := fullCover(t)
	replay := NewReplayCache(64, time.Hour)
	mem := NewContactMemory(time.Hour, 0)

	cred, err := k.Issue(300, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ClientConfig{Pool: pool(t), Cover: cover, Credential: cred, Contacts: mem}

	cf, sf, err := dialOnce(t, k, cover, cfg, replay)
	if err != nil {
		t.Fatalf("first connection: %v", err)
	}
	if !cf || !sf {
		t.Fatalf("first contact was client-full=%v server-full=%v, want both true", cf, sf)
	}
	if mem.Tracked() != 1 {
		t.Fatalf("the completed full handshake was not recorded (%d contacts)", mem.Tracked())
	}

	// A fresh credential, as rotation would supply, so the second connection
	// fails for shape reasons rather than a spent ticket.
	cfg.Credential, err = k.Issue(300, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}
	cf, sf, err = dialOnce(t, k, cover, cfg, replay)
	if err != nil {
		t.Fatalf("second connection: %v", err)
	}
	if cf || sf {
		t.Errorf("the second connection was client-full=%v server-full=%v, want both false", cf, sf)
	}

	// And past the horizon it re-fulls, because the censor can no longer be
	// assumed to remember.
	mem.Reset()
	cfg.Credential, err = k.Issue(300, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}
	cf, _, err = dialOnce(t, k, cover, cfg, replay)
	if err != nil {
		t.Fatalf("third connection: %v", err)
	}
	if !cf {
		t.Error("after the relationship was forgotten the client did not re-full")
	}
}

// A Contacts-driven choice degrades rather than failing when the cover has no
// measured full profile, because refusing the connection would make enabling
// Contacts depend on every cover having been probed first. The degradation must
// not be recorded, or it would latch: one silent resumption would look like a
// satisfied relationship forever.
func TestContactsDegradeWhenTheCoverCannotBackAFullHandshake(t *testing.T) {
	k := ticketKey(t)
	cover := mustCover(t, "www.microsoft.com") // table default: no full profile
	mem := NewContactMemory(time.Hour, 0)
	cred, err := k.Issue(310, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}

	cf, sf, err := dialOnce(t, k, cover,
		ClientConfig{Pool: pool(t), Cover: cover, Credential: cred, Contacts: mem},
		NewReplayCache(64, time.Hour))
	if err != nil {
		t.Fatalf("the connection was refused instead of degrading: %v", err)
	}
	if cf || sf {
		t.Errorf("client-full=%v server-full=%v against a cover with no full profile", cf, sf)
	}
	if mem.Tracked() != 0 {
		t.Error("a degraded connection was recorded as a completed full handshake; it would never retry")
	}
}

// The same degradation for a pool that cannot carry the ticket -- the non-ECH
// pool docs/ech.md keeps as an escape hatch. Connectivity must survive it.
func TestContactsDegradeWhenThePoolCannotCarryTheTicket(t *testing.T) {
	k := ticketKey(t)
	cover := fullCover(t)
	mem := NewContactMemory(time.Hour, 0)
	cred, err := k.Issue(320, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}
	none := [][]byte{stripECH(t, DefaultPool()[0]), stripECH(t, DefaultPool()[1])}

	cf, _, err := dialOnce(t, k, cover,
		ClientConfig{Pool: none, Cover: cover, Credential: cred, Contacts: mem},
		NewReplayCache(64, time.Hour))
	if err != nil {
		t.Fatalf("a pool with no carrier refused the connection instead of degrading: %v", err)
	}
	if cf {
		t.Error("claimed a full handshake from a pool that cannot carry the ticket")
	}
	if mem.Tracked() != 0 {
		t.Error("a degraded connection was recorded")
	}
}

// A full handshake that FAILED established no relationship, so it must not be
// recorded. Recording on attempt rather than completion is the subtle version
// of the bug this whole mechanism exists to prevent: the next connection would
// resume against an egress the censor never saw a completed handshake with,
// which is exactly the structurally impossible shape.
func TestContactsRecordOnlyCompletedHandshakes(t *testing.T) {
	k := ticketKey(t)
	cover := fullCover(t)
	mem := NewContactMemory(time.Hour, 0)
	cred, err := k.Issue(330, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}

	// A server that reads the opening and then hangs up, so the client's full
	// handshake reaches the wire but never completes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		readRecord(c) // consume the ClientHello, answer nothing
		c.Close()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	local, remote := raw.LocalAddr(), raw.RemoteAddr()

	if _, _, err := Client(raw, ClientConfig{
		Pool: pool(t), Cover: cover, Credential: cred, Contacts: mem,
	}); err == nil {
		t.Fatal("the client reported success against a server that answered nothing")
	}

	if mem.Tracked() != 0 {
		t.Errorf("a failed full handshake was recorded (%d contacts)", mem.Tracked())
	}
	if !mem.needsFull(local, remote, time.Now()) {
		t.Error("after a FAILED full handshake the next connection would resume, with no completed predecessor for a censor to have seen")
	}
}
