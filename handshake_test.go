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

// TestEndToEndOverSocket is the Phase 0 goal: a client and server complete the
// opening over a real socket and pass bytes through the record layer.
func TestEndToEndOverSocket(t *testing.T) {
	k := ticketKey(t)
	cred, err := k.Issue(99, DefaultTicketLen)
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
		sc, err := Server(c, ServerConfig{TicketKey: k, MaxAge: time.Hour})
		srvCh <- result{sc, err}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cc, next, err := Client(raw, ClientConfig{
		Pool: pool(t), CoverSNI: "www.microsoft.com", Credential: cred,
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
	badCred, _ := other.Issue(1, DefaultTicketLen)

	cases := map[string]func(net.Conn){
		"garbage":          func(c net.Conn) { c.Write([]byte("not a tls record at all")) },
		"bare TLS hello":   func(c net.Conn) { c.Write(pool(t)[0]) },
		"wrong ticket key": func(c net.Conn) { w, _, _ := Twiddle(pool(t)[0], Options{Credential: badCred, BinderLen: 32}); c.Write(w) },
		"truncated":        func(c net.Conn) { w, _, _ := Twiddle(pool(t)[0], Options{Credential: badCred, BinderLen: 32}); c.Write(w[:40]) },
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
				_, err = Server(c, ServerConfig{TicketKey: k, MaxAge: time.Hour})
				errCh <- err
			}()
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			send(c)
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
	cred, _ := k.Issue(1, DefaultTicketLen)
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
	go Client(raw, ClientConfig{Pool: pool(t), CoverSNI: "www.microsoft.com", Credential: cred})
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
