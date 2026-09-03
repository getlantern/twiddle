package twiddle

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// spyConn records each Write as TLS record lengths, which is what a censor
// looking at record sizes and directions actually sees.
type spyConn struct {
	net.Conn
	mu     sync.Mutex
	writes []int
}

func (c *spyConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.mu.Lock()
		c.writes = append(c.writes, recordLens(p[:n])...)
		c.mu.Unlock()
	}
	return n, err
}

func (c *spyConn) snapshot() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]int, len(c.writes))
	copy(out, c.writes)
	return out
}

func recordLens(b []byte) []int {
	var out []int
	for len(b) >= recordHeaderLen {
		n := int(binary.BigEndian.Uint16(b[3:5]))
		total := recordHeaderLen + n
		if total > len(b) {
			out = append(out, len(b))
			break
		}
		out = append(out, total)
		b = b[total:]
	}
	if len(b) > 0 && len(b) < recordHeaderLen {
		out = append(out, len(b))
	}
	return out
}

func TestOpeningRecordSequenceMatchesCover(t *testing.T) {
	for _, host := range MeasuredCovers() {
		t.Run(host, func(t *testing.T) {
			cover := mustCover(t, host)
			k := ticketKey(t)
			cred, err := k.Issue(1, cover.TicketLen)
			if err != nil {
				t.Fatal(err)
			}
			replay := NewReplayCache(8, time.Hour)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			srvDone := make(chan error, 1)
			var serverSpy *spyConn
			go func() {
				c, err := ln.Accept()
				if err != nil {
					srvDone <- err
					return
				}
				serverSpy = &spyConn{Conn: c}
				sc, err := Server(serverSpy, ServerConfig{
					TicketKey: k, Cover: cover, MaxAge: time.Hour, Replay: replay,
				})
				if err == nil {
					sc.Close()
				}
				srvDone <- err
			}()

			raw, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			clientSpy := &spyConn{Conn: raw}
			cc, next, err := Client(clientSpy, ClientConfig{
				Pool: pool(t), Cover: cover, Credential: cred,
			})
			if err != nil {
				t.Fatalf("client: %v", err)
			}
			cc.Close()
			if err := <-srvDone; err != nil {
				t.Fatalf("server: %v", err)
			}
			if next == nil || len(next.Ticket) != cover.TicketLen {
				t.Fatalf("rotated ticket len %d, want %d", len(next.Ticket), cover.TicketLen)
			}

			sw := serverSpy.snapshot()
			// ServerHello, CCS, EncryptedExtensions/Finished remainder.
			// NewSessionTicket is a later write, after the client Finished.
			if len(sw) < 3 {
				t.Fatalf("server writes %v, want at least 3 records", sw)
			}
			if sw[0] != ServerHelloResumedLen {
				t.Errorf("ServerHello %d, want %d", sw[0], ServerHelloResumedLen)
			}
			if sw[1] != len(ChangeCipherSpec()) {
				t.Errorf("server CCS %d, want %d", sw[1], len(ChangeCipherSpec()))
			}
			if sw[2] != cover.ServerEncryptedWire() {
				t.Errorf("server encrypted remainder %d, want %d (burst %d - SH %d - CCS %d)",
					sw[2], cover.ServerEncryptedWire(), cover.ServerOpeningBurst,
					ServerHelloResumedLen, len(ChangeCipherSpec()))
			}
			sum := sw[0] + sw[1] + sw[2]
			if sum != cover.ServerOpeningBurst {
				t.Errorf("first server burst %d, measured %d", sum, cover.ServerOpeningBurst)
			}
			if len(sw) < 4 || sw[3] != sessionTicketWire {
				t.Errorf("NewSessionTicket write %v, want %d after the opening burst", sw[3:], sessionTicketWire)
			}

			cw := clientSpy.snapshot()
			// ClientHello, then CCS, then Finished-sized record.
			if len(cw) < 3 {
				t.Fatalf("client writes %v, want CH + CCS + Finished", cw)
			}
			if cw[1] != len(ChangeCipherSpec()) {
				t.Errorf("client CCS %d, want %d", cw[1], len(ChangeCipherSpec()))
			}
			if cw[2] != cover.ClientEncryptedWire() {
				t.Errorf("client Finished %d, want %d (flight %d)", cw[2], cover.ClientEncryptedWire(), cover.ClientFlight)
			}
			if cw[1]+cw[2] != cover.ClientFlight {
				t.Errorf("client flight %d, measured %d", cw[1]+cw[2], cover.ClientFlight)
			}
		})
	}
}

func TestReplayTakesCoverPath(t *testing.T) {
	cover := mustCover(t, "www.google.com")
	k := ticketKey(t)
	cred, err := k.Issue(7, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}
	replay := NewReplayCache(8, time.Hour)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serve := func() error {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = Server(c, ServerConfig{
			TicketKey: k, Cover: cover, MaxAge: time.Hour, Replay: replay,
		})
		return err
	}

	errCh := make(chan error, 1)
	go func() { errCh <- serve() }()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cc, _, err := Client(raw, ClientConfig{Pool: pool(t), Cover: cover, Credential: cred})
	if err != nil {
		t.Fatalf("first opening: %v", err)
	}
	cc.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("first server: %v", err)
	}

	go func() { errCh <- serve() }()
	raw, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = Client(raw, ClientConfig{Pool: pool(t), Cover: cover, Credential: cred})
	raw.Close()
	if err == nil {
		t.Fatal("client replay succeeded")
	}
	if err := <-errCh; err != ErrNotOurs {
		t.Fatalf("replay got %v, want ErrNotOurs (cover path)", err)
	}
}

func TestMicrosoftCoverUsesSHA384(t *testing.T) {
	cover := mustCover(t, "www.microsoft.com")
	if cover.BinderLen != 48 {
		t.Errorf("microsoft binder %d, captured tickets use 48", cover.BinderLen)
	}
	if cover.CipherSuite != TLS_AES_256_GCM_SHA384 {
		t.Errorf("microsoft cipher %#04x, want TLS_AES_256_GCM_SHA384", cover.CipherSuite)
	}

	k := ticketKey(t)
	cred, err := k.Issue(1, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}
	wire, _, err := Twiddle(pool(t)[0], Options{
		CoverSNI: cover.Host, Credential: cred, BinderLen: cover.BinderLen,
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseClientHello(wire)
	if err != nil {
		t.Fatal(err)
	}
	_, _, binder, err := parsePSK(h.Find(ExtPreSharedKey).Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(binder) != 48 {
		t.Errorf("emitted binder %d bytes, want 48", len(binder))
	}
}

func TestCoverRejectsMismatchedClientHello(t *testing.T) {
	cover := mustCover(t, "www.microsoft.com")
	k := ticketKey(t)
	credential, err := k.Issue(1, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}

	makeHello := func(credential *Credential, sni string, binderLen int) *ClientHello {
		t.Helper()
		wire, _, err := Twiddle(pool(t)[0], Options{
			CoverSNI: sni, Credential: credential, BinderLen: binderLen,
		})
		if err != nil {
			t.Fatal(err)
		}
		h, err := ParseClientHello(wire)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}

	if _, err := cover.validateClientHello(makeHello(credential, cover.Host, cover.BinderLen)); err != nil {
		t.Fatalf("valid ClientHello rejected: %v", err)
	}

	shortCredential, err := k.Issue(1, mustCover(t, "www.google.com").TicketLen)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]*ClientHello{
		"SNI":           makeHello(credential, "www.google.com", cover.BinderLen),
		"ticket length": makeHello(shortCredential, cover.Host, cover.BinderLen),
		"binder length": makeHello(credential, cover.Host, 32),
	}
	withoutCipher := makeHello(credential, cover.Host, cover.BinderLen)
	for i, suite := range withoutCipher.CipherSuites {
		if suite == cover.CipherSuite {
			withoutCipher.CipherSuites = append(withoutCipher.CipherSuites[:i:i], withoutCipher.CipherSuites[i+1:]...)
			break
		}
	}
	cases["cipher suite"] = withoutCipher

	for name, hello := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := cover.validateClientHello(hello); err == nil {
				t.Fatal("mismatched ClientHello accepted")
			}
		})
	}

	if _, _, err := Client(nil, ClientConfig{
		Pool: pool(t), Cover: cover, Credential: shortCredential,
	}); err == nil {
		t.Fatal("client accepted a credential with the wrong ticket length")
	}
}

func TestServerRequiresSharedReplayCache(t *testing.T) {
	_, err := Server(nil, ServerConfig{Cover: mustCover(t, "www.google.com")})
	if err == nil {
		t.Fatal("server accepted a nil replay cache")
	}
}

func TestUnknownCoverIsRejected(t *testing.T) {
	_, err := CoverFor("unmeasured.example")
	if err == nil {
		t.Fatal("unknown cover was accepted")
	}
	_, err = CoverFor("github.com")
	if err == nil {
		t.Fatal("github.com ticket is too short to impersonate")
	}
	cfg := ClientConfig{Pool: pool(t), Cover: CoverProfile{Host: "www.microsoft.com", BinderLen: 32}}
	if _, _, err := Client(nil, cfg); err == nil {
		t.Fatal("a partial microsoft profile (32-byte binder) was accepted")
	}
}
