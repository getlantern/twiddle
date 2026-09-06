package twiddle

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// tamperingProxy relays between client and server, flipping one bit in the Nth
// record the SERVER sends. Record 0 is the ServerHello, record 1 the
// ChangeCipherSpec.
func tamperingProxy(t *testing.T, upstream string, record, offset int) net.Listener {
	t.Helper()
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
		up, err := net.Dial("tcp", upstream)
		if err != nil {
			return
		}
		defer up.Close()
		go io.Copy(up, c)

		for i := 0; ; i++ {
			var hdr [recordHeaderLen]byte
			if _, err := io.ReadFull(up, hdr[:]); err != nil {
				return
			}
			body := make([]byte, int(binary.BigEndian.Uint16(hdr[3:5])))
			if _, err := io.ReadFull(up, body); err != nil {
				return
			}
			rec := append(hdr[:], body...)
			if i == record && offset >= 0 && offset < len(rec) {
				rec[offset] ^= 0x01
			}
			if _, err := c.Write(rec); err != nil {
				return
			}
			if i >= record {
				io.Copy(c, up)
				return
			}
		}
	}()
	return ln
}

// An on-path attacker must not be able to alter the opening and have the
// handshake still succeed. This is an ACTIVE distinguisher, not a passive one:
// a censor flips one byte in a ServerHello and watches whether the connection
// survives. A genuine TLS 1.3 client aborts -- RFC 8446 4.1.3 requires the
// legacy_session_id_echo to match, and the server Finished MACs the whole
// transcript -- so a peer that sails on is visibly not TLS.
//
// Before DeriveSession took a transcript, SIX of the seven fields below were
// accepted. The client pulled the X25519 half out of the key_share, did the
// ECDH, and derived keys from the psk and its OWN configured cipher suite, so
// nothing else in the ServerHello was load-bearing. Only the X25519 half was
// caught, and only because it breaks the ECDH.
func TestOnPathServerHelloTamperingBreaksTheHandshake(t *testing.T) {
	// Offsets into the ServerHello record, from SynthesizeServerHello:
	//   0 type | 1-2 ver | 3-4 len | 5 hs type | 6-8 hs len | 9-10 legacy_ver
	//   11-42 random | 43 sid len | 44-75 session_id echo | 76-77 cipher
	//   78 compression | 79-80 ext len | ...
	cases := []struct {
		name   string
		offset int
	}{
		{"ServerHello.random", 20},
		{"legacy_session_id_echo", 50},
		{"cipher_suite", 76},
		{"legacy_version", 10},
		{"compression_method", 78},
		{"ML-KEM half of key_share", 200},
		{"X25519 half of key_share", ServerHelloResumedLen - 16},
		{"record length header", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tamperedOpening(t, 0, tc.offset); err == nil {
				t.Errorf("the client completed a handshake whose ServerHello was altered in %s; "+
					"a real TLS client aborts, so surviving this is an active distinguisher", tc.name)
			}
		})
	}
}

// The control: the same harness with nothing altered must succeed, or every
// case above would "pass" for the wrong reason.
func TestUntamperedOpeningThroughTheProxySucceeds(t *testing.T) {
	if err := tamperedOpening(t, 0, -1); err != nil {
		t.Fatalf("an untampered opening failed through the proxy: %v", err)
	}
}

// tamperedOpening runs one client/server opening through the proxy and returns
// the client's error.
func tamperedOpening(t *testing.T, record, offset int) error {
	t.Helper()
	k := ticketKey(t)
	cover := mustCover(t, "www.microsoft.com")
	cred, err := k.Issue(1, cover.TicketLen)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		c, err := srv.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if sc, err := Server(c, ServerConfig{
			TicketKey: k, Cover: cover,
			MaxAge: time.Hour, Replay: NewReplayCache(16, time.Hour),
		}); err == nil {
			sc.Write([]byte("payload"))
		}
	}()

	proxy := tamperingProxy(t, srv.Addr().String(), record, offset)
	defer proxy.Close()
	raw, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(4 * time.Second))

	_, _, err = Client(raw, ClientConfig{Pool: pool(t), Cover: cover, Credential: cred})
	return err
}

// The ChangeCipherSpec is in the transcript too.
//
// On its own it is a far weaker distinguisher than the ServerHello was -- a
// fixed 6-byte legacy record with one meaningful byte, so there is almost
// nothing for a censor to vary. It is covered anyway because covering it costs
// one argument, and leaving a known hole open because it is small is how the
// ServerHello hole survived: each individual field looked unimportant.
func TestChangeCipherSpecTamperingBreaksTheHandshake(t *testing.T) {
	if err := tamperedOpening(t, 1, 5); err == nil {
		t.Error("the client completed a handshake whose ChangeCipherSpec was altered in flight")
	}
}

// An unbound derivation must not be possible at all, not merely discouraged.
//
// Fixed-arity Transcript stops a caller dropping one record; this stops a
// caller dropping the whole transcript, which is the same silent weakening by a
// shorter route. Both compile, both produce working keys, and neither fails a
// test that only checks bytes move -- which is why the check has to be in
// DeriveSession rather than in a comment.
func TestDeriveSessionRefusesAnUnboundTranscript(t *testing.T) {
	for _, tc := range []struct {
		name       string
		transcript []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DeriveSession(make([]byte, 32), make([]byte, 32),
				TLS_AES_128_GCM_SHA256, tc.transcript)
			if err == nil {
				t.Error("DeriveSession produced keys bound to nothing; ServerHello tampering would go undetected")
			}
		})
	}
	// And the bound form still works, or the check would be indiscriminate.
	if _, err := DeriveSession(make([]byte, 32), make([]byte, 32),
		TLS_AES_128_GCM_SHA256, testTranscript()); err != nil {
		t.Errorf("a bound derivation was refused: %v", err)
	}
}
