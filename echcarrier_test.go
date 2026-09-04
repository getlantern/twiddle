package twiddle

import (
	"bytes"
	"testing"
	"time"
)

// helloWithECHPayload returns a parsed pool hello whose ECH payload is exactly
// want bytes, so a test can pick the bucket it needs rather than hope.
func helloWithECHPayload(t *testing.T, want int) *ClientHello {
	t.Helper()
	for _, rec := range DefaultPool() {
		h, err := ParseClientHello(rec)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := h.ECHPayloadLen(); err == nil && n == want {
			return h
		}
	}
	t.Fatalf("no pool hello carries a %d-byte ECH payload", want)
	return nil
}

// fullCred mints a credential and its full-handshake companion ticket.
func fullCred(t *testing.T, k *TicketKey, clientID uint64) (*Credential, []byte) {
	t.Helper()
	cred, err := k.Issue(clientID, DefaultTicketLen)
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.FullTicket) != FullTicketLen {
		t.Fatalf("Issue produced a %d-byte full ticket, want %d", len(cred.FullTicket), FullTicketLen)
	}
	return cred, cred.FullTicket
}

func TestECHCarrierRoundTrip(t *testing.T) {
	k := ticketKey(t)
	cred, full := fullCred(t, k, 42)
	h := helloWithECHPayload(t, 240)
	if _, err := h.SetKeyShare(); err != nil {
		t.Fatal(err)
	}
	if err := h.SetECHTicketAuth(full, cred.PSK); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyECHTicketAuth(h, k, time.Hour)
	if err != nil {
		t.Fatalf("a well-formed full-handshake opening was rejected: %v", err)
	}
	if res.ClientID != 42 {
		t.Errorf("clientID %d, want 42", res.ClientID)
	}
	if res.PSK != cred.PSK {
		t.Error("recovered psk differs from the credential's; DeriveSession would disagree")
	}
	if res.ClientEphemeral == nil {
		t.Error("no client ephemeral recovered")
	}
}

// IssueFull must mint a companion, not a second identity: the replay gate keys
// on clientID and the tunnel keys on psk, so a full ticket carrying either a
// different id or a different psk would silently split one client in two.
func TestIssueFullSharesTheCredentialIdentity(t *testing.T) {
	k := ticketKey(t)
	cred, full := fullCred(t, k, 7)
	if len(full) != FullTicketLen {
		t.Fatalf("full ticket is %d bytes, want %d", len(full), FullTicketLen)
	}
	if bytes.Equal(full, cred.Ticket) {
		t.Fatal("the two tickets are byte-identical; this test proves nothing")
	}
	id, psk, _, err := k.Open(full)
	if err != nil {
		t.Fatal(err)
	}
	if id != 7 {
		t.Errorf("clientID %d, want 7", id)
	}
	if psk != cred.PSK {
		t.Error("the full ticket carries a different psk from the credential")
	}
}

// The point of this construction over the binder: the binder mirrors RFC 8446's
// Truncate() and covers only a prefix, whereas this MAC covers the whole hello.
// Each mutation below is a field an active adversary would rewrite, and each
// must break verification. Without the MAC actually spanning the marshalled
// hello, several of these would pass.
func TestECHCarrierMACCoversTheWholeHello(t *testing.T) {
	k := ticketKey(t)

	mutations := []struct {
		name string
		bend func(t *testing.T, h *ClientHello)
	}{
		{"SNI", func(t *testing.T, h *ClientHello) {
			if err := h.SetSNI("www.example.org"); err != nil {
				t.Fatal(err)
			}
		}},
		{"key_share", func(t *testing.T, h *ClientHello) {
			e := h.Find(ExtKeyShare)
			if e == nil {
				t.Fatal("no key_share to bend")
			}
			e.Data[len(e.Data)-1] ^= 0x01
		}},
		{"ECH padding after the ticket", func(t *testing.T, h *ClientHello) {
			pay, err := echPayload(h.Find(ExtECH))
			if err != nil {
				t.Fatal(err)
			}
			if len(pay) <= FullTicketLen {
				t.Fatalf("payload %d has no padding to bend", len(pay))
			}
			pay[len(pay)-1] ^= 0x01
		}},
		{"ECH enc", func(t *testing.T, h *ClientHello) {
			h.Find(ExtECH).Data[10] ^= 0x01
		}},
		{"cipher suites", func(t *testing.T, h *ClientHello) {
			h.CipherSuites[len(h.CipherSuites)-1] ^= 0x0001
		}},
		{"session id", func(t *testing.T, h *ClientHello) {
			if len(h.SessionID) == 0 {
				t.Fatal("no session id to bend")
			}
			h.SessionID[0] ^= 0x01
		}},
		{"random itself", func(t *testing.T, h *ClientHello) {
			h.Random[0] ^= 0x01
		}},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			cred, full := fullCred(t, k, 3)
			h := helloWithECHPayload(t, 240)
			if _, err := h.SetKeyShare(); err != nil {
				t.Fatal(err)
			}
			if err := h.SetECHTicketAuth(full, cred.PSK); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyECHTicketAuth(h, k, time.Hour); err != nil {
				t.Fatalf("baseline opening did not verify: %v", err)
			}

			m.bend(t, h)
			if _, err := VerifyECHTicketAuth(h, k, time.Hour); err == nil {
				t.Errorf("verification still succeeded after bending %s; the MAC does not cover it", m.name)
			}
		})
	}
}

func TestECHCarrierRejectsAForeignPSK(t *testing.T) {
	k := ticketKey(t)
	cred, full := fullCred(t, k, 5)
	h := helloWithECHPayload(t, 240)
	if _, err := h.SetKeyShare(); err != nil {
		t.Fatal(err)
	}
	// A censor who captured a ticket but not the psk it pairs with.
	var wrong [32]byte
	copy(wrong[:], cred.PSK[:])
	wrong[0] ^= 0x01
	if err := h.SetECHTicketAuth(full, wrong); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyECHTicketAuth(h, k, time.Hour); err == nil {
		t.Error("an opening MACed under the wrong psk was accepted")
	}
}

// The two paths are mutually exclusive by construction. A hello carrying both
// carriers is not a client we issued, and accepting one would give an adversary
// a choice of which authenticator to satisfy.
func TestECHCarrierAndResumptionAreExclusive(t *testing.T) {
	k := ticketKey(t)
	cred, full := fullCred(t, k, 9)

	h := helloWithECHPayload(t, 240)
	if _, err := h.SetKeyShare(); err != nil {
		t.Fatal(err)
	}
	if err := h.SetTicketAuth(cred, 32); err != nil {
		t.Fatal(err)
	}
	if err := h.SetECHTicketAuth(full, cred.PSK); err == nil {
		t.Error("SetECHTicketAuth accepted a hello that still carries pre_shared_key")
	}
	if _, err := VerifyECHTicketAuth(h, k, time.Hour); err == nil {
		t.Error("VerifyECHTicketAuth accepted a resumption hello")
	}
}

func TestECHCarrierRejectsAnExpiredTicket(t *testing.T) {
	k := ticketKey(t)
	cred, err := k.Issue(11, DefaultTicketLen)
	if err != nil {
		t.Fatal(err)
	}
	old, err := k.seal(11, cred.PSK, FullTicketLen, time.Now().Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	h := helloWithECHPayload(t, 240)
	if _, err := h.SetKeyShare(); err != nil {
		t.Fatal(err)
	}
	if err := h.SetECHTicketAuth(old, cred.PSK); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyECHTicketAuth(h, k, 24*time.Hour); err == nil {
		t.Error("a ticket older than maxAge was accepted")
	}
	if _, err := VerifyECHTicketAuth(h, k, 0); err != nil {
		t.Errorf("maxAge 0 should skip the age check: %v", err)
	}
}

// A pool whose hellos carry no ECH, or too small an ECH, cannot offer this path
// at all. That has to fail loudly at emission rather than produce an opening
// that no server can authenticate.
func TestECHCarrierRefusesAPayloadTooSmallToCarryATicket(t *testing.T) {
	k := ticketKey(t)
	cred, full := fullCred(t, k, 13)

	t.Run("no ECH extension", func(t *testing.T) {
		h := helloWithECHPayload(t, 240)
		for i := range h.Extensions {
			if h.Extensions[i].Type == ExtECH {
				h.Extensions = append(h.Extensions[:i], h.Extensions[i+1:]...)
				break
			}
		}
		if err := h.SetECHTicketAuth(full, cred.PSK); err == nil {
			t.Error("a hello with no ECH extension was accepted as a carrier")
		}
	})

	t.Run("payload below FullTicketLen", func(t *testing.T) {
		h := helloWithECHPayload(t, 240)
		e := h.Find(ExtECH)
		// Shrink the payload to one byte under the ticket size.
		short := FullTicketLen - 1
		e.Data = append(e.Data[:len(e.Data)-240-2], byte(short>>8), byte(short))
		e.Data = append(e.Data, make([]byte, short)...)
		if n, err := h.ECHPayloadLen(); err != nil || n != short {
			t.Fatalf("payload is %d (%v), want %d", n, err, short)
		}
		err := h.SetECHTicketAuth(full, cred.PSK)
		if err == nil {
			t.Fatal("a payload too small for the ticket was accepted")
		}
		if !contains(err.Error(), "too small") {
			t.Errorf("unhelpful error: %v", err)
		}
	})
}

// The padding after the ticket is refilled on every call rather than inherited.
// rerandECHGrease normally supplies it, but a caller that reached this function
// without Rerandomize would otherwise emit one harvested browser's payload tail
// verbatim on every connection -- a per-device constant sitting in a field that
// is supposed to be fresh random bytes each time.
func TestECHCarrierRefreshesThePaddingItself(t *testing.T) {
	k := ticketKey(t)
	cred, full := fullCred(t, k, 19)

	tail := func() []byte {
		h := helloWithECHPayload(t, 240)
		if _, err := h.SetKeyShare(); err != nil {
			t.Fatal(err)
		}
		// Deliberately NO Rerandomize: the padding must not come from the pool.
		if err := h.SetECHTicketAuth(full, cred.PSK); err != nil {
			t.Fatal(err)
		}
		pay, err := echPayload(h.Find(ExtECH))
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), pay[FullTicketLen:]...)
	}

	a, b := tail(), tail()
	if bytes.Equal(a, b) {
		t.Error("two emissions from the same pool hello produced identical ECH padding")
	}
}

// What a censor actually sees. The emitted opening must carry no
// pre_shared_key -- that is the whole point -- and its ECH payload length must
// still be one Chrome draws, because a length outside the buckets is a
// distinguisher that costs one comparison.
func TestECHCarrierEmitsAFullHandshakeShape(t *testing.T) {
	k := ticketKey(t)

	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		cred, full := fullCred(t, k, 17)
		h, err := ParseClientHello(DefaultPool()[i%len(DefaultPool())])
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Rerandomize(); err != nil {
			t.Fatal(err)
		}
		if _, err := h.SetKeyShare(); err != nil {
			t.Fatal(err)
		}
		if err := h.SetECHTicketAuth(full, cred.PSK); err != nil {
			t.Fatal(err)
		}

		if h.Find(ExtPreSharedKey) != nil {
			t.Fatal("the emitted opening carries pre_shared_key; it still reads as a resumption")
		}
		n, err := h.ECHPayloadLen()
		if err != nil {
			t.Fatal(err)
		}
		ok := false
		for _, want := range echGREASELengths {
			if n == want {
				ok = true
			}
		}
		if !ok {
			t.Fatalf("ECH payload is %d bytes, which is not one of Chrome's buckets %v", n, echGREASELengths)
		}
		seen[n] = true

		// It must still authenticate after the round trip through Marshal.
		reparsed, err := ParseClientHello(h.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyECHTicketAuth(reparsed, k, time.Hour); err != nil {
			t.Fatalf("the opening did not survive marshal/parse: %v", err)
		}
	}
	if len(seen) < 2 {
		t.Errorf("only saw payload lengths %v over 200 emissions; the length is not varying", seen)
	}
}

// shrinkECH rewrites a hello's ECH payload to n bytes, standing in for a pool
// hello from a browser whose ECH is too small to carry a ticket.
func shrinkECH(t *testing.T, rec []byte, n int) []byte {
	t.Helper()
	h, err := ParseClientHello(rec)
	if err != nil {
		t.Fatal(err)
	}
	e := h.Find(ExtECH)
	if e == nil {
		t.Fatal("hello has no ECH to shrink")
	}
	pay, err := echPayload(e)
	if err != nil {
		t.Fatal(err)
	}
	head := len(e.Data) - len(pay) - 2
	d := append([]byte(nil), e.Data[:head]...)
	d = append(d, byte(n>>8), byte(n))
	d = append(d, make([]byte, n)...)
	e.Data = d
	if got, err := h.ECHPayloadLen(); err != nil || got != n {
		t.Fatalf("shrink produced %d (%v), want %d", got, err, n)
	}
	return h.Marshal()
}

// stripECH removes the ECH extension entirely, standing in for the non-ECH
// pool docs/ech.md keeps as an escape hatch.
func stripECH(t *testing.T, rec []byte) []byte {
	t.Helper()
	h, err := ParseClientHello(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !h.dropExtension(ExtECH) {
		t.Fatal("hello had no ECH to strip")
	}
	return h.Marshal()
}

// A pool is not uniform: a device tap copies whatever the browser emitted, so
// hellos that can carry a ticket sit alongside hellos that cannot. Drawing
// uniformly from the whole pool would fail on SOME connections and succeed on
// others -- an intermittent failure far worse than not offering the path.
func TestFullHandshakeCarriersFiltersThePool(t *testing.T) {
	base := DefaultPool()[0] // 240-byte payload
	good := helloWithECHPayload(t, 144)

	mixed := [][]byte{
		stripECH(t, base),
		shrinkECH(t, base, FullTicketLen-1),
		base,
		shrinkECH(t, base, 16),
		good.Marshal(),
		[]byte("not a hello at all"),
	}
	got := FullHandshakeCarriers(mixed)
	if len(got) != 2 {
		t.Fatalf("kept %d of 6 hellos, want the 2 with a large enough ECH payload", len(got))
	}
	for _, rec := range got {
		h, err := ParseClientHello(rec)
		if err != nil {
			t.Fatal(err)
		}
		n, err := h.ECHPayloadLen()
		if err != nil || n < FullTicketLen {
			t.Errorf("kept a hello with payload %d (%v)", n, err)
		}
	}
	if len(FullHandshakeCarriers([][]byte{stripECH(t, base)})) != 0 {
		t.Error("a pool with no usable ECH was reported as able to carry the full handshake")
	}
}
