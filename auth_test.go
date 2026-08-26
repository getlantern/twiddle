package twiddle

import (
	"bytes"
	"testing"
	"time"
)

func ticketKey(t *testing.T) *TicketKey {
	t.Helper()
	k, err := NewTicketKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestTicketRoundTrip(t *testing.T) {
	k := ticketKey(t)
	cred, err := k.Issue(0xdeadbeef, DefaultTicketLen)
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.Ticket) != DefaultTicketLen {
		t.Fatalf("ticket is %d bytes, want %d", len(cred.Ticket), DefaultTicketLen)
	}
	id, psk, issued, err := k.Open(cred.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	if id != 0xdeadbeef {
		t.Errorf("client id %#x", id)
	}
	if psk != cred.PSK {
		t.Error("psk mismatch")
	}
	if time.Since(issued) > time.Minute {
		t.Errorf("issued time is %v", issued)
	}
}

// TestTicketsAreConstantLengthAndUnique: a real server's ticket format does not
// vary connection to connection, so ours must not either -- but the bytes must.
func TestTicketsAreConstantLengthAndUnique(t *testing.T) {
	k := ticketKey(t)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := k.Issue(7, DefaultTicketLen)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Ticket) != DefaultTicketLen {
			t.Fatalf("ticket length varied: %d", len(c.Ticket))
		}
		if seen[string(c.Ticket)] {
			t.Fatal("ticket repeated")
		}
		seen[string(c.Ticket)] = true
	}
}

// TestTicketBytesLookUniform is the property the ECDH construction could not
// provide: a ticket is AEAD ciphertext, so it carries no algebraic structure a
// censor can test for. A raw X25519 key would fail a curve-membership check
// ~100% of the time where random bytes pass ~50%.
func TestTicketBytesLookUniform(t *testing.T) {
	k := ticketKey(t)
	var ones, total int
	byteCounts := make([]int, 256)
	for i := 0; i < 400; i++ {
		c, err := k.Issue(uint64(i), DefaultTicketLen)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range c.Ticket {
			byteCounts[b]++
			total += 8
			for j := 0; j < 8; j++ {
				ones += int(b>>j) & 1
			}
		}
	}
	frac := float64(ones) / float64(total)
	if frac < 0.49 || frac > 0.51 {
		t.Errorf("bit balance %.4f is not ~0.5", frac)
	}
	empty := 0
	for _, c := range byteCounts {
		if c == 0 {
			empty++
		}
	}
	if empty > 0 {
		t.Errorf("%d byte values never appeared across %d tickets", empty, 400)
	}
	t.Logf("bit balance %.4f over %d bits, all 256 byte values present", frac, total)
}

func TestTicketAuthEndToEnd(t *testing.T) {
	k := ticketKey(t)
	cred, _ := k.Issue(42, DefaultTicketLen)
	n := 0
	for name, rec := range realHellos(t) {
		wire, eph, err := Twiddle(rec, Options{
			CoverSNI:   "www.microsoft.com",
			Credential: cred,
			BinderLen:  32,
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		back, err := ParseClientHello(wire)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		res, err := VerifyTicketAuth(back, k, time.Hour)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.ClientID != 42 {
			t.Errorf("client id %d", res.ClientID)
		}
		if res.PSK != cred.PSK {
			t.Error("psk mismatch")
		}
		// the ephemeral on the wire must be the one we generated -- that is
		// what gives the session forward secrecy independent of the psk
		if !bytes.Equal(res.ClientEphemeral.Bytes(), eph.PublicKey().Bytes()) {
			t.Error("key_share does not carry our ephemeral")
		}
		if back.Extensions[len(back.Extensions)-1].Type != ExtPreSharedKey {
			t.Error("pre_shared_key is not last")
		}
		n++
	}
	t.Logf("ticket auth verified over all %d captured hellos", n)
}

func TestVerifyRejectsWrongTicketKey(t *testing.T) {
	real, imposter := ticketKey(t), ticketKey(t)
	cred, _ := real.Issue(1, DefaultTicketLen)
	for _, rec := range realHellos(t) {
		wire, _, err := Twiddle(rec, Options{Credential: cred, BinderLen: 32})
		if err != nil {
			t.Fatal(err)
		}
		back, _ := ParseClientHello(wire)
		if _, err := VerifyTicketAuth(back, imposter, time.Hour); err == nil {
			t.Fatal("a different ticket key verified")
		}
		if _, err := VerifyTicketAuth(back, real, time.Hour); err != nil {
			t.Fatalf("the real key failed: %v", err)
		}
		break
	}
}

func TestVerifyRejectsExpiredTicket(t *testing.T) {
	k := ticketKey(t)
	old, err := k.issueAt(1, DefaultTicketLen, time.Now().Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range realHellos(t) {
		wire, _, _ := Twiddle(rec, Options{Credential: old, BinderLen: 32})
		back, _ := ParseClientHello(wire)
		if _, err := VerifyTicketAuth(back, k, 24*time.Hour); err == nil {
			t.Fatal("an expired ticket verified")
		}
		if _, err := VerifyTicketAuth(back, k, 0); err != nil {
			t.Fatalf("age check disabled should still verify: %v", err)
		}
		break
	}
}

func TestBinderIsBoundToTheHello(t *testing.T) {
	k := ticketKey(t)
	cred, _ := k.Issue(1, DefaultTicketLen)
	var a, b []byte
	for _, rec := range realHellos(t) {
		if a == nil {
			a = rec
			continue
		}
		b = rec
		break
	}
	wire, _, _ := Twiddle(a, Options{Credential: cred, BinderLen: 32})
	ha, _ := ParseClientHello(wire)
	stolen := ha.Find(ExtPreSharedKey).Data

	hb, _ := ParseClientHello(b)
	hb.Extensions = append(hb.Extensions, Extension{ExtPreSharedKey, stolen})
	if _, err := VerifyTicketAuth(hb, k, time.Hour); err == nil {
		t.Fatal("a binder lifted onto a different hello verified")
	}
}

func TestKeyShareCarriesFreshEphemeralEachTime(t *testing.T) {
	k := ticketKey(t)
	cred, _ := k.Issue(1, DefaultTicketLen)
	seen := map[string]bool{}
	for _, rec := range realHellos(t) {
		for i := 0; i < 25; i++ {
			wire, _, err := Twiddle(rec, Options{Credential: cred, BinderLen: 32})
			if err != nil {
				t.Fatal(err)
			}
			h, _ := ParseClientHello(wire)
			ks, err := h.KeyShare()
			if err != nil {
				t.Fatal(err)
			}
			s := string(ks.Bytes())
			if seen[s] {
				t.Fatal("key_share ephemeral repeated across connections")
			}
			seen[s] = true
		}
		break
	}
}

func TestBinderLength48(t *testing.T) {
	k := ticketKey(t)
	cred, _ := k.Issue(1, DefaultTicketLen)
	for _, rec := range realHellos(t) {
		wire, _, err := Twiddle(rec, Options{Credential: cred, BinderLen: 48})
		if err != nil {
			t.Fatal(err)
		}
		back, _ := ParseClientHello(wire)
		if _, err := VerifyTicketAuth(back, k, time.Hour); err != nil {
			t.Fatalf("SHA-384 binder: %v", err)
		}
		break
	}
}
