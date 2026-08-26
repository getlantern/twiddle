package twiddle

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func serverKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestPSKAuthRoundTrip(t *testing.T) {
	srv := serverKey(t)
	for _, binderLen := range []int{32, 48} {
		for name, rec := range realHellos(t) {
			h, err := ParseClientHello(rec)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.SetPSKAuth(srv.PublicKey(), 176, binderLen); err != nil {
				t.Fatalf("%s: SetPSKAuth: %v", name, err)
			}
			wire := h.Marshal()
			back, err := ParseClientHello(wire)
			if err != nil {
				t.Fatalf("%s: authenticated hello does not parse: %v", name, err)
			}
			shared, err := VerifyPSKAuth(back, srv)
			if err != nil {
				t.Fatalf("%s (binder %d): verify: %v", name, binderLen, err)
			}
			if len(shared) != 32 {
				t.Errorf("shared secret is %d bytes", len(shared))
			}
			break
		}
	}
}

// TestPSKAuthRejectsWrongServer is the property that matters: only the holder of
// the static private key can verify, so extracting one client's state does not
// let an observer confirm anyone's connections.
func TestPSKAuthRejectsWrongServer(t *testing.T) {
	real, imposter := serverKey(t), serverKey(t)
	for _, rec := range realHellos(t) {
		h, _ := ParseClientHello(rec)
		if _, err := h.SetPSKAuth(real.PublicKey(), 176, 32); err != nil {
			t.Fatal(err)
		}
		back, _ := ParseClientHello(h.Marshal())
		if _, err := VerifyPSKAuth(back, imposter); err == nil {
			t.Fatal("a different server key verified the binder")
		}
		break
	}
}

// TestPSKAuthIsBoundToTheHello: the binder covers the truncated transcript, so a
// tag cannot be lifted onto a different hello.
func TestPSKAuthIsBoundToTheHello(t *testing.T) {
	srv := serverKey(t)
	var a, b []byte
	for _, rec := range realHellos(t) {
		if a == nil {
			a = rec
			continue
		}
		b = rec
		break
	}
	ha, _ := ParseClientHello(a)
	if _, err := ha.SetPSKAuth(srv.PublicKey(), 176, 32); err != nil {
		t.Fatal(err)
	}
	stolen := ha.Find(ExtPreSharedKey).Data

	hb, _ := ParseClientHello(b)
	if err := hb.SetSNI("cover.example"); err != nil {
		t.Fatal(err)
	}
	hb.Extensions = append(hb.Extensions, Extension{ExtPreSharedKey, stolen})
	if _, err := VerifyPSKAuth(hb, srv); err == nil {
		t.Fatal("a binder lifted onto a different hello verified")
	}
}

func TestPSKAuthIsFreshEveryConnection(t *testing.T) {
	srv := serverKey(t)
	seen := map[string]bool{}
	for _, rec := range realHellos(t) {
		for i := 0; i < 20; i++ {
			h, _ := ParseClientHello(rec)
			if _, err := h.SetPSKAuth(srv.PublicKey(), 176, 32); err != nil {
				t.Fatal(err)
			}
			d := h.Find(ExtPreSharedKey).Data
			if seen[string(d)] {
				t.Fatal("pre_shared_key repeated across connections")
			}
			seen[string(d)] = true
		}
		break
	}
	if len(seen) != 20 {
		t.Fatalf("expected 20 distinct authenticators, got %d", len(seen))
	}
}

// TestEphemeralTopBitVaries: an X25519 public key's high bit is always zero,
// which is a one-bit bias an observer could accumulate. RFC 7748 requires
// receivers to mask it, so we randomise it.
func TestEphemeralTopBitVaries(t *testing.T) {
	srv := serverKey(t)
	var high, low int
	for _, rec := range realHellos(t) {
		for i := 0; i < 100; i++ {
			h, _ := ParseClientHello(rec)
			if _, err := h.SetPSKAuth(srv.PublicKey(), 176, 32); err != nil {
				t.Fatal(err)
			}
			ticket, _, _, err := parsePSK(h.Find(ExtPreSharedKey).Data)
			if err != nil {
				t.Fatal(err)
			}
			if ticket[ephemeralLen-1]&0x80 != 0 {
				high++
			} else {
				low++
			}
		}
		break
	}
	if high < 25 || low < 25 {
		t.Errorf("ephemeral top bit is biased: %d high, %d low in 100", high, low)
	}
	t.Logf("ephemeral top bit: %d high / %d low", high, low)
}

func TestFullPipelineHarvestToWire(t *testing.T) {
	srv := serverKey(t)
	n := 0
	for name, rec := range realHellos(t) {
		wire, eph, err := Twiddle(rec, Options{
			CoverSNI:     "www.microsoft.com",
			ServerStatic: srv.PublicKey(),
			TicketLen:    176,
			BinderLen:    32,
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		back, err := ParseClientHello(wire)
		if err != nil {
			t.Fatalf("%s: emitted hello does not parse: %v", name, err)
		}
		if back.SNI() != "www.microsoft.com" {
			t.Errorf("%s: SNI is %q", name, back.SNI())
		}
		if !IsGREASE(back.Extensions[0].Type) {
			t.Errorf("%s: leading GREASE lost", name)
		}
		if back.Extensions[len(back.Extensions)-1].Type != ExtPreSharedKey {
			t.Errorf("%s: pre_shared_key is not last", name)
		}
		if !IsGREASE(back.Extensions[len(back.Extensions)-2].Type) {
			t.Errorf("%s: pre_shared_key not preceded by GREASE, unlike Chrome", name)
		}
		shared, err := VerifyPSKAuth(back, srv)
		if err != nil {
			t.Fatalf("%s: auth did not survive the pipeline: %v", name, err)
		}
		mine, err := eph.ECDH(srv.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(shared, mine) {
			t.Errorf("%s: client and server derived different secrets", name)
		}
		n++
	}
	t.Logf("harvest -> twiddle -> verify, over all %d captured hellos", n)
}

// TestShuffleAfterAuthIsCaught documents the footgun Twiddle exists to prevent.
func TestShuffleAfterAuthIsCaught(t *testing.T) {
	srv := serverKey(t)
	for _, rec := range realHellos(t) {
		h, _ := ParseClientHello(rec)
		if _, err := h.SetPSKAuth(srv.PublicKey(), 176, 32); err != nil {
			t.Fatal(err)
		}
		if err := h.Shuffle(); err != nil {
			t.Fatal(err)
		}
		back, _ := ParseClientHello(h.Marshal())
		if _, err := VerifyPSKAuth(back, srv); err == nil {
			t.Fatal("shuffling after authenticating should invalidate the binder")
		}
		break
	}
}
