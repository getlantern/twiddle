package twiddle

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/binary"
	"testing"
)

func oneHello(t *testing.T) []byte {
	t.Helper()
	for _, rec := range realHellos(t) {
		if h, err := ParseClientHello(rec); err == nil && len(h.Extensions) >= 8 {
			return rec
		}
	}
	t.Skip("no usable hello")
	return nil
}

// TestShuffleProducesVariedOrdersWithFixedEnds mirrors what Chrome does: the
// GREASE ends and pre_shared_key stay put, everything between permutes, and the
// order differs between connections.
func TestShuffleProducesVariedOrdersWithFixedEnds(t *testing.T) {
	for name, rec := range realHellos(t) {
		base, err := ParseClientHello(rec)
		if err != nil {
			t.Fatal(err)
		}
		wantSet := map[uint16]int{}
		for _, e := range base.Extensions {
			wantSet[e.Type]++
		}
		firstWas, lastWas := base.Extensions[0].Type, base.Extensions[len(base.Extensions)-1].Type

		orders := map[string]bool{}
		for i := 0; i < 24; i++ {
			h, _ := ParseClientHello(rec)
			if err := h.Shuffle(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if got := h.Extensions[0].Type; got != firstWas {
				t.Fatalf("%s: leading extension moved: %#04x -> %#04x", name, firstWas, got)
			}
			if got := h.Extensions[len(h.Extensions)-1].Type; got != lastWas {
				t.Fatalf("%s: trailing extension moved: %#04x -> %#04x", name, lastWas, got)
			}
			gotSet := map[uint16]int{}
			var key []byte
			for _, e := range h.Extensions {
				gotSet[e.Type]++
				key = appendU16(key, e.Type)
			}
			if len(gotSet) != len(wantSet) {
				t.Fatalf("%s: extension multiset changed", name)
			}
			for k, v := range wantSet {
				if gotSet[k] != v {
					t.Fatalf("%s: extension %#04x count %d, want %d", name, k, gotSet[k], v)
				}
			}
			if _, err := ParseClientHello(h.Marshal()); err != nil {
				t.Fatalf("%s: shuffled hello does not parse: %v", name, err)
			}
			orders[string(key)] = true
		}
		if len(orders) < 8 {
			t.Errorf("%s: only %d distinct orders in 24 shuffles", name, len(orders))
		}
		break
	}
}

// TestShuffleAcceptsEveryCapturedHello guards against a hello shape the
// GREASE/PSK assumptions do not cover.
func TestShuffleAcceptsEveryCapturedHello(t *testing.T) {
	n := 0
	for name, rec := range realHellos(t) {
		h, err := ParseClientHello(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Shuffle(); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		n++
	}
	t.Logf("shuffled %d captured hellos without a structural surprise", n)
}

func TestRerandomizeChangesEveryVariableField(t *testing.T) {
	rec := oneHello(t)
	a, _ := ParseClientHello(rec)
	b, _ := ParseClientHello(rec)
	if err := a.Rerandomize(); err != nil {
		t.Fatal(err)
	}
	if err := b.Rerandomize(); err != nil {
		t.Fatal(err)
	}
	if a.Random == b.Random {
		t.Error("ClientHello.random repeated across connections")
	}
	if bytes.Equal(a.SessionID, b.SessionID) {
		t.Error("session_id repeated across connections")
	}
	if ka, kb := a.Find(ExtKeyShare), b.Find(ExtKeyShare); ka != nil && kb != nil {
		if bytes.Equal(ka.Data, kb.Data) {
			t.Error("key_share repeated across connections")
		}
	}
	if _, err := ParseClientHello(a.Marshal()); err != nil {
		t.Fatalf("re-randomised hello does not parse: %v", err)
	}
}

// TestECHGreaseHitsMeasuredBuckets checks that re-randomised ECH lands in the
// 32-byte buckets observed from Chrome, and actually varies.
func TestECHGreaseHitsMeasuredBuckets(t *testing.T) {
	rec := oneHello(t)
	if h, _ := ParseClientHello(rec); h.Find(ExtECH) == nil {
		t.Skip("hello carries no ECH extension")
	}
	seen := map[int]int{}
	for i := 0; i < 60; i++ {
		h, _ := ParseClientHello(rec)
		if err := h.Rerandomize(); err != nil {
			t.Fatal(err)
		}
		seen[len(h.Find(ExtECH).Data)]++
	}
	if len(seen) < 3 {
		t.Errorf("ECH length took only %d distinct values in 60 draws: %v", len(seen), seen)
	}
	for l := range seen {
		if (l-186)%32 != 0 || l < 186 || l > 282 {
			t.Errorf("ECH extension length %d is outside the measured 186..282 /32 buckets", l)
		}
	}
	t.Logf("ECH lengths: %v", seen)
}

// TestKeySharesAreValidNotRandom pins the bug that random-filling key_share
// introduced. Random bytes are not a valid ML-KEM-768 encapsulation key, and a
// real server answers such a hello with illegal_parameter or decode_error --
// which hands a censor a replay distinguisher: capture our hello, send it to the
// SNI we claim, and see an alert where genuine Chrome draws a ServerHello.
func TestKeySharesAreValidNotRandom(t *testing.T) {
	checked := 0
	for name, rec := range realHellos(t) {
		h, err := ParseClientHello(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Rerandomize(); err != nil {
			t.Fatal(err)
		}
		e := h.Find(ExtKeyShare)
		if e == nil {
			continue
		}
		d := e.Data
		p := 2
		for p+4 <= len(d) {
			group := binary.BigEndian.Uint16(d[p : p+2])
			n := int(binary.BigEndian.Uint16(d[p+2 : p+4]))
			if p+4+n > len(d) {
				t.Fatalf("%s: malformed key_share", name)
			}
			val := d[p+4 : p+4+n]
			switch {
			case group == GroupX25519 && n == 32:
				if _, err := ecdh.X25519().NewPublicKey(val); err != nil {
					t.Errorf("%s: X25519 share is not a valid public key: %v", name, err)
				}
				checked++
			case group == GroupX25519MLKEM768 && n == mlkem768EncapKeyLen+32:
				if _, err := mlkem.NewEncapsulationKey768(val[:mlkem768EncapKeyLen]); err != nil {
					t.Errorf("%s: ML-KEM share is not a valid encapsulation key: %v", name, err)
				}
				if _, err := ecdh.X25519().NewPublicKey(val[mlkem768EncapKeyLen:]); err != nil {
					t.Errorf("%s: hybrid X25519 half is not a valid public key: %v", name, err)
				}
				checked += 2
			}
			p += 4 + n
		}
	}
	if checked == 0 {
		t.Fatal("no key shares checked")
	}
	t.Logf("validated %d key shares across the corpus", checked)
}

// TestKeySharesAreFreshEachConnection: valid must not mean constant.
func TestKeySharesAreFreshEachConnection(t *testing.T) {
	rec := oneHello(t)
	seen := map[string]bool{}
	for i := 0; i < 12; i++ {
		h, _ := ParseClientHello(rec)
		if err := h.Rerandomize(); err != nil {
			t.Fatal(err)
		}
		d := h.Find(ExtKeyShare).Data
		if seen[string(d)] {
			t.Fatal("key_share repeated across connections")
		}
		seen[string(d)] = true
	}
}
