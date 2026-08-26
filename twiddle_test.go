package twiddle

import (
	"bytes"
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
