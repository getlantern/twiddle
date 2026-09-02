package twiddle

import (
	"encoding/binary"
	"testing"
)

// greaseSlots reads back every GREASE codepoint in a hello, by slot.
type greaseSlots struct {
	cipher, ext1, ext2, group, ksGroup, version, sigAlg uint16
}

func readGREASE(t *testing.T, h *ClientHello) greaseSlots {
	t.Helper()
	var g greaseSlots
	for _, c := range h.CipherSuites {
		if IsGREASE(c) {
			g.cipher = c
		}
	}
	for i := range h.Extensions {
		if IsGREASE(h.Extensions[i].Type) {
			if g.ext1 == 0 {
				g.ext1 = h.Extensions[i].Type
			} else {
				g.ext2 = h.Extensions[i].Type
			}
		}
	}
	firstGREASEInList := func(typ uint16, hdr int) uint16 {
		e := h.Find(typ)
		if e == nil || len(e.Data) < hdr {
			return 0
		}
		n := int(e.Data[0])
		if hdr == 2 {
			n = int(binary.BigEndian.Uint16(e.Data[0:2]))
		}
		end := hdr + n
		if end > len(e.Data) {
			end = len(e.Data)
		}
		for p := hdr; p+2 <= end; p += 2 {
			if v := binary.BigEndian.Uint16(e.Data[p : p+2]); IsGREASE(v) {
				return v
			}
		}
		return 0
	}
	g.group = firstGREASEInList(ExtSupportedGroups, 2)
	g.version = firstGREASEInList(ExtSupportedVersions, 1)
	g.sigAlg = firstGREASEInList(ExtSignatureAlgorithms, 2)

	if e := h.Find(ExtKeyShare); e != nil && len(e.Data) >= 2 {
		for p := 2; p+4 <= len(e.Data); {
			n := int(binary.BigEndian.Uint16(e.Data[p+2 : p+4]))
			if v := binary.BigEndian.Uint16(e.Data[p : p+2]); IsGREASE(v) {
				g.ksGroup = v
			}
			if p+4+n > len(e.Data) {
				break
			}
			p += 4 + n
		}
	}
	return g
}

// The two constraints measured across the embedded pool and Chrome 152, on 15
// of 15 hellos: the two extension draws differ, and the supported_groups draw
// is the same value as the key_share group. The second is a protocol
// requirement -- a key_share names a group the client offered -- so violating
// it produces a hello no browser would send.
func TestRerandGREASEHoldsTheMeasuredConstraints(t *testing.T) {
	for i := 0; i < 200; i++ {
		h, err := ParseClientHello(DefaultPool()[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Rerandomize(); err != nil {
			t.Fatal(err)
		}
		g := readGREASE(t, h)

		if g.ext1 == g.ext2 {
			t.Fatalf("iteration %d: both extension draws are %#04x", i, g.ext1)
		}
		if g.group != g.ksGroup {
			t.Fatalf("iteration %d: supported_groups %#04x != key_share group %#04x",
				i, g.group, g.ksGroup)
		}
		for name, v := range map[string]uint16{
			"cipher": g.cipher, "ext1": g.ext1, "ext2": g.ext2,
			"group": g.group, "version": g.version,
		} {
			if v == 0 || !IsGREASE(v) {
				t.Fatalf("iteration %d: %s = %#04x is not a GREASE codepoint", i, name, v)
			}
		}
	}
}

// Each slot must actually move, and cover the whole 16-value space. A slot
// pinned to one value is the bug this fix exists to close.
func TestRerandGREASECoversAllSixteenValues(t *testing.T) {
	seen := map[string]map[uint16]bool{
		"cipher": {}, "ext1": {}, "ext2": {}, "group": {}, "version": {},
	}
	for i := 0; i < 600; i++ {
		h, err := ParseClientHello(DefaultPool()[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Rerandomize(); err != nil {
			t.Fatal(err)
		}
		g := readGREASE(t, h)
		seen["cipher"][g.cipher] = true
		seen["ext1"][g.ext1] = true
		seen["ext2"][g.ext2] = true
		seen["group"][g.group] = true
		seen["version"][g.version] = true
	}
	for slot, vals := range seen {
		if len(vals) != greaseCount {
			t.Errorf("%s took %d distinct values in 600 draws, want all %d",
				slot, len(vals), greaseCount)
		}
	}
}

// Collisions ACROSS slots must be possible, because real hellos have them:
// pool[3] drew 0xfafa for both its cipher suite and its trailing extension.
// Forbidding them would itself be a deviation.
func TestRerandGREASEAllowsCrossSlotCollisions(t *testing.T) {
	for i := 0; i < 2000; i++ {
		h, err := ParseClientHello(DefaultPool()[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Rerandomize(); err != nil {
			t.Fatal(err)
		}
		g := readGREASE(t, h)
		if g.cipher == g.ext2 || g.cipher == g.group || g.version == g.ext1 {
			return // observed one, as expected
		}
	}
	t.Error("no cross-slot collision in 2000 draws; the draws are not independent")
}

// The GREASE rewrite must not disturb the structures it reaches into: it edits
// values inside supported_groups, supported_versions, signature_algorithms and
// key_share, so every length must survive, the record must still parse, and
// Shuffle's GREASE-at-both-ends invariant must still hold.
//
// ECH is the one exception, and deliberately so: Rerandomize redraws its GREASE
// bucket across the measured 186/218/250/282, which is the only length delta
// handshake_test.go permits between a harvested hello and an emitted one.
func TestRerandGREASEPreservesStructure(t *testing.T) {
	for _, rec := range DefaultPool() {
		before, err := ParseClientHello(rec)
		if err != nil {
			t.Fatal(err)
		}
		h, err := ParseClientHello(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Rerandomize(); err != nil {
			t.Fatal(err)
		}

		if len(h.Extensions) != len(before.Extensions) {
			t.Fatalf("extension count changed: %d != %d", len(h.Extensions), len(before.Extensions))
		}
		echDelta := 0
		for i := range h.Extensions {
			if before.Extensions[i].Type == ExtECH {
				echDelta = len(h.Extensions[i].Data) - len(before.Extensions[i].Data)
				continue
			}
			if len(h.Extensions[i].Data) != len(before.Extensions[i].Data) {
				t.Errorf("extension %d (%#04x) length changed: %d != %d",
					i, before.Extensions[i].Type, len(h.Extensions[i].Data), len(before.Extensions[i].Data))
			}
		}
		if len(h.CipherSuites) != len(before.CipherSuites) {
			t.Error("cipher suite count changed")
		}

		wire := h.Marshal()
		if len(wire) != len(rec)+echDelta {
			t.Errorf("record length changed by %d, but the ECH bucket only moved %d",
				len(wire)-len(rec), echDelta)
		}
		if _, err := ParseClientHello(wire); err != nil {
			t.Fatalf("rewritten hello does not parse: %v", err)
		}
		if err := h.Shuffle(); err != nil {
			t.Errorf("Shuffle rejected the rewritten hello: %v", err)
		}
	}
}

// The GREASE key_share entry carries exactly one zero byte in real Chrome --
// 15 of 15 measured. It was previously filled with random bytes, which is a
// deterministic tell on 255 of 256 connections.
func TestGREASEKeyShareValueIsZero(t *testing.T) {
	for i := 0; i < 50; i++ {
		h, err := ParseClientHello(DefaultPool()[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Rerandomize(); err != nil {
			t.Fatal(err)
		}
		e := h.Find(ExtKeyShare)
		if e == nil {
			t.Fatal("no key_share")
		}
		var checked int
		for p := 2; p+4 <= len(e.Data); {
			g := binary.BigEndian.Uint16(e.Data[p : p+2])
			n := int(binary.BigEndian.Uint16(e.Data[p+2 : p+4]))
			if p+4+n > len(e.Data) {
				break
			}
			if IsGREASE(g) {
				for _, b := range e.Data[p+4 : p+4+n] {
					if b != 0x00 {
						t.Fatalf("GREASE key_share %#04x carries %#02x, want 0x00", g, b)
					}
				}
				checked++
			}
			p += 4 + n
		}
		if checked == 0 {
			t.Fatal("no GREASE key_share entry found")
		}
	}
}
