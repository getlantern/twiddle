package twiddle

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realHellos loads every ClientHello captured from a real Chrome in harvest/testdata.
func realHellos(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	paths, _ := filepath.Glob("harvest/testdata/*.hex")
	if len(paths) == 0 {
		t.Skip("no captured hellos in harvest/testdata")
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				continue
			}
			rec, err := hex.DecodeString(parts[1])
			if err != nil {
				continue
			}
			out[filepath.Base(p)+":"+parts[0]+":"+string(rune('a'+i%26))] = rec
		}
	}
	return out
}

// TestRoundTripIsLossless is the load-bearing test. Extensions are held as raw
// bytes precisely so that parsing and re-marshalling reproduces the input
// exactly, including extensions no Go TLS library models. If this ever fails,
// the transport is emitting something a real browser would not.
func TestRoundTripIsLossless(t *testing.T) {
	hellos := realHellos(t)
	if len(hellos) < 20 {
		t.Fatalf("expected a real corpus, got %d hellos", len(hellos))
	}
	for name, rec := range hellos {
		h, err := ParseClientHello(rec)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		got := h.Marshal()
		if !bytes.Equal(got, rec) {
			t.Errorf("%s: round-trip differs (in %d bytes, out %d)", name, len(rec), len(got))
		}
	}
	t.Logf("round-tripped %d captured Chrome hellos byte-for-byte", len(hellos))
}

func TestParseFindsExpectedStructure(t *testing.T) {
	for name, rec := range realHellos(t) {
		h, err := ParseClientHello(rec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(h.SessionID) != 32 {
			t.Errorf("%s: session_id is %d bytes, expected 32 from Chrome", name, len(h.SessionID))
		}
		if h.SNI() == "" {
			t.Errorf("%s: no SNI", name)
		}
		if h.Find(ExtKeyShare) == nil {
			t.Errorf("%s: no key_share", name)
		}
		// Chrome pins GREASE at both ends of the extension list.
		first, last := h.Extensions[0].Type, h.Extensions[len(h.Extensions)-1].Type
		if !IsGREASE(first) {
			t.Errorf("%s: first extension %#04x is not GREASE", name, first)
		}
		if !IsGREASE(last) && last != ExtPreSharedKey {
			t.Errorf("%s: last extension %#04x is neither GREASE nor pre_shared_key", name, last)
		}
	}
}

func TestSetSNIRewritesAndStaysParseable(t *testing.T) {
	for name, rec := range realHellos(t) {
		h, err := ParseClientHello(rec)
		if err != nil {
			t.Fatal(err)
		}
		orig := h.SNI()
		for _, cover := range []string{"a.io", "www.microsoft.com", strings.Repeat("x", 200) + ".example"} {
			h2, _ := ParseClientHello(rec)
			if err := h2.SetSNI(cover); err != nil {
				t.Fatalf("%s: SetSNI(%q): %v", name, cover, err)
			}
			out := h2.Marshal()
			back, err := ParseClientHello(out)
			if err != nil {
				t.Fatalf("%s: rewritten hello does not parse: %v", name, err)
			}
			if back.SNI() != cover {
				t.Errorf("%s: SNI is %q, want %q", name, back.SNI(), cover)
			}
			// everything except server_name must be untouched
			if len(back.Extensions) != len(h.Extensions) {
				t.Errorf("%s: extension count changed %d -> %d", name, len(h.Extensions), len(back.Extensions))
			}
			delta := len(out) - len(rec)
			want := len(cover) - len(orig)
			if delta != want {
				t.Errorf("%s: length delta %d, want %d (cascade is wrong)", name, delta, want)
			}
		}
		break // one hello exercises every path; the corpus is covered by round-trip
	}
}

func TestIsGREASE(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0xdada, 0xfafa} {
		if !IsGREASE(v) {
			t.Errorf("%#04x should be GREASE", v)
		}
	}
	for _, v := range []uint16{0x0000, 0x0033, 0xfe0d, 0x12e0, 0x0a1a} {
		if IsGREASE(v) {
			t.Errorf("%#04x should not be GREASE", v)
		}
	}
}
