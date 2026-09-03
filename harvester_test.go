package twiddle

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// tapped builds a hello of the shape a device tap would see: a real pooled
// hello rewritten to name a site the user visited.
func tapped(t *testing.T, sni string, _ uint16) []byte {
	t.Helper()
	h, err := ParseClientHello(DefaultPool()[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := h.SetSNI(sni); err != nil {
		t.Fatal(err)
	}
	return h.Marshal()
}

// tappedVariant builds a hello that genuinely CONTRIBUTES: same build, but with
// a distinct body in an extension the emitter does not regenerate. This is how
// real same-build hellos differ -- Chrome 152 varies 0xca34 per connection at a
// constant length -- so it is what the harvester should be storing.
//
// Varying GREASE would not do: since rerandGREASE, GREASE draws are generated
// per connection and two hellos differing only there are interchangeable.
func tappedVariant(t *testing.T, sni string, marker byte) []byte {
	t.Helper()
	h, err := ParseClientHello(tapped(t, sni, 0))
	if err != nil {
		t.Fatal(err)
	}
	last := h.Extensions[len(h.Extensions)-1]
	h.Extensions = append(h.Extensions[:len(h.Extensions)-1:len(h.Extensions)-1],
		Extension{0xca34, bytes.Repeat([]byte{marker}, 206)}, last)
	return h.Marshal()
}

func TestHarvesterAcceptsAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "device.hex")
	hv := NewHarvester(path, 0)

	ok, err := hv.Offer(tapped(t, "news.example", 0x1a1a))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("a real Chrome hello was not accepted")
	}
	if hv.Len() != 1 {
		t.Fatalf("pool holds %d, want 1", hv.Len())
	}

	// It must be on disk, and LoadPool must pick it as the device tier.
	p, err := LoadPool(Sources{Device: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != OriginDevice {
		t.Fatalf("origin = %v, want device", p.Origin)
	}
	if len(p.Hellos) != 1 {
		t.Fatalf("loaded %d hellos, want 1", len(p.Hellos))
	}
}

// The privacy obligation, end to end: nothing the harvester writes may name the
// site the user visited or carry that site's ticket.
func TestHarvesterNeverPersistsUserTraces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.hex")
	hv := NewHarvester(path, 0)

	h, err := ParseClientHello(DefaultPool()[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := h.SetSNI("private.bank.example"); err != nil {
		t.Fatal(err)
	}
	if e := h.Find(ExtSessionTicket); e != nil {
		e.Data = []byte("REAL-TICKET-FOR-A-REAL-SITE")
	}
	if _, err := hv.Offer(h.Marshal()); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded := strings.ToLower(string(raw))
	for _, secret := range []string{"private.bank.example", "REAL-TICKET-FOR-A-REAL-SITE"} {
		if strings.Contains(string(body), secret) {
			t.Errorf("pool file contains %q verbatim", secret)
		}
		if strings.Contains(decoded, strings.ToLower(hexOf(secret))) {
			t.Errorf("pool file contains %q hex-encoded", secret)
		}
	}
}

func hexOf(s string) string {
	const digits = "0123456789abcdef"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteByte(digits[s[i]>>4])
		b.WriteByte(digits[s[i]&0x0f])
	}
	return b.String()
}

// Two hellos that differ only in fields the emitter regenerates are
// interchangeable, so the second must not be stored.
func TestHarvesterDedupsInterchangeableHellos(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.hex")
	hv := NewHarvester(path, 0)

	first := tapped(t, "a.example", 0x1a1a)
	if ok, err := hv.Offer(first); err != nil || !ok {
		t.Fatalf("first offer: ok=%v err=%v", ok, err)
	}

	// Same build; differs only in SNI and in everything Rerandomize touches --
	// which since the GREASE fix includes the GREASE draws themselves.
	second, err := ParseClientHello(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.SetSNI("b.example"); err != nil {
		t.Fatal(err)
	}
	if err := second.Rerandomize(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := hv.Offer(second.Marshal()); ok {
		t.Error("an interchangeable hello was stored")
	}
	if hv.Len() != 1 {
		t.Errorf("pool holds %d, want 1", hv.Len())
	}
}

// A body we do NOT regenerate is a real contribution. Chrome 152 varies 0xca34
// per connection at a constant length, so two hellos identical but for that
// body are both worth holding.
func TestHarvesterStoresUnmodelledVariation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.hex")
	hv := NewHarvester(path, 0)

	if ok, err := hv.Offer(tappedVariant(t, "a.example", 0x01)); err != nil || !ok {
		t.Fatalf("first: ok=%v err=%v", ok, err)
	}
	if ok, err := hv.Offer(tappedVariant(t, "a.example", 0x02)); err != nil || !ok {
		t.Fatalf("a differing 0xca34 body was not treated as a contribution: ok=%v err=%v", ok, err)
	}
	if hv.Len() != 2 {
		t.Fatalf("pool holds %d, want 2", hv.Len())
	}
	// Same length and same build, so this must not have looked like two builds.
	stored, _ := readPoolFile(path)
	if err := Coherent(stored); err != nil {
		t.Errorf("a varying body split the build: %v", err)
	}
}

// The dedup key must contain nothing the emitter regenerates. If Rerandomize or
// Shuffle changes the key, the harvester will hoard entries that differ only in
// fields we overwrite -- and the key's definition has drifted from the pipeline.
func TestContributionKeySurvivesTheEmitter(t *testing.T) {
	base := tapped(t, "a.example", 0x1a1a)
	want, ok := contributionKey(base)
	if !ok {
		t.Fatal("no key for a pooled hello")
	}
	for i := 0; i < 25; i++ {
		h, err := ParseClientHello(base)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Rerandomize(); err != nil {
			t.Fatal(err)
		}
		if err := h.Shuffle(); err != nil {
			t.Fatal(err)
		}
		if _, err := h.SetKeyShare(); err != nil {
			t.Fatal(err)
		}
		got, ok := contributionKey(h.Marshal())
		if !ok {
			t.Fatal("no key after emission")
		}
		if got != want {
			t.Fatalf("iteration %d: key changed under the emitter: %s != %s", i, got, want)
		}
	}
}

func TestHarvesterRejectsWhatItCannotEmit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.hex")
	hv := NewHarvester(path, 0)

	// A tap sees every TLS client on the box, plus plain non-TLS traffic.
	for _, tc := range []struct {
		name string
		rec  []byte
	}{
		{"not a record", []byte("GET / HTTP/1.1\r\n\r\n")},
		{"truncated", DefaultPool()[0][:40]},
		{"empty", nil},
	} {
		if ok, err := hv.Offer(tc.rec); ok || err != nil {
			t.Errorf("%s: accepted=%v err=%v", tc.name, ok, err)
		}
	}
	if hv.Len() != 0 {
		t.Errorf("pool holds %d, want 0", hv.Len())
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("harvester wrote a file despite accepting nothing")
	}
}

// A hello with no server_name -- Chrome sends these for IP-literal
// destinations, so a tap will see them -- has no SNI to rewrite and must be
// refused rather than stored and failed at connection time.
func TestHarvesterRejectsHellosWithoutSNI(t *testing.T) {
	h, err := ParseClientHello(DefaultPool()[0])
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range h.Extensions {
		if e.Type == ExtServerName {
			h.Extensions = append(h.Extensions[:i:i], h.Extensions[i+1:]...)
			break
		}
	}
	hv := NewHarvester(filepath.Join(t.TempDir(), "device.hex"), 0)
	if ok, _ := hv.Offer(h.Marshal()); ok {
		t.Error("stored a hello with no server_name")
	}
}

// A resumption hello carries a live ticket for a real site. Sanitize converts
// it to a full hello, so it should be accepted -- with the ticket gone.
func TestHarvesterAcceptsResumptionHellosAsFullOnes(t *testing.T) {
	h, err := ParseClientHello(DefaultPool()[0])
	if err != nil {
		t.Fatal(err)
	}
	h.Extensions = append(h.Extensions, Extension{ExtPreSharedKey, []byte("live-ticket")})
	path := filepath.Join(t.TempDir(), "device.hex")
	hv := NewHarvester(path, 0)

	ok, err := hv.Offer(h.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("a resumption hello was refused outright")
	}
	stored, errs := readPoolFile(path)
	if len(errs) != 0 || len(stored) != 1 {
		t.Fatalf("stored=%d errs=%v", len(stored), errs)
	}
	out, err := ParseClientHello(stored[0])
	if err != nil {
		t.Fatal(err)
	}
	if out.Find(ExtPreSharedKey) != nil {
		t.Error("pre_shared_key survived into the pool")
	}
	if strings.Contains(string(stored[0]), "live-ticket") {
		t.Error("the site's ticket survived into the pool")
	}
}

// A device that auto-updates Chrome offers a new build against a file holding
// the old one. The pool must not end up mixing them.
func TestHarvesterKeepsOneBuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.hex")
	hv := NewHarvester(path, 0)

	for _, m := range []byte{1, 2, 3} {
		if ok, err := hv.Offer(tappedVariant(t, "a.example", m)); err != nil || !ok {
			t.Fatalf("offer variant %d: ok=%v err=%v", m, ok, err)
		}
	}

	// A structurally different build: one fewer extension.
	other, err := ParseClientHello(tappedVariant(t, "new.example", 9))
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range other.Extensions {
		if e.Type == ExtServerPadding {
			other.Extensions = append(other.Extensions[:i:i], other.Extensions[i+1:]...)
			break
		}
	}
	hv.Offer(other.Marshal())

	stored, errs := readPoolFile(path)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	if err := Coherent(stored); err != nil {
		t.Errorf("harvested pool mixes builds: %v", err)
	}
}

func otherBuildHello(t *testing.T, marker byte) []byte {
	t.Helper()
	other, err := ParseClientHello(tappedVariant(t, "new.example", marker))
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range other.Extensions {
		if e.Type == ExtServerPadding {
			other.Extensions = append(other.Extensions[:i:i], other.Extensions[i+1:]...)
			break
		}
	}
	return other.Marshal()
}

func thirdBuildHello(t *testing.T, marker byte) []byte {
	t.Helper()
	third, err := ParseClientHello(otherBuildHello(t, marker))
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range third.Extensions {
		if e.Type == ExtSupportedVersions {
			third.Extensions = append(third.Extensions[:i:i], third.Extensions[i+1:]...)
			return third.Marshal()
		}
	}
	t.Fatal("test hello has no supported_versions extension")
	return nil
}

// After two old-build hellos, Offer used to reject every new-build sample
// because each was a 1-vs-2 minority. Ten new-build offers then accepted 0.
func TestHarvesterNewBuildCanTakeOver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.hex")
	hv := NewHarvester(path, 0)

	for _, m := range []byte{1, 2} {
		if ok, err := hv.Offer(tappedVariant(t, "a.example", m)); err != nil || !ok {
			t.Fatalf("seed old build %d: ok=%v err=%v", m, ok, err)
		}
	}
	if hv.Len() != 2 {
		t.Fatalf("seeded %d, want 2", hv.Len())
	}

	accepted := 0
	for m := byte(1); m <= 10; m++ {
		ok, err := hv.Offer(otherBuildHello(t, m))
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			accepted++
		}
	}
	if accepted == 0 {
		t.Fatal("new-build hellos were all rejected; the new build can never become the majority")
	}
	stored, _ := readPoolFile(path)
	if err := Coherent(stored); err != nil {
		t.Fatalf("after takeover the pool mixes builds: %v", err)
	}
	h, err := ParseClientHello(stored[0])
	if err != nil {
		t.Fatal(err)
	}
	if h.Find(ExtServerPadding) != nil {
		t.Fatal("emit pool is still the old build")
	}
}

func TestHarvesterPromotesOnePendingBuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.hex")
	hv := NewHarvester(path, 0)
	for _, marker := range []byte{1, 2} {
		if ok, err := hv.Offer(tappedVariant(t, "a.example", marker)); err != nil || !ok {
			t.Fatalf("seed active build %d: ok=%v err=%v", marker, ok, err)
		}
	}

	for _, offer := range []struct {
		record []byte
		want   bool
	}{
		{otherBuildHello(t, 1), false},
		{thirdBuildHello(t, 1), false},
		{otherBuildHello(t, 2), false},
		{otherBuildHello(t, 3), true},
	} {
		ok, err := hv.Offer(offer.record)
		if err != nil {
			t.Fatal(err)
		}
		if ok != offer.want {
			t.Fatalf("Offer returned %v, want %v", ok, offer.want)
		}
	}

	stored, errs := readPoolFile(path)
	if len(errs) != 0 {
		t.Fatalf("read promoted pool: %v", errs)
	}
	if len(stored) != 3 {
		t.Fatalf("promoted pool has %d records, want 3 from the winning build", len(stored))
	}
	if err := Coherent(stored); err != nil {
		t.Fatalf("promoted pool mixes pending builds: %v", err)
	}
}

func TestHarvesterHonoursMaxAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.hex")
	hv := NewHarvester(path, 3)

	for _, m := range []byte{1, 2, 3, 4, 5} {
		if _, err := hv.Offer(tappedVariant(t, "a.example", m)); err != nil {
			t.Fatal(err)
		}
	}
	if hv.Len() != 3 {
		t.Fatalf("pool holds %d, want the 3-entry cap", hv.Len())
	}

	// A fresh harvester over the same file picks up what is there.
	again := NewHarvester(path, 3)
	if again.Len() != 3 {
		t.Errorf("reopened harvester holds %d, want 3", again.Len())
	}
}

// A corrupt existing file must not stop the device tier working -- refusing to
// harvest would strand the device on a staler tier permanently.
func TestHarvesterSurvivesACorruptExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.hex")
	if err := os.WriteFile(path, []byte("garbage\nnot hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hv := NewHarvester(path, 0)
	if hv.Len() != 0 {
		t.Fatalf("pool holds %d, want 0", hv.Len())
	}
	if ok, err := hv.Offer(tapped(t, "a.example", 0)); err != nil || !ok {
		t.Fatalf("harvesting stopped after a corrupt file: ok=%v err=%v", ok, err)
	}
}

// Offer runs on the connection path, so it must be safe under concurrency.
func TestHarvesterIsConcurrencySafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.hex")
	hv := NewHarvester(path, 0)

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hv.Offer(tappedVariant(t, "a.example", byte(i)))
		}(i)
	}
	wg.Wait()

	stored, errs := readPoolFile(path)
	if len(errs) != 0 {
		t.Errorf("concurrent writes produced a corrupt file: %v", errs)
	}
	if len(stored) == 0 {
		t.Error("nothing was stored")
	}
	if err := Coherent(stored); err != nil {
		t.Errorf("concurrent writes produced a mixed pool: %v", err)
	}
}

// What the harvester stores must survive the full emission pipeline.
func TestHarvestedPoolSurvivesTwiddle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.hex")
	hv := NewHarvester(path, 0)
	if ok, err := hv.Offer(tapped(t, "news.example", 0x1a1a)); err != nil || !ok {
		t.Fatalf("offer: ok=%v err=%v", ok, err)
	}

	p, err := LoadPool(Sources{Device: path})
	if err != nil {
		t.Fatal(err)
	}
	k := new(TicketKey)
	cred, err := k.Issue(1, DefaultTicketLen)
	if err != nil {
		t.Fatal(err)
	}
	wire, _, err := Twiddle(p.Hellos[0], Options{
		CoverSNI: "www.microsoft.com", Credential: cred, BinderLen: 32,
	})
	if err != nil {
		t.Fatalf("Twiddle on a harvested hello: %v", err)
	}
	out, err := ParseClientHello(wire)
	if err != nil {
		t.Fatal(err)
	}
	if out.SNI() != "www.microsoft.com" {
		t.Errorf("SNI = %q", out.SNI())
	}
	// The record must still be self-consistent after every length cascade.
	if n := int(binary.BigEndian.Uint16(wire[3:5])); len(wire) != 5+n {
		t.Errorf("record length %d does not match %d bytes", n, len(wire)-5)
	}
}
