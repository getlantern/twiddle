package twiddle

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePool writes hellos to a temp pool file and returns its path.
func writePool(t *testing.T, name string, hellos [][]byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(FormatPool(hellos)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// sniHello returns a pooled hello rewritten to carry the given server name, so
// tests can tell two otherwise identical pools apart.
func sniHello(t *testing.T, name string) []byte {
	t.Helper()
	h, err := ParseClientHello(DefaultPool()[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := h.SetSNI(name); err != nil {
		t.Fatal(err)
	}
	return h.Marshal()
}

func TestLoadPoolPrefersDevice(t *testing.T) {
	device := writePool(t, "device.hex", [][]byte{sniHello(t, "device.example")})
	config := writePool(t, "config.hex", [][]byte{sniHello(t, "config.example")})

	p, err := LoadPool(Sources{Device: device, Config: config})
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != OriginDevice {
		t.Fatalf("origin = %v, want device", p.Origin)
	}
	h, _ := ParseClientHello(p.Hellos[0])
	if got := h.SNI(); got != "device.example" {
		t.Errorf("loaded the wrong pool: SNI %q", got)
	}
}

func TestLoadPoolFallsThroughToConfigThenEmbedded(t *testing.T) {
	config := writePool(t, "config.hex", [][]byte{sniHello(t, "config.example")})

	// Device path absent: config wins.
	p, err := LoadPool(Sources{Device: filepath.Join(t.TempDir(), "missing.hex"), Config: config})
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != OriginConfig {
		t.Fatalf("origin = %v, want config", p.Origin)
	}
	if len(p.Skipped) != 0 {
		t.Errorf("an absent device pool is the normal case, should not be reported: %v", p.Skipped)
	}

	// Neither path set: embedded only when explicitly allowed.
	p, err = LoadPool(Sources{})
	if err == nil {
		t.Fatal("empty sources must not silently use the stale embedded pool")
	}

	p, err = LoadPool(Sources{AllowEmbedded: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != OriginEmbedded {
		t.Fatalf("origin = %v, want embedded", p.Origin)
	}
	if len(p.Hellos) == 0 {
		t.Error("embedded fallback is empty")
	}
	if err := Coherent(p.Hellos); err != nil {
		t.Errorf("embedded fallback is not one build: %v", err)
	}
}

// A device pool whose every entry is unusable must not strand the client on an
// empty pool -- it must fall through, and say why.
func TestLoadPoolFallsThroughOnUnusableEntries(t *testing.T) {
	dir := t.TempDir()
	device := filepath.Join(dir, "device.hex")
	body := "not-hex\n" + hex.EncodeToString([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0xff}) + "\n"
	if err := os.WriteFile(device, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := LoadPool(Sources{Device: device})
	if err == nil {
		t.Fatal("an unusable device pool must not fall through to embedded")
	}
	if p != nil {
		t.Fatalf("got pool origin %v, want error", p.Origin)
	}

	p, err = LoadPool(Sources{Device: device, AllowEmbedded: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != OriginEmbedded {
		t.Fatalf("origin = %v, want embedded", p.Origin)
	}
	// Two bad lines, plus whatever the embedded fallback reports about itself.
	var lineErrs int
	for _, e := range p.Skipped {
		if strings.Contains(e.Error(), device) {
			lineErrs++
		}
	}
	if lineErrs != 2 {
		t.Fatalf("Skipped = %v, want one error per bad line", p.Skipped)
	}
}

// A device tap sees every TLS client on the box. Non-Chrome entries should be
// dropped without discarding the Chrome-shaped ones alongside them.
func TestLoadPoolKeepsGoodEntriesAmongBad(t *testing.T) {
	dir := t.TempDir()
	device := filepath.Join(dir, "device.hex")
	good := sniHello(t, "good.example")
	body := "# a comment\n\nnot-hex\n" + hex.EncodeToString(good) + "\n"
	if err := os.WriteFile(device, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := LoadPool(Sources{Device: device})
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != OriginDevice || len(p.Hellos) != 1 {
		t.Fatalf("origin=%v hellos=%d, want device with 1", p.Origin, len(p.Hellos))
	}
	if len(p.Skipped) != 1 {
		t.Errorf("Skipped = %v, want the one bad line reported", p.Skipped)
	}
}

// The harvest tools write "<id> <hex>", and testdata is in that form. Feeding
// those in directly should work rather than being a silent footgun.
func TestReadPoolAcceptsLabelledLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "labelled.hex")
	body := "7 " + hex.EncodeToString(sniHello(t, "labelled.example")) + "\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	hellos, errs := readPoolFile(p)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	if len(hellos) != 1 {
		t.Fatalf("got %d hellos, want 1", len(hellos))
	}
}

// Sources are tried whole. A pool that mixes builds must be rejected rather
// than emitted, because alternating fingerprints across connections is a
// sharper signal than a stale pool.
func TestCoherentRejectsMixedBuilds(t *testing.T) {
	a := DefaultPool()[0]
	h, err := ParseClientHello(a)
	if err != nil {
		t.Fatal(err)
	}
	// Drop one extension: a different build, structurally.
	for i, e := range h.Extensions {
		if e.Type == ExtServerPadding {
			h.Extensions = append(h.Extensions[:i:i], h.Extensions[i+1:]...)
			break
		}
	}
	b := h.Marshal()

	if err := Coherent([][]byte{a}); err != nil {
		t.Errorf("single hello should be coherent: %v", err)
	}
	if err := Coherent([][]byte{a, b}); err == nil {
		t.Error("a pool mixing two extension sets should be rejected")
	} else if !strings.Contains(err.Error(), "browser builds") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// The embedded pool is NOT coherent, and this test pins that finding: four of
// its eight hellos carry server_padding (0x12e0) and four do not, because the
// capture arms mixed a fresh Chrome profile with an established one and that
// extension is field-trial gated. LoadPool must therefore hand back only the
// majority build, never all eight.
func TestEmbeddedPoolIsPartitionedByBuild(t *testing.T) {
	raw := DefaultPool()
	if err := Coherent(raw); err == nil {
		t.Fatal("embedded pool is now coherent; drop the partitioning workaround and this test")
	}

	p, err := LoadPool(Sources{AllowEmbedded: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := Coherent(p.Hellos); err != nil {
		t.Fatalf("LoadPool handed back an incoherent pool: %v", err)
	}
	if len(p.Hellos) >= len(raw) {
		t.Fatalf("kept %d of %d hellos; the minority build was not dropped", len(p.Hellos), len(raw))
	}
	if len(p.Skipped) == 0 {
		t.Error("dropping half the embedded pool must be reported in Skipped")
	}

	// Whichever build wins, it must be the same one on every load.
	for i := 0; i < 5; i++ {
		q, err := LoadPool(Sources{AllowEmbedded: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(q.Hellos) != len(p.Hellos) {
			t.Fatal("LoadPool is not stable across calls")
		}
		for j := range q.Hellos {
			if hex.EncodeToString(q.Hellos[j]) != hex.EncodeToString(p.Hellos[j]) {
				t.Fatal("LoadPool picked a different build on a later call")
			}
		}
	}
	t.Logf("embedded pool: kept %d of %d hellos, one build", len(p.Hellos), len(raw))
}

// The ECH GREASE bucket must never be what splits a pool -- Chrome redraws it
// per connection, so hellos differing only in ECH length are one build.
func TestECHBucketDoesNotSplitBuilds(t *testing.T) {
	p, err := LoadPool(Sources{AllowEmbedded: true})
	if err != nil {
		t.Fatal(err)
	}
	lens := map[int]bool{}
	for _, rec := range p.Hellos {
		h, _ := ParseClientHello(rec)
		if e := h.Find(ExtECH); e != nil {
			lens[len(e.Data)] = true
		}
	}
	if len(lens) < 2 {
		t.Skipf("majority build has only one ECH bucket (%v); nothing to prove", lens)
	}
	if err := Coherent(p.Hellos); err != nil {
		t.Fatalf("ECH bucket split a single build: %v", err)
	}
	t.Logf("one build across %d distinct ECH bucket lengths: %v", len(lens), lens)
}

// A GREASE cipher suite is redrawn every connection -- the embedded pool shows
// seven distinct first-suite values across eight hellos -- so it must not
// contribute to the build fingerprint.
func TestFingerprintNormalisesGREASECipherSuite(t *testing.T) {
	a, err := ParseClientHello(DefaultPool()[0])
	if err != nil {
		t.Fatal(err)
	}
	if !IsGREASE(a.CipherSuites[0]) {
		t.Skip("first cipher suite is not GREASE in this pool")
	}
	before := a.Fingerprint()
	a.CipherSuites[0] = 0xdada // another GREASE draw
	if got := a.Fingerprint(); got != before {
		t.Errorf("fingerprint changed with the GREASE cipher draw: %s != %s", got, before)
	}
	a.CipherSuites[0] = 0x1302 // a real suite: a different build
	if got := a.Fingerprint(); got == before {
		t.Error("fingerprint ignored a real cipher-suite change")
	}
}

// Fingerprint must ignore per-connection variation. Two emissions of the same
// harvested hello differ in order, random, key shares and ECH bucket, and must
// still fingerprint as the same build once the ECH length is normalised.
func TestFingerprintIgnoresPerConnectionVariation(t *testing.T) {
	h, err := ParseClientHello(DefaultPool()[0])
	if err != nil {
		t.Fatal(err)
	}
	want := h.fingerprintIgnoringECHLength()

	for i := 0; i < 20; i++ {
		c, err := ParseClientHello(DefaultPool()[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Rerandomize(); err != nil {
			t.Fatal(err)
		}
		if err := c.Shuffle(); err != nil {
			t.Fatal(err)
		}
		if got := c.fingerprintIgnoringECHLength(); got != want {
			t.Fatalf("iteration %d: fingerprint changed after rerandomize+shuffle: %s != %s", i, got, want)
		}
	}
}

func TestUsableRejectsWhatTwiddleCannotEmit(t *testing.T) {
	base := DefaultPool()[0]
	if err := Usable(base); err != nil {
		t.Fatalf("a pooled hello should be usable: %v", err)
	}

	strip := func(typ uint16) []byte {
		h, err := ParseClientHello(base)
		if err != nil {
			t.Fatal(err)
		}
		for i, e := range h.Extensions {
			if e.Type == typ {
				h.Extensions = append(h.Extensions[:i:i], h.Extensions[i+1:]...)
				break
			}
		}
		return h.Marshal()
	}

	for _, tc := range []struct {
		name string
		rec  []byte
		want string
	}{
		{"no server_name", strip(ExtServerName), "server_name"},
		{"no key_share", strip(ExtKeyShare), "key_share"},
		{"truncated", base[:20], "does not match"},
	} {
		err := Usable(tc.rec)
		if err == nil {
			t.Errorf("%s: expected rejection", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.want)
		}
	}
}

// A hello carrying pre_shared_key is a resumption hello holding a real ticket
// for a real site. It must be rejected until sanitised, and sanitising must
// make it usable.
func TestUsableRejectsResumptionUntilSanitized(t *testing.T) {
	h, err := ParseClientHello(DefaultPool()[0])
	if err != nil {
		t.Fatal(err)
	}
	// Append a PSK the way a resumption hello carries it: after the trailing
	// GREASE, which is where Chrome puts it.
	h.Extensions = append(h.Extensions, Extension{ExtPreSharedKey, []byte{0xde, 0xad}})
	withPSK := h.Marshal()

	err = Usable(withPSK)
	if err == nil || !strings.Contains(err.Error(), "pre_shared_key") {
		t.Fatalf("expected a pre_shared_key rejection, got %v", err)
	}

	h2, err := ParseClientHello(withPSK)
	if err != nil {
		t.Fatal(err)
	}
	if err := h2.Sanitize(); err != nil {
		t.Fatal(err)
	}
	if err := Usable(h2.Marshal()); err != nil {
		t.Errorf("sanitized hello should be usable: %v", err)
	}
}

// Sanitize is the privacy boundary for the device path: nothing it writes to
// disk may still name the site the user visited or carry that site's ticket.
func TestSanitizeRemovesUserTraces(t *testing.T) {
	h, err := ParseClientHello(DefaultPool()[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := h.SetSNI("private.bank.example"); err != nil {
		t.Fatal(err)
	}
	if e := h.Find(ExtSessionTicket); e != nil {
		e.Data = []byte("a real ticket for a real site")
	}
	h.Extensions = append(h.Extensions, Extension{ExtEarlyData, nil})
	for i := range h.Random {
		h.Random[i] = 0xab
	}

	echBefore, ksBefore := -1, -1
	if e := h.Find(ExtECH); e != nil {
		echBefore = len(e.Data)
	}
	if e := h.Find(ExtKeyShare); e != nil {
		ksBefore = len(e.Data)
	}

	if err := h.Sanitize(); err != nil {
		t.Fatal(err)
	}
	wire := h.Marshal()

	if strings.Contains(string(wire), "private.bank.example") {
		t.Error("sanitized hello still names the visited site")
	}
	if strings.Contains(string(wire), "a real ticket") {
		t.Error("sanitized hello still carries the site's session ticket")
	}
	if h.Find(ExtEarlyData) != nil {
		t.Error("early_data survived sanitize")
	}
	if h.Random != [32]byte{} {
		t.Error("client random survived sanitize")
	}

	// key_share and ECH must survive untouched: the emitter reads their
	// structure back before replacing their contents.
	if e := h.Find(ExtECH); e == nil || len(e.Data) != echBefore {
		t.Errorf("ECH length changed: %v, want %d", e, echBefore)
	}
	if e := h.Find(ExtKeyShare); e == nil || len(e.Data) != ksBefore {
		t.Errorf("key_share length changed: %v, want %d", e, ksBefore)
	}
	if err := Usable(h.Marshal()); err != nil {
		t.Errorf("sanitized hello is no longer usable: %v", err)
	}
}

// The point of the whole exercise: a hello that came off disk must still make
// it all the way through Twiddle.
func TestLoadedPoolSurvivesTwiddle(t *testing.T) {
	h, err := ParseClientHello(DefaultPool()[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := h.SetSNI("tapped.example"); err != nil {
		t.Fatal(err)
	}
	if err := h.Sanitize(); err != nil {
		t.Fatal(err)
	}
	path := writePool(t, "device.hex", [][]byte{h.Marshal()})

	p, err := LoadPool(Sources{Device: path})
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != OriginDevice {
		t.Fatalf("origin = %v, want device", p.Origin)
	}

	k := new(TicketKey)
	cred, err := k.Issue(1, DefaultTicketLen)
	if err != nil {
		t.Fatal(err)
	}
	wire, eph, err := Twiddle(p.Hellos[0], Options{
		CoverSNI:   "www.microsoft.com",
		Credential: cred,
		BinderLen:  32,
	})
	if err != nil {
		t.Fatalf("Twiddle on a disk-sourced hello: %v", err)
	}
	if eph == nil {
		t.Error("no ephemeral returned")
	}
	out, err := ParseClientHello(wire)
	if err != nil {
		t.Fatalf("emitted hello does not parse: %v", err)
	}
	if out.SNI() != "www.microsoft.com" {
		t.Errorf("SNI = %q, want the cover domain", out.SNI())
	}
}

func TestFormatPoolRoundTrips(t *testing.T) {
	want := DefaultPool()
	path := writePool(t, "round.hex", want)
	got, errs := readPoolFile(path)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d hellos, want %d", len(got), len(want))
	}
	for i := range want {
		if hex.EncodeToString(got[i]) != hex.EncodeToString(want[i]) {
			t.Errorf("hello %d did not round-trip", i)
		}
	}
}

func TestOriginString(t *testing.T) {
	for o, want := range map[Origin]string{
		OriginDevice: "device", OriginConfig: "config", OriginEmbedded: "embedded",
	} {
		if got := o.String(); got != want {
			t.Errorf("Origin(%d) = %q, want %q", o, got, want)
		}
	}
}

// The config service delivers hellos in its JSON body, not as a file. That
// must be the same tier as a config-written file, and must still lose to the
// device tap.
func TestConfigInlineIsTheConfigTier(t *testing.T) {
	inline := FormatPool([][]byte{sniHello(t, "inline.example")})

	p, err := LoadPool(Sources{ConfigInline: inline})
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != OriginConfig {
		t.Fatalf("origin = %v, want config", p.Origin)
	}
	h, _ := ParseClientHello(p.Hellos[0])
	if h.SNI() != "inline.example" {
		t.Errorf("loaded SNI %q, want the inline pool", h.SNI())
	}

	// Device still wins.
	device := writePool(t, "device.hex", [][]byte{sniHello(t, "device.example")})
	p, err = LoadPool(Sources{Device: device, ConfigInline: inline})
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != OriginDevice {
		t.Fatalf("origin = %v, want device to beat inline config", p.Origin)
	}

	// A readable config FILE takes the tier; inline is the fallback within it.
	file := writePool(t, "config.hex", [][]byte{sniHello(t, "file.example")})
	p, err = LoadPool(Sources{Config: file, ConfigInline: inline})
	if err != nil {
		t.Fatal(err)
	}
	h, _ = ParseClientHello(p.Hellos[0])
	if h.SNI() != "file.example" {
		t.Errorf("loaded SNI %q, want the config file to win its own tier", h.SNI())
	}
}

// An unusable inline pool must fall through to embedded rather than stranding
// the client, and must say why.
func TestConfigInlineFallsThroughWhenUnusable(t *testing.T) {
	p, err := LoadPool(Sources{ConfigInline: "not-hex\n"})
	if err == nil {
		t.Fatal("an unusable inline pool must not fall through to embedded")
	}
	if p != nil {
		t.Fatalf("got pool origin %v, want error", p.Origin)
	}

	p, err = LoadPool(Sources{ConfigInline: "not-hex\n", AllowEmbedded: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin != OriginEmbedded {
		t.Fatalf("origin = %v, want embedded", p.Origin)
	}
	var sawInline bool
	for _, e := range p.Skipped {
		if strings.Contains(e.Error(), "inline") {
			sawInline = true
		}
	}
	if !sawInline {
		t.Errorf("Skipped does not mention the inline pool: %v", p.Skipped)
	}
}
