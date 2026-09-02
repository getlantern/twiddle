package twiddle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
)

// Origin says where a pool's hellos came from. Higher is better, and the
// ordering is the whole point of reading pools off disk rather than compiling
// them in:
//
//	OriginDevice   — tapped from this device's own outbound TLS traffic
//	OriginConfig   — delivered by the config service
//	OriginEmbedded — the compiled-in snapshot in pool/chrome.hex
//
// Device beats config because it is the only source that cannot go stale: it is
// by construction the hello the browser on THIS device is emitting right now,
// from the version installed here, on this OS, with this device's field-trial
// state. Config beats embedded for the same reason one step weaker -- it can be
// refreshed without shipping a binary.
//
// The staleness this ordering defends against is measurable, not theoretical.
// The embedded pool carries BoringSSL's server_padding (0x12e0) and no 0xca34;
// Chrome 152 sends 0xca34 and has dropped 0x12e0 entirely, and its hellos run
// 1919-1983 bytes against the pool's 1725-1827. A client emitting the embedded
// pool today is not emitting anything Chrome 152 emits.
type Origin int

const (
	OriginEmbedded Origin = iota
	OriginConfig
	OriginDevice
)

func (o Origin) String() string {
	switch o {
	case OriginDevice:
		return "device"
	case OriginConfig:
		return "config"
	case OriginEmbedded:
		return "embedded"
	}
	return "unknown"
}

// Sources names where a pool may be read from. Every field may be empty;
// LoadPool falls through to the next source, and to the embedded pool last.
type Sources struct {
	// Device is the path to a pool written by whatever on this device taps
	// outbound TLS. Entries must already be sanitised -- see Sanitize.
	Device string
	// Config is the path to a pool written by the config fetcher.
	Config string
	// ConfigInline is a pool carried directly in a config response, in the same
	// one-record-per-line form as the files. It ranks with Config, not above or
	// below it, and is used when Config names no readable file -- a config
	// service that delivers hellos in its JSON body and one that drops them in a
	// file are the same tier of trust and the same staleness risk.
	ConfigInline string
}

// Pool is a set of harvested hellos and a record of where they came from.
type Pool struct {
	Hellos [][]byte
	Origin Origin
	// Skipped explains why every higher-preference source was not used. It is
	// diagnostic, not fatal: a client that silently drops to the embedded pool
	// looks fine while emitting a stale fingerprint, so callers should log this.
	Skipped []error
}

// LoadPool returns the best usable pool: device, else config, else embedded.
//
// Sources are never merged. A real browser install emits hellos from exactly
// one build, so a pool blending a device-tapped Chrome 152 hello with a
// config-delivered Chrome 141 one would have this client alternating between
// two fingerprints across connections -- which is not a thing any browser does,
// and is a sharper signal than either pool alone.
//
// Within a source the same rule applies, but rejection would be the wrong
// remedy: a device tap running across a Chrome auto-update legitimately holds
// hellos from two builds, and discarding the file for that would drop this
// client back to the stale embedded pool -- the worse of the two outcomes. So
// an incoherent source is PARTITIONED by build and the largest partition wins.
// The minority is reported in Skipped rather than emitted.
func LoadPool(s Sources) (*Pool, error) {
	var skipped []error
	for _, src := range []struct {
		origin Origin
		path   string
		inline string
	}{
		{origin: OriginDevice, path: s.Device},
		{origin: OriginConfig, path: s.Config, inline: s.ConfigInline},
	} {
		if src.path == "" && src.inline == "" {
			continue
		}
		hellos, errs := readPoolFile(src.path)
		skipped = append(skipped, errs...)
		if len(hellos) == 0 && src.inline != "" {
			var inlineErrs []error
			hellos, inlineErrs = parsePool(src.inline, src.origin.String()+" (inline)")
			skipped = append(skipped, inlineErrs...)
		}
		if len(hellos) == 0 {
			continue
		}
		best, dropped := largestBuild(hellos)
		if dropped > 0 {
			skipped = append(skipped, fmt.Errorf(
				"twiddle: %s pool mixes builds; kept the %d-hello majority, dropped %d",
				src.origin, len(best), dropped))
		}
		return &Pool{Hellos: best, Origin: src.origin, Skipped: skipped}, nil
	}

	// The embedded pool is partitioned on the same terms. It needs it: four of
	// its eight hellos carry BoringSSL's server_padding (0x12e0) and four do
	// not, because the capture arms included both a fresh profile and an
	// established one, and that extension is field-trial gated. A real install
	// is in the trial or out of it and does not change its mind between
	// connections.
	best, dropped := largestBuild(DefaultPool())
	if dropped > 0 {
		skipped = append(skipped, fmt.Errorf(
			"twiddle: embedded pool mixes builds; kept the %d-hello majority, dropped %d",
			len(best), dropped))
	}
	return &Pool{Hellos: best, Origin: OriginEmbedded, Skipped: skipped}, nil
}

// largestBuild groups hellos by build and returns the biggest group along with
// how many hellos were left out. Ties break on the fingerprint so the choice is
// stable across runs -- a pool that silently changed which build it emitted
// from one process start to the next would defeat the point.
func largestBuild(hellos [][]byte) (best [][]byte, dropped int) {
	groups := map[string][][]byte{}
	for _, rec := range hellos {
		h, err := ParseClientHello(rec)
		if err != nil {
			continue // Usable already screened these; belt and braces
		}
		fp := h.fingerprintIgnoringECHLength()
		groups[fp] = append(groups[fp], rec)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if a, b := len(groups[keys[i]]), len(groups[keys[j]]); a != b {
			return a > b
		}
		return keys[i] < keys[j]
	})
	if len(keys) == 0 {
		return nil, 0
	}
	best = groups[keys[0]]
	return best, len(hellos) - len(best)
}

// readPoolFile reads one pool file, dropping unusable entries rather than
// failing the file.
//
// Tolerance is deliberate and asymmetric to ParsePool, which stays strict for
// the embedded pool because a corrupt embedded pool is a build error. An
// on-disk pool is different: a device tap sees every TLS client on the box --
// Safari, curl, an app's pinned stack, an old Electron build -- and only the
// Chrome-shaped ones can survive Twiddle. Rejecting the file because six of
// twenty entries were not Chrome would throw away a working device pool and
// silently drop to the stale embedded one.
func readPoolFile(path string) ([][]byte, []error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil // absent is not a problem; it is the normal case
		}
		return nil, []error{fmt.Errorf("twiddle: pool %s: %w", path, err)}
	}
	return parsePool(string(b), path)
}

// parsePool reads pool lines from any origin, file or inline, dropping
// unusable entries rather than failing the whole body. what names the source
// in errors.
func parsePool(body, what string) ([][]byte, []error) {
	var out [][]byte
	var errs []error
	for i, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Accept an optional leading label so harvest output ("<id> <hex>") and
		// the testdata files can be fed in directly.
		if f := strings.Fields(line); len(f) > 1 {
			line = f[len(f)-1]
		}
		rec, err := hex.DecodeString(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("twiddle: pool %s line %d: %w", what, i+1, err))
			continue
		}
		if err := Usable(rec); err != nil {
			errs = append(errs, fmt.Errorf("twiddle: pool %s line %d: %w", what, i+1, err))
			continue
		}
		out = append(out, rec)
	}
	return out, errs
}

// FormatPool renders hellos as a pool file, one hex record per line. It is the
// write half of readPoolFile, for whatever assembles a device or config pool.
func FormatPool(hellos [][]byte) string {
	var b strings.Builder
	for _, rec := range hellos {
		b.WriteString(hex.EncodeToString(rec))
		b.WriteByte('\n')
	}
	return b.String()
}

// Usable reports whether a record can survive the Twiddle pipeline, which is
// the real admission test for a tapped hello.
//
// Each check corresponds to a step that would otherwise fail at connection
// time, when there is nothing useful to do about it. The checks mirror
// SetSNI's requirement of a server_name to rewrite, Shuffle's requirement of
// GREASE pinned at both ends, and SetKeyShare's requirement of a key_share to
// replace.
func Usable(rec []byte) error {
	h, err := ParseClientHello(rec)
	if err != nil {
		return err
	}
	if h.Find(ExtServerName) == nil {
		// Chrome omits server_name for IP-literal destinations, so a tap will
		// see these; they are real Chrome hellos but there is no SNI to rewrite.
		return errors.New("twiddle: hello has no server_name to rewrite")
	}
	if h.Find(ExtKeyShare) == nil {
		return errors.New("twiddle: hello has no key_share")
	}
	if h.Find(ExtPreSharedKey) != nil {
		// A resumption hello carries a real ticket for a real site. Pool entries
		// are full hellos; SetTicketAuth appends the PSK itself.
		return errors.New("twiddle: hello carries pre_shared_key; sanitize it first")
	}
	if n := len(h.Extensions); n < 3 {
		return fmt.Errorf("twiddle: hello has %d extensions, too few to shuffle", n)
	}
	if !IsGREASE(h.Extensions[0].Type) {
		return fmt.Errorf("twiddle: first extension %#04x is not GREASE", h.Extensions[0].Type)
	}
	if last := h.Extensions[len(h.Extensions)-1]; !IsGREASE(last.Type) {
		return fmt.Errorf("twiddle: last extension %#04x is not GREASE", last.Type)
	}
	return nil
}

// Sanitize prepares a hello tapped off real device traffic for use as a pool
// entry, and must run BEFORE the hello is written to disk.
//
// Two separate obligations meet here. The privacy one: a tapped hello names a
// site the user actually visited, in the clear, and a resumption hello also
// carries that site's session ticket -- neither belongs in a file we persist,
// let alone one we might ship to an egress. The correctness one: pool entries
// are full-handshake hellos, because SetTicketAuth appends pre_shared_key
// itself and a hello that already has one would end up with two.
//
// Everything blanked here is regenerated per connection by Rerandomize, so
// zeroing costs nothing at emission time.
//
// key_share and ECH are deliberately left ALONE despite also being
// per-connection. Both are structured, and both are read back by the emitter
// before being replaced: rerandKeyShare walks the KeyShareEntry group IDs and
// lengths to know which groups to generate valid keys for, and rerandECHGrease
// reads the advertised HPKE kdf/aead out of the first five bytes to preserve
// them. Blanking either one destroys the structure the emitter needs -- zeroing
// key_share costs the X25519 group ID and makes SetKeyShare fail outright.
// Neither carries anything that identifies the user or the site: they are
// ephemeral public values from a connection that is long over.
func (h *ClientHello) Sanitize() error {
	if h.Find(ExtServerName) == nil {
		return errors.New("twiddle: hello has no server_name")
	}
	// A placeholder of the same length keeps the record length stable; SetSNI
	// rewrites it per connection anyway.
	if err := h.SetSNI(strings.Repeat("x", len(h.SNI()))); err != nil {
		return err
	}

	kept := h.Extensions[:0]
	for _, e := range h.Extensions {
		switch e.Type {
		case ExtPreSharedKey, ExtEarlyData:
			// Drop the resumption carriers. SetTicketAuth re-adds
			// pre_shared_key in the position Chrome puts it.
			continue
		case ExtSessionTicket:
			// A real ticket for a real site. Empty is also what Chrome sends
			// on a full handshake, which is what this hello now is.
			e.Data = nil
		}
		kept = append(kept, e)
	}
	h.Extensions = kept

	h.Random = [32]byte{}
	zero(h.SessionID)
	return nil
}

// Fingerprint digests the fields that identify the browser BUILD rather than
// the connection: the version, cipher suites, compression, and the multiset of
// extension types with their lengths.
//
// Extension ORDER is deliberately excluded. Chrome permutes its interior
// extensions on every connection -- 8 captured connections produced 8 distinct
// orderings -- so order is per-connection noise, and Shuffle reproduces that.
// What must not vary within a pool is the set of extensions and the cipher
// list, because those change only when Chrome does.
func (h *ClientHello) Fingerprint() string {
	var b []byte
	b = appendU16(b, h.LegacyVersion)
	for _, c := range h.CipherSuites {
		// Chrome's first cipher suite is a GREASE value redrawn every
		// connection -- the embedded pool shows 0x4a4a, 0x8a8a, 0x3a3a, 0xfafa,
		// 0xcaca, 0xdada and 0x7a7a across eight captures. Only its presence
		// and position are stable, so normalise the value away.
		if IsGREASE(c) {
			c = 0x0a0a
		}
		b = appendU16(b, c)
	}
	b = append(b, h.Compression...)

	// GREASE values are drawn fresh per connection, so normalise them to a
	// single sentinel; their POSITIONS are what Shuffle preserves, not values.
	ext := make([]uint32, 0, len(h.Extensions))
	for _, e := range h.Extensions {
		t := e.Type
		if IsGREASE(t) {
			t = 0x0a0a
		}
		ext = append(ext, uint32(t)<<16|uint32(len(e.Data)))
	}
	sort.Slice(ext, func(i, j int) bool { return ext[i] < ext[j] })
	for _, v := range ext {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// Coherent reports whether every hello in a pool came from the same browser
// build.
//
// A pool is camouflage only if it is internally consistent. Emitting Chrome
// 152's extension set on one connection and Chrome 141's on the next makes this
// client the only host on the network that changes browser build between TCP
// connections -- which no amount of per-hello fidelity repairs.
//
// The ECH GREASE bucket is the one field allowed to vary, because Chrome varies
// it per connection: the extension's length was measured at 186/218/250/282
// bytes across a same-SNI sweep. Fingerprint therefore compares ECH by
// presence, not by length.
func Coherent(hellos [][]byte) error {
	if len(hellos) == 0 {
		return errors.New("twiddle: pool is empty")
	}
	groups := map[string][]int{}
	for i, rec := range hellos {
		h, err := ParseClientHello(rec)
		if err != nil {
			return fmt.Errorf("twiddle: pool entry %d: %w", i, err)
		}
		fp := h.fingerprintIgnoringECHLength()
		groups[fp] = append(groups[fp], i)
	}
	if len(groups) == 1 {
		return nil
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s%v", k, groups[k]))
	}
	return fmt.Errorf("twiddle: pool mixes %d browser builds: %s",
		len(groups), strings.Join(parts, " "))
}

// fingerprintIgnoringECHLength is Fingerprint with the ECH GREASE length
// normalised away, since Chrome redraws it per connection.
func (h *ClientHello) fingerprintIgnoringECHLength() string {
	c := *h
	c.Extensions = make([]Extension, len(h.Extensions))
	copy(c.Extensions, h.Extensions)
	for i := range c.Extensions {
		if c.Extensions[i].Type == ExtECH {
			c.Extensions[i].Data = nil
		}
	}
	return c.Fingerprint()
}
