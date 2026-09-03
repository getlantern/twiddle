package twiddle

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// DefaultHarvestMax is how many hellos a device pool keeps.
//
// It is generous because same-build hellos are not interchangeable. The
// emitter regenerates the random, session id, key shares, ECH bucket, GREASE
// draws and extension order, but not every per-connection field a browser
// varies: Chrome 152's 0xca34 body differs between connections at a constant
// length, and nothing here reproduces that. Holding more entries samples more
// of what we cannot generate. Each costs ~2 KB.
const DefaultHarvestMax = 32

// Harvester accumulates ClientHellos tapped from this device's own outbound TLS
// traffic and maintains them as a device pool file for LoadPool to read back.
//
// It is the write half of the highest-preference source, and the only one whose
// contents cannot go stale: what it collects is what the browser installed on
// this device is emitting right now.
//
// Offer is safe to call from the connection path. It parses and screens in
// memory and only touches the disk when it actually accepts something, and
// accepts fall off quickly: a device settles onto one browser build, and once
// the pool is full every further offer is either a duplicate contribution or
// displaces one entry.
type Harvester struct {
	path string
	max  int

	mu          sync.Mutex
	hellos      [][]byte
	keys        map[string]struct{}
	pending     [][]byte
	pendingKeys map[string]struct{}
}

// NewHarvester opens or creates the device pool at path.
//
// An unreadable or corrupt existing file is not an error: the pool is
// opportunistic by nature, and refusing to harvest because a previous file went
// bad would strand the device on the config or embedded tier forever.
func NewHarvester(path string, max int) *Harvester {
	if max <= 0 {
		max = DefaultHarvestMax
	}
	h := &Harvester{path: path, max: max, keys: map[string]struct{}{}, pendingKeys: map[string]struct{}{}}
	existing, _ := readPoolFile(path)
	for _, rec := range existing {
		if len(h.hellos) >= max {
			break
		}
		if k, ok := contributionKey(rec); ok {
			if _, dup := h.keys[k]; !dup {
				h.keys[k] = struct{}{}
				h.hellos = append(h.hellos, rec)
			}
		}
	}
	return h
}

// Offer sanitises and screens one tapped record, adding it to the pool if it is
// usable and contributes something the pool does not already hold. It reports
// whether the record was accepted.
//
// The caller must pass a COMPLETE handshake record. Chrome writes its whole
// ClientHello in a single socket write -- measured, see
// harvest/testdata/arrival-chrome152.log -- so a caller watching the first
// write of a connection has the whole thing and does not need to reassemble.
func (h *Harvester) Offer(rec []byte) (bool, error) {
	parsed, err := ParseClientHello(rec)
	if err != nil {
		return false, nil // not a ClientHello, or not one we can read
	}
	// Sanitize BEFORE anything is retained, let alone written: a tapped hello
	// names a site the user actually visited, and a resumption hello carries
	// that site's session ticket.
	if err := parsed.Sanitize(); err != nil {
		return false, nil
	}
	clean := parsed.Marshal()
	if err := Usable(clean); err != nil {
		return false, nil
	}
	key, ok := contributionKey(clean)
	if !ok {
		return false, nil
	}

	h.mu.Lock()
	if _, dup := h.keys[key]; dup {
		h.mu.Unlock()
		return false, nil
	}
	// Keep the emit pool to one browser build. A device that just auto-updated
	// Chrome will offer hellos from the new build while the file still holds
	// the old one; appending both would have this client alternating
	// fingerprints between connections.
	//
	// Rejecting the minority outright was wrong: after two old-build hellos,
	// every new-build sample was a 1-vs-2 minority, so the new build could
	// never become the majority. Count minority samples aside, and switch the
	// emit pool once they outnumber it.
	newFP := recordBuild(clean)
	curFP := ""
	if len(h.hellos) > 0 {
		curFP = recordBuild(h.hellos[0])
	}
	if len(h.hellos) == 0 || newFP == curFP {
		h.hellos = append(h.hellos, clean)
		h.keys[key] = struct{}{}
		if len(h.hellos) > h.max {
			h.hellos = h.hellos[len(h.hellos)-h.max:]
			h.keys = map[string]struct{}{}
			for _, r := range h.hellos {
				if k, ok := contributionKey(r); ok {
					h.keys[k] = struct{}{}
				}
			}
		}
		snapshot := append([][]byte(nil), h.hellos...)
		h.mu.Unlock()
		if err := writePoolFile(h.path, snapshot); err != nil {
			return true, err
		}
		return true, nil
	}

	if _, dup := h.pendingKeys[key]; dup {
		h.mu.Unlock()
		return false, nil
	}
	h.pending = append(h.pending, clean)
	h.pendingKeys[key] = struct{}{}
	if len(h.pending) <= len(h.hellos) {
		h.mu.Unlock()
		return false, nil
	}
	h.hellos = h.pending
	h.keys = h.pendingKeys
	h.pending = nil
	h.pendingKeys = map[string]struct{}{}
	if len(h.hellos) > h.max {
		h.hellos = h.hellos[len(h.hellos)-h.max:]
		h.keys = map[string]struct{}{}
		for _, r := range h.hellos {
			if k, ok := contributionKey(r); ok {
				h.keys[k] = struct{}{}
			}
		}
	}
	snapshot := append([][]byte(nil), h.hellos...)
	h.mu.Unlock()

	if err := writePoolFile(h.path, snapshot); err != nil {
		return true, err
	}
	return true, nil
}

// Len reports how many hellos the pool holds.
func (h *Harvester) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.hellos)
}

func recordBuild(rec []byte) string {
	h, err := ParseClientHello(rec)
	if err != nil {
		return ""
	}
	return h.fingerprintIgnoringECHLength()
}

// contributionKey identifies what a pool entry adds that the emitter cannot
// generate for itself.
//
// It is the entry's canonical form: the hello with every field the emission
// pipeline regenerates stripped out. Two entries with the same key are
// interchangeable, and storing the second buys nothing.
//
// This is derived from what Rerandomize and Shuffle actually do rather than
// listed by hand, because the two must not drift. When Rerandomize learns to
// regenerate another field, that field must be stripped here too -- otherwise
// the harvester hoards entries that differ only in something we overwrite.
// TestContributionKeySurvivesTheEmitter pins the relationship.
func contributionKey(rec []byte) (string, bool) {
	h, err := ParseClientHello(rec)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(h.canonicalForm())
	return hex.EncodeToString(sum[:12]), true
}

// canonicalForm renders the hello with everything the emitter regenerates
// blanked, so what remains is exactly the part a pool entry contributes.
//
// What survives is the interesting part. Notably 0xca34 does: Chrome 152 varies
// its body per connection -- two hellos from one browser, same 206-byte length,
// different contents -- and nothing here reproduces that. So two same-build
// hellos are NOT generally interchangeable, and a device pool holding several
// of them is buying real variety rather than hoarding duplicates.
func (h *ClientHello) canonicalForm() []byte {
	c := &ClientHello{
		LegacyVersion: h.LegacyVersion,
		Compression:   append([]byte(nil), h.Compression...),
		SessionID:     make([]byte, len(h.SessionID)), // regenerated; length kept
	}
	// Random is left zero: regenerated every connection.

	c.CipherSuites = make([]uint16, len(h.CipherSuites))
	for i, v := range h.CipherSuites {
		if IsGREASE(v) {
			v = greaseSentinel // redrawn by rerandGREASE
		}
		c.CipherSuites[i] = v
	}

	c.Extensions = make([]Extension, 0, len(h.Extensions))
	for _, e := range h.Extensions {
		t, d := e.Type, append([]byte(nil), e.Data...)
		if IsGREASE(t) {
			t = greaseSentinel
		}
		switch t {
		case ExtServerName:
			d = nil // rewritten to the cover domain
		case ExtECH:
			// rerandECHGrease redraws config_id, enc, payload and the bucket
			// length, but preserves the advertised HPKE kdf/aead.
			if len(d) >= 5 {
				d = d[:5]
			} else {
				d = nil
			}
		case ExtKeyShare:
			blankKeyShareValues(d)
			replaceGREASEKeyShareGroup(d, greaseSentinel)
		case ExtSupportedGroups, ExtSignatureAlgorithms:
			replaceGREASEInU16List(d, 2, greaseSentinel)
		case ExtSupportedVersions:
			replaceGREASEInU16List(d, 1, greaseSentinel)
		}
		c.Extensions = append(c.Extensions, Extension{t, d})
	}
	// Order is reproduced by Shuffle, so it cannot be part of the key.
	sort.SliceStable(c.Extensions, func(i, j int) bool {
		if c.Extensions[i].Type != c.Extensions[j].Type {
			return c.Extensions[i].Type < c.Extensions[j].Type
		}
		return bytes.Compare(c.Extensions[i].Data, c.Extensions[j].Data) < 0
	})
	return c.Marshal()
}

// greaseSentinel stands in for any GREASE codepoint in a canonical form.
const greaseSentinel uint16 = 0x0a0a

// blankKeyShareValues zeroes each KeyShareEntry's key_exchange bytes while
// leaving the groups and lengths, which are the part rerandKeyShare keeps.
func blankKeyShareValues(d []byte) {
	if len(d) < 2 {
		return
	}
	for p := 2; p+4 <= len(d); {
		n := int(binary.BigEndian.Uint16(d[p+2 : p+4]))
		if p+4+n > len(d) {
			return
		}
		zero(d[p+4 : p+4+n])
		p += 4 + n
	}
}

// writePoolFile replaces the pool file atomically. A torn file would be read
// back by LoadPool at the next start, and a half-written last line is exactly
// the corruption readPoolFile has to tolerate -- better not to create it.
func writePoolFile(path string, hellos [][]byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("twiddle: pool dir %s: %w", dir, err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(FormatPool(hellos)), 0o600); err != nil {
		return fmt.Errorf("twiddle: write pool %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("twiddle: replace pool %s: %w", path, err)
	}
	return nil
}
