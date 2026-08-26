package twiddle

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Shuffle permutes the interior extensions, reproducing what Chrome does on
// every connection.
//
// Measured across 78 captured hellos: Chrome pins a GREASE extension first and
// another last, places pre_shared_key after the trailing GREASE when present,
// and permutes everything between on every single connection -- 8 connections
// produced 8 distinct orderings, including between two otherwise identical full
// hellos. Emitting a harvested hello verbatim would therefore hold a FIXED order
// across our connections, which is something Chrome never does. Shuffling is
// required for fidelity, not an optional obfuscation.
func (h *ClientHello) Shuffle() error {
	n := len(h.Extensions)
	if n < 3 {
		return errors.New("twiddle: too few extensions to shuffle")
	}
	if !IsGREASE(h.Extensions[0].Type) {
		return fmt.Errorf("twiddle: first extension %#04x is not GREASE", h.Extensions[0].Type)
	}

	head := h.Extensions[0]
	var tail []Extension
	body := h.Extensions[1:]

	if last := body[len(body)-1]; last.Type == ExtPreSharedKey {
		if len(body) < 2 || !IsGREASE(body[len(body)-2].Type) {
			return errors.New("twiddle: pre_shared_key not preceded by GREASE")
		}
		tail = []Extension{body[len(body)-2], last}
		body = body[:len(body)-2]
	} else {
		if !IsGREASE(last.Type) {
			return fmt.Errorf("twiddle: last extension %#04x is neither GREASE nor pre_shared_key", last.Type)
		}
		tail = []Extension{last}
		body = body[:len(body)-1]
	}

	interior := make([]Extension, len(body))
	copy(interior, body)
	for i := len(interior) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		k := j.Int64()
		interior[i], interior[k] = interior[k], interior[i]
	}

	out := make([]Extension, 0, n)
	out = append(out, head)
	out = append(out, interior...)
	out = append(out, tail...)
	h.Extensions = out
	return nil
}

// echGREASELengths are the ECH payload sizes observed from real Chrome. The
// extension's total length was measured at 186/218/250/282 bytes, i.e. 32-byte
// buckets, and re-randomised per connection independently of SNI length -- a
// same-SNI sweep produced 218, 218, 250, 186, 250, 218, 218, 186.
var echGREASELengths = []int{144, 176, 208, 240}

// Rerandomize refreshes every field a real browser varies per connection.
// uTLS holds ECH GREASE constant where Chrome varies it, so a harvested hello
// replayed without this would repeat one connection's random values.
func (h *ClientHello) Rerandomize() error {
	if _, err := rand.Read(h.Random[:]); err != nil {
		return err
	}
	if len(h.SessionID) > 0 {
		if _, err := rand.Read(h.SessionID); err != nil {
			return err
		}
	}
	if e := h.Find(ExtKeyShare); e != nil {
		if err := rerandKeyShare(e); err != nil {
			return err
		}
	}
	if e := h.Find(ExtECH); e != nil {
		if err := rerandECHGrease(e); err != nil {
			return err
		}
	}
	return nil
}

// rerandKeyShare replaces each offered public key with fresh random bytes,
// preserving the group ids and key lengths. Under the theater model no real
// key agreement runs over these, so any bytes of the right length will do --
// and every group in use encodes as uniform-looking bytes.
func rerandKeyShare(e *Extension) error {
	d := e.Data
	if len(d) < 2 {
		return errMalformed
	}
	p := 2
	for p+4 <= len(d) {
		n := int(binary.BigEndian.Uint16(d[p+2 : p+4]))
		if p+4+n > len(d) {
			return errMalformed
		}
		if _, err := rand.Read(d[p+4 : p+4+n]); err != nil {
			return err
		}
		p += 4 + n
	}
	return nil
}

// rerandECHGrease rebuilds a GREASE ECH extension: fresh config_id, fresh 32-byte
// enc, and a fresh random payload whose length is drawn from the observed buckets.
func rerandECHGrease(e *Extension) error {
	if len(e.Data) < 1 || e.Data[0] != 0x00 {
		return nil // inner ECH, or a shape we do not model -- leave it alone
	}
	pick, err := rand.Int(rand.Reader, big.NewInt(int64(len(echGREASELengths))))
	if err != nil {
		return err
	}
	payloadLen := echGREASELengths[pick.Int64()]

	enc := make([]byte, 32)
	if _, err := rand.Read(enc); err != nil {
		return err
	}
	payload := make([]byte, payloadLen)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	cfg := make([]byte, 1)
	if _, err := rand.Read(cfg); err != nil {
		return err
	}

	// preserve the advertised HPKE cipher suite from the original
	var kdf, aead uint16 = 0x0001, 0x0001
	if len(e.Data) >= 5 {
		kdf = binary.BigEndian.Uint16(e.Data[1:3])
		aead = binary.BigEndian.Uint16(e.Data[3:5])
	}

	d := make([]byte, 0, 8+len(enc)+len(payload))
	d = append(d, 0x00)
	d = appendU16(d, kdf)
	d = appendU16(d, aead)
	d = append(d, cfg[0])
	d = appendU16(d, uint16(len(enc)))
	d = append(d, enc...)
	d = appendU16(d, uint16(len(payload)))
	e.Data = append(d, payload...)
	return nil
}

// Options configure a single emission of a harvested hello.
type Options struct {
	// CoverSNI replaces the harvested hello's server name.
	CoverSNI string
	// Credential is the ticket and psk this client presents.
	Credential *Credential
	// TicketLen is the pre_shared_key ticket length. Real servers were measured
	// at 32, 105, 176, 230 and 256 bytes; it should be stable per identity, since
	// a server's ticket format does not vary connection to connection.
	TicketLen int
	// BinderLen must equal the hash length of the cipher suite the synthesised
	// ServerHello selects: 32 for SHA-256, 48 for SHA-384.
	BinderLen int
}

// Twiddle rewrites a harvested ClientHello for emission and returns the wire
// bytes plus the ephemeral key the egress will agree on.
//
// The step order is load-bearing and is why this exists rather than callers
// composing the pieces themselves:
//
//	SetSNI -> Rerandomize -> Shuffle -> SetKeyShare -> SetTicketAuth
//
// The binder is a MAC over the hello truncated at the binders, so it must be
// computed over the FINAL byte layout. Shuffling after authenticating changes
// the transcript and silently invalidates the binder. Real TLS has the same
// constraint: a client picks its extension order first and computes the binder
// last.
func Twiddle(harvested []byte, opt Options) (wire []byte, eph *ecdh.PrivateKey, err error) {
	h, err := ParseClientHello(harvested)
	if err != nil {
		return nil, nil, err
	}
	if opt.CoverSNI != "" {
		if err := h.SetSNI(opt.CoverSNI); err != nil {
			return nil, nil, err
		}
	}
	if err := h.Rerandomize(); err != nil {
		return nil, nil, err
	}
	if err := h.Shuffle(); err != nil {
		return nil, nil, err
	}
	eph, err = h.SetKeyShare()
	if err != nil {
		return nil, nil, err
	}
	if err := h.SetTicketAuth(opt.Credential, opt.BinderLen); err != nil {
		return nil, nil, err
	}
	return h.Marshal(), eph, nil
}
