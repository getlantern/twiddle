package twiddle

import (
	"crypto/ecdh"
	"crypto/mlkem"
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
	if err := h.rerandGREASE(); err != nil {
		return err
	}
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

// rerandKeyShare replaces each offered public key with a fresh, VALID one.
//
// An earlier version filled these with random bytes, reasoning that under the
// theater model no real key agreement runs over them. That was wrong, and
// measurably so: real servers rejected the resulting hello with
// illegal_parameter or decode_error, because random bytes are not a valid
// ML-KEM-768 encapsulation key.
//
// The consequence is not a broken tool but a live distinguisher. A censor can
// capture one of our hellos and replay it to the SNI we claim -- a genuine
// Chrome hello draws a ServerHello, ours would draw an alert. Every key share
// we emit must be something a real server accepts.
func rerandKeyShare(e *Extension) error {
	d := e.Data
	if len(d) < 2 {
		return errMalformed
	}
	p := 2
	for p+4 <= len(d) {
		group := binary.BigEndian.Uint16(d[p : p+2])
		n := int(binary.BigEndian.Uint16(d[p+2 : p+4]))
		if p+4+n > len(d) {
			return errMalformed
		}
		if err := freshKeyShare(group, d[p+4:p+4+n]); err != nil {
			return err
		}
		p += 4 + n
	}
	return nil
}

// freshKeyShare fills one KeyShareEntry in place with a valid public value for
// its group. Unknown groups -- GREASE placeholders carry a single byte -- keep
// random contents, which is what Chrome sends for them.
func freshKeyShare(group uint16, out []byte) error {
	switch {
	case group == GroupX25519 && len(out) == 32:
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		copy(out, k.PublicKey().Bytes())
		return nil

	case group == GroupX25519MLKEM768 && len(out) == mlkem768EncapKeyLen+32:
		// X25519MLKEM768 concatenates the ML-KEM encapsulation key with the
		// X25519 public key. Both halves must be genuine or the server rejects.
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return err
		}
		copy(out[:mlkem768EncapKeyLen], dk.EncapsulationKey().Bytes())
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		copy(out[mlkem768EncapKeyLen:], k.PublicKey().Bytes())
		return nil

	default:
		// A GREASE placeholder. Chrome sends exactly one zero byte here --
		// measured 0x00 on 15 of 15 key_share GREASE entries across the pool's
		// Chrome and Chrome 152. An earlier version filled this with random
		// bytes on the theory that GREASE contents are arbitrary; they are not
		// arbitrary in practice, and randomising a byte the browser always
		// leaves zero is wrong 255 times in 256, deterministically, on every
		// connection we open.
		zero(out)
		return nil
	}
}

// greaseValues are the 16 GREASE codepoints of RFC 8701.
const greaseCount = 16

// greaseValue draws one uniformly. The codepoints are 0x0a0a, 0x1a1a, ...
// 0xfafa, i.e. 0x0a0a + n*0x1010.
func greaseValue() (uint16, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(greaseCount))
	if err != nil {
		return 0, err
	}
	return 0x0a0a + uint16(n.Int64())*0x1010, nil
}

// rerandGREASE redraws every GREASE codepoint in the hello.
//
// Nothing else re-randomises these, which made them the one field a pooled
// hello uniquely contributed: a pool of eight entries emitted eight fixed
// GREASE draws forever, where Chrome redraws per connection from all sixteen
// values. Across many connections that is a distinguisher, and a cheap one --
// no reassembly, no statistics, just the observation that this host's draws
// come from a set of eight and repeat.
//
// Six slots, measured across the embedded pool and Chrome 152:
//
//	cipher_suites[0]           independent draw
//	first extension type       independent draw
//	last extension type        independent, and MUST differ from the first
//	supported_groups           independent draw, but see below
//	key_share group            the SAME value as supported_groups
//	supported_versions[0]      independent draw
//	signature_algorithms       independent draw (Chrome 152; absent earlier)
//
// The two coupled ones are coupled by the protocol, not by taste: a key_share
// entry names a group the client offered, so a GREASE key_share whose group is
// not in supported_groups is a contradiction no browser produces. The
// distinctness of the two extension draws is BoringSSL's own rule, observed on
// 15 of 15 hellos.
//
// Collisions ACROSS slots are left alone because real hellos have them --
// pool[3] drew 0xfafa for both its cipher and its trailing extension.
func (h *ClientHello) rerandGREASE() error {
	cipher, err := greaseValue()
	if err != nil {
		return err
	}
	ext1, err := greaseValue()
	if err != nil {
		return err
	}
	ext2, err := greaseValue()
	if err != nil {
		return err
	}
	for ext2 == ext1 {
		if ext2, err = greaseValue(); err != nil {
			return err
		}
	}
	group, err := greaseValue()
	if err != nil {
		return err
	}
	version, err := greaseValue()
	if err != nil {
		return err
	}
	sigAlg, err := greaseValue()
	if err != nil {
		return err
	}

	for i, c := range h.CipherSuites {
		if IsGREASE(c) {
			h.CipherSuites[i] = cipher
		}
	}

	// First and last GREASE extension types. Rerandomize runs before Shuffle,
	// so these are still where the browser put them, and Shuffle then pins them
	// in place.
	var greased []int
	for i := range h.Extensions {
		if IsGREASE(h.Extensions[i].Type) {
			greased = append(greased, i)
		}
	}
	for n, i := range greased {
		switch {
		case n == 0:
			h.Extensions[i].Type = ext1
		case n == len(greased)-1:
			h.Extensions[i].Type = ext2
		default:
			// No measured hello has an interior GREASE extension; if one turns
			// up, give it its own draw rather than aliasing an end.
			v, err := greaseValue()
			if err != nil {
				return err
			}
			h.Extensions[i].Type = v
		}
	}

	if e := h.Find(ExtSupportedGroups); e != nil {
		replaceGREASEInU16List(e.Data, 2, group)
	}
	if e := h.Find(ExtKeyShare); e != nil {
		replaceGREASEKeyShareGroup(e.Data, group)
	}
	if e := h.Find(ExtSupportedVersions); e != nil {
		replaceGREASEInU16List(e.Data, 1, version)
	}
	if e := h.Find(ExtSignatureAlgorithms); e != nil {
		replaceGREASEInU16List(e.Data, 2, sigAlg)
	}
	return nil
}

// replaceGREASEInU16List rewrites every GREASE codepoint in a length-prefixed
// list of uint16s, in place and without changing any length. hdr is the size of
// the list's own length prefix: 2 bytes for supported_groups and
// signature_algorithms, 1 for supported_versions.
func replaceGREASEInU16List(d []byte, hdr int, v uint16) {
	if len(d) < hdr {
		return
	}
	var n int
	switch hdr {
	case 1:
		n = int(d[0])
	case 2:
		n = int(binary.BigEndian.Uint16(d[0:2]))
	default:
		return
	}
	end := hdr + n
	if end > len(d) {
		end = len(d)
	}
	for p := hdr; p+2 <= end; p += 2 {
		if IsGREASE(binary.BigEndian.Uint16(d[p : p+2])) {
			binary.BigEndian.PutUint16(d[p:p+2], v)
		}
	}
}

// replaceGREASEKeyShareGroup rewrites the group of every GREASE KeyShareEntry,
// leaving each entry's length and contents untouched.
func replaceGREASEKeyShareGroup(d []byte, v uint16) {
	if len(d) < 2 {
		return
	}
	for p := 2; p+4 <= len(d); {
		n := int(binary.BigEndian.Uint16(d[p+2 : p+4]))
		if IsGREASE(binary.BigEndian.Uint16(d[p : p+2])) {
			binary.BigEndian.PutUint16(d[p:p+2], v)
		}
		if p+4+n > len(d) {
			return
		}
		p += 4 + n
	}
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
	// ServerHello selects: 32 for SHA-256, 48 for SHA-384. Ignored when
	// FullHandshake is set, which has no binder.
	BinderLen int
	// FullHandshake emits a FULL-handshake opening: no pre_shared_key, the
	// ticket in the ECH payload and the MAC in random. See echcarrier.go and
	// docs/full-handshake-carrier.md.
	FullHandshake bool
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
//
// The full-handshake variant substitutes SetECHTicketAuth for the final step
// and is bound by the same rule for the same reason. It is bound MORE tightly,
// in fact: its MAC covers the whole hello rather than a truncation of it, and
// Rerandomize overwrites both fields it uses -- random directly, and the ECH
// payload through rerandECHGrease -- so it must follow Rerandomize and not
// merely SetKeyShare.
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
	if opt.FullHandshake {
		// Harvested hellos routinely carry pre_shared_key -- they are captured
		// from real browsing, which resumes -- so the template must be stripped
		// rather than trusted. LoadPool's Sanitize already drops them, but a
		// caller reading a raw capture does not go through it, and the resumed
		// path is equally forgiving: setPSK removes any existing extension
		// before appending its own.
		//
		// The emitted hello is then shorter than the hello it came from by
		// exactly the pre_shared_key extension, which is precisely the
		// difference between a real Chrome resumption hello and a real Chrome
		// full one.
		h.dropExtension(ExtPreSharedKey)
		if len(opt.Credential.FullTicket) != FullTicketLen {
			return nil, nil, fmt.Errorf("twiddle: credential carries a %d-byte full ticket, want %d; it cannot open a full handshake",
				len(opt.Credential.FullTicket), FullTicketLen)
		}
		if err := h.SetECHTicketAuth(opt.Credential.FullTicket, opt.Credential.PSK[:]); err != nil {
			return nil, nil, err
		}
		return h.Marshal(), eph, nil
	}
	if err := h.SetTicketAuth(opt.Credential, opt.BinderLen); err != nil {
		return nil, nil, err
	}
	return h.Marshal(), eph, nil
}
