package twiddle

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// Authentication rides in the PSK extension of a resumption ClientHello.
//
// RFC 8446 §4.2.11.2 defines the binder as
//     HMAC(binder_key, Transcript-Hash(Truncate(ClientHello)))
// which is a MAC over the opening keyed by a secret shared with the server --
// exactly the side-door construction, in the field TLS already defines for it.
// So the authenticator is not injected into a foreign protocol; it populates the
// slot the protocol provides.
//
//	ticket (identity)  <- ephemeral X25519 public key, then random padding
//	binder             <- MAC over the truncated hello under ECDH(eph, server_pk)
//
// Both fields are opaque BY SPECIFICATION: a ticket is server-chosen opaque data
// and a binder is an HMAC under a key derived from it. No observer can validate
// either without the resumption secret, which makes them the only ClientHello
// fields unverifiable by construction rather than by convention.
//
// KNOWN LIMITATION -- see docs/uniform-ephemeral.md. The ephemeral is written
// into the ticket as a raw X25519 public key, and only about half of all field
// elements are valid Curve25519 u-coordinates, so one Legendre-symbol test
// distinguishes it from the uniform AEAD ciphertext a real ticket carries. The
// top-bit bias below is fixed; curve membership is not. This must be resolved
// before the transport ships.
//
// Deriving the MAC key from ECDH to the server's static key keeps the
// verifiable-only-by-the-server property: no symmetric secret is shared across
// clients, so extracting one client's state does not let a censor confirm
// anyone else's connections.

const (
	ephemeralLen = 32
	domainSep    = "twiddle/psk-auth/v1"
)

// TicketLen returns a plausible ticket length. Measured from real servers:
// 32 B (github), 105 B (Go's crypto/tls), 176 B (cloudflare), 230 B (google),
// 256 B (microsoft). A ticket must be at least the ephemeral length.
func TicketLen(n int) int {
	if n < ephemeralLen+8 {
		return 128
	}
	return n
}

// binderHash picks the hash for the binder. Its length must match the hash of
// the cipher suite the ServerHello selects -- 32 bytes for SHA-256 suites, 48
// for SHA-384. A mismatch is a free structural tell, so this is not a free
// choice at the framing layer.
func binderHash(binderLen int) (func() hash.Hash, error) {
	switch binderLen {
	case sha256.Size:
		return sha256.New, nil
	case sha512.Size384:
		return sha512.New384, nil
	default:
		return nil, fmt.Errorf("twiddle: binder length %d is neither 32 (SHA-256) nor 48 (SHA-384)", binderLen)
	}
}

// SetPSKAuth installs a fresh authenticator into the hello's pre_shared_key
// extension, creating it if absent. Returns the ephemeral private key so the
// caller can derive the same secret the server will.
func (h *ClientHello) SetPSKAuth(serverStatic *ecdh.PublicKey, ticketLen, binderLen int) (*ecdh.PrivateKey, error) {
	newHash, err := binderHash(binderLen)
	if err != nil {
		return nil, err
	}
	ticketLen = TicketLen(ticketLen)

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(serverStatic)
	if err != nil {
		return nil, err
	}

	ticket := make([]byte, ticketLen)
	copy(ticket, priv.PublicKey().Bytes())
	if _, err := rand.Read(ticket[ephemeralLen:]); err != nil {
		return nil, err
	}
	// An X25519 public key is a field element below 2^255-19, so its top bit is
	// always zero -- a one-bit bias a censor could accumulate over samples.
	// RFC 7748 §5 requires receivers to mask that bit, so randomising it is free.
	if _, err := randomizeTopBit(ticket); err != nil {
		return nil, err
	}

	var age [4]byte
	if _, err := rand.Read(age[:]); err != nil {
		return nil, err
	}
	setPSK(h, ticket, age, make([]byte, binderLen))
	binder := hmac.New(newHash, macKey(shared))
	binder.Write(truncateForBinder(h.Marshal(), binderLen))
	setPSK(h, ticket, age, binder.Sum(nil))
	return priv, nil
}

// VerifyPSKAuth recomputes the binder using the server's static private key.
// It returns the shared secret on success so the caller can derive tunnel keys.
func VerifyPSKAuth(h *ClientHello, serverStatic *ecdh.PrivateKey) ([]byte, error) {
	e := h.Find(ExtPreSharedKey)
	if e == nil {
		return nil, errors.New("twiddle: hello carries no pre_shared_key")
	}
	ticket, age, binder, err := parsePSK(e.Data)
	if err != nil {
		return nil, err
	}
	if len(ticket) < ephemeralLen {
		return nil, errors.New("twiddle: ticket too short to carry an ephemeral")
	}
	newHash, err := binderHash(len(binder))
	if err != nil {
		return nil, err
	}

	eph := make([]byte, ephemeralLen)
	copy(eph, ticket[:ephemeralLen])
	eph[ephemeralLen-1] &= 0x7f // undo the top-bit randomisation, per RFC 7748
	pub, err := ecdh.X25519().NewPublicKey(eph)
	if err != nil {
		return nil, fmt.Errorf("twiddle: bad ephemeral: %w", err)
	}
	shared, err := serverStatic.ECDH(pub)
	if err != nil {
		return nil, err
	}

	probe := *h
	probe.Extensions = append([]Extension(nil), h.Extensions...)
	setPSK(&probe, ticket, age, make([]byte, len(binder)))
	want := hmac.New(newHash, macKey(shared))
	want.Write(truncateForBinder(probe.Marshal(), len(binder)))
	if !hmac.Equal(want.Sum(nil), binder) {
		return nil, errors.New("twiddle: binder does not verify")
	}
	return shared, nil
}

func macKey(shared []byte) []byte {
	k := sha256.Sum256(append([]byte(domainSep), shared...))
	return k[:]
}

// randomizeTopBit flips the high bit of the ephemeral's final byte at random.
func randomizeTopBit(ticket []byte) (bool, error) {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return false, err
	}
	if b[0]&1 == 1 {
		ticket[ephemeralLen-1] |= 0x80
		return true, nil
	}
	return false, nil
}

// truncateForBinder drops the binders list, mirroring RFC 8446's Truncate().
func truncateForBinder(rec []byte, binderLen int) []byte {
	cut := 2 + 1 + binderLen
	if len(rec) < cut {
		return rec
	}
	return rec[:len(rec)-cut]
}

// setPSK writes the pre_shared_key extension and moves it to the end.
//
// RFC 8446 §4.2.11 requires pre_shared_key to be the last extension, and the
// binder is a MAC over the hello truncated at the binders -- so "last" is not a
// style choice, it is what makes the truncation well defined.
//
// obfuscated_ticket_age is a caller-supplied constant rather than generated
// here, because this is called twice per authentication (once with a zero
// binder to build the transcript, once with the real one) and any field that
// differed between those calls would break verification.
func setPSK(h *ClientHello, ticket []byte, age [4]byte, binder []byte) {
	d := make([]byte, 0, 11+len(ticket)+len(binder))
	d = appendU16(d, uint16(len(ticket)+6)) // identities list
	d = appendU16(d, uint16(len(ticket)))
	d = append(d, ticket...)
	d = append(d, age[:]...)
	d = appendU16(d, uint16(len(binder)+1))
	d = append(d, byte(len(binder)))
	d = append(d, binder...)

	out := h.Extensions[:0:0]
	for _, e := range h.Extensions {
		if e.Type != ExtPreSharedKey {
			out = append(out, e)
		}
	}
	h.Extensions = append(out, Extension{ExtPreSharedKey, d})
}

func parsePSK(d []byte) (ticket []byte, age [4]byte, binder []byte, err error) {
	if len(d) < 2 {
		return nil, age, nil, errMalformed
	}
	idsEnd := 2 + int(binary.BigEndian.Uint16(d[0:2]))
	if idsEnd+2 > len(d) || idsEnd < 4 {
		return nil, age, nil, errMalformed
	}
	tl := int(binary.BigEndian.Uint16(d[2:4]))
	if 4+tl+4 > len(d) {
		return nil, age, nil, errMalformed
	}
	ticket = d[4 : 4+tl]
	copy(age[:], d[4+tl:4+tl+4])
	p := idsEnd + 2
	if p >= len(d) {
		return nil, age, nil, errMalformed
	}
	bl := int(d[p])
	if p+1+bl > len(d) {
		return nil, age, nil, errMalformed
	}
	return ticket, age, d[p+1 : p+1+bl], nil
}
