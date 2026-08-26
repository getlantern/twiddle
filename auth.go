package twiddle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"crypto/sha512"
	"time"
)

// Authentication mirrors TLS 1.3 psk_dhe_ke, using the fields TLS already
// provides rather than inventing carriers:
//
//	key_share[X25519]  <- a real ephemeral public key (forward secrecy)
//	ticket (identity)  <- AEAD(k_server, client_id ‖ psk ‖ issued_at ‖ padding)
//	binder             <- HMAC over the truncated hello, keyed from the psk
//
// The ticket is uniform BY CONSTRUCTION because it is AEAD ciphertext, which is
// exactly what a real session ticket is. That sidesteps the problem an ECDH
// value in this position would have: only about half of all field elements are
// valid Curve25519 u-coordinates, so a raw public key here is separable from
// random bytes by one Legendre-symbol test. See docs/uniform-ephemeral.md.
//
// The ephemeral moves to key_share, where a curve point is precisely what
// belongs and carries no anomaly at all. Every captured Chrome hello offers
// group 0x001d with a 32-byte key, so there is always a slot for it.
//
// Forward secrecy therefore comes from the key_share, not the psk -- the same
// division of labour TLS 1.3 uses, and the reason psk_dhe_ke exists.

const (
	// TicketOverhead is nonce + GCM tag + the fixed plaintext fields.
	ticketNonceLen = 12
	ticketTagLen   = 16
	ticketFixed    = 8 + 32 + 8 // client_id ‖ psk ‖ issued_at
	MinTicketLen   = ticketNonceLen + ticketTagLen + ticketFixed

	// DefaultTicketLen matches the middle of the range measured from real
	// servers (32, 105, 176, 230, 256 bytes). It must be stable per identity: a
	// server's ticket format does not vary connection to connection.
	DefaultTicketLen = 176

	GroupX25519 uint16 = 0x001d
)

// TicketKey is a server's long-term ticket-encryption key. It never leaves the
// egress; clients hold only issued tickets.
type TicketKey [32]byte

// Credential is what a client presents: an opaque ticket plus the psk it is
// paired with. The first arrives by provisioning; each connection's reply
// carries the next, exactly as NewSessionTicket does.
type Credential struct {
	Ticket []byte
	PSK    [32]byte
}

func NewTicketKey() (*TicketKey, error) {
	k := new(TicketKey)
	if _, err := rand.Read(k[:]); err != nil {
		return nil, err
	}
	return k, nil
}

func (k *TicketKey) aead() (cipher.AEAD, error) {
	b, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Issue mints a credential. ticketLen is the total on-wire ticket size; the
// plaintext is padded to fill it so every ticket this server issues is the same
// length, as a real server's would be.
func (k *TicketKey) Issue(clientID uint64, ticketLen int) (*Credential, error) {
	return k.issueAt(clientID, ticketLen, time.Now())
}

func (k *TicketKey) issueAt(clientID uint64, ticketLen int, now time.Time) (*Credential, error) {
	if ticketLen < MinTicketLen {
		return nil, fmt.Errorf("twiddle: ticket length %d below minimum %d", ticketLen, MinTicketLen)
	}
	aead, err := k.aead()
	if err != nil {
		return nil, err
	}
	cred := &Credential{}
	if _, err := rand.Read(cred.PSK[:]); err != nil {
		return nil, err
	}

	plain := make([]byte, ticketLen-ticketNonceLen-ticketTagLen)
	binary.BigEndian.PutUint64(plain[0:8], clientID)
	copy(plain[8:40], cred.PSK[:])
	binary.BigEndian.PutUint64(plain[40:48], uint64(now.Unix()))
	if _, err := rand.Read(plain[ticketFixed:]); err != nil {
		return nil, err
	}

	nonce := make([]byte, ticketNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	cred.Ticket = aead.Seal(nonce, nonce, plain, nil)
	return cred, nil
}

// Open recovers a ticket's contents. Only the holder of the ticket key can do
// this, which is what keeps the authenticator verifiable by the server alone.
func (k *TicketKey) Open(ticket []byte) (clientID uint64, psk [32]byte, issued time.Time, err error) {
	if len(ticket) < MinTicketLen {
		return 0, psk, issued, errors.New("twiddle: ticket too short")
	}
	aead, err := k.aead()
	if err != nil {
		return 0, psk, issued, err
	}
	plain, err := aead.Open(nil, ticket[:ticketNonceLen], ticket[ticketNonceLen:], nil)
	if err != nil {
		return 0, psk, issued, errors.New("twiddle: ticket does not decrypt")
	}
	if len(plain) < ticketFixed {
		return 0, psk, issued, errMalformed
	}
	clientID = binary.BigEndian.Uint64(plain[0:8])
	copy(psk[:], plain[8:40])
	issued = time.Unix(int64(binary.BigEndian.Uint64(plain[40:48])), 0)
	return clientID, psk, issued, nil
}

func binderKey(psk []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte("twiddle/binder/v1"))
	return m.Sum(nil)
}

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

// SetKeyShare replaces the X25519 entry's public key with a real ephemeral,
// leaving every other offered group untouched. Returns the private key.
func (h *ClientHello) SetKeyShare() (*ecdh.PrivateKey, error) {
	e := h.Find(ExtKeyShare)
	if e == nil {
		return nil, errors.New("twiddle: hello has no key_share")
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey().Bytes()
	d := e.Data
	p := 2
	for p+4 <= len(d) {
		g := binary.BigEndian.Uint16(d[p : p+2])
		n := int(binary.BigEndian.Uint16(d[p+2 : p+4]))
		if p+4+n > len(d) {
			return nil, errMalformed
		}
		if g == GroupX25519 && n == len(pub) {
			copy(d[p+4:p+4+n], pub)
			return priv, nil
		}
		p += 4 + n
	}
	return nil, errors.New("twiddle: hello offers no X25519 key_share")
}

// KeyShare returns the client's offered X25519 public key.
func (h *ClientHello) KeyShare() (*ecdh.PublicKey, error) {
	e := h.Find(ExtKeyShare)
	if e == nil {
		return nil, errors.New("twiddle: hello has no key_share")
	}
	d := e.Data
	p := 2
	for p+4 <= len(d) {
		g := binary.BigEndian.Uint16(d[p : p+2])
		n := int(binary.BigEndian.Uint16(d[p+2 : p+4]))
		if p+4+n > len(d) {
			return nil, errMalformed
		}
		if g == GroupX25519 {
			return ecdh.X25519().NewPublicKey(d[p+4 : p+4+n])
		}
		p += 4 + n
	}
	return nil, errors.New("twiddle: hello offers no X25519 key_share")
}

// SetTicketAuth installs the credential and computes the binder over the final
// byte layout. Call it last -- see Twiddle.
func (h *ClientHello) SetTicketAuth(cred *Credential, binderLen int) error {
	newHash, err := binderHash(binderLen)
	if err != nil {
		return err
	}
	var age [4]byte
	if _, err := rand.Read(age[:]); err != nil {
		return err
	}
	setPSK(h, cred.Ticket, age, make([]byte, binderLen))
	m := hmac.New(newHash, binderKey(cred.PSK[:]))
	m.Write(truncateForBinder(h.Marshal(), binderLen))
	setPSK(h, cred.Ticket, age, m.Sum(nil))
	return nil
}

// AuthResult is what a verified opening yields.
type AuthResult struct {
	ClientID        uint64
	PSK             [32]byte
	Issued          time.Time
	ClientEphemeral *ecdh.PublicKey
}

// VerifyTicketAuth authenticates a hello. maxAge bounds ticket lifetime; pass 0
// to skip the check.
func VerifyTicketAuth(h *ClientHello, k *TicketKey, maxAge time.Duration) (*AuthResult, error) {
	return verifyAt(h, k, maxAge, time.Now())
}

func verifyAt(h *ClientHello, k *TicketKey, maxAge time.Duration, now time.Time) (*AuthResult, error) {
	e := h.Find(ExtPreSharedKey)
	if e == nil {
		return nil, errors.New("twiddle: hello carries no pre_shared_key")
	}
	ticket, age, binder, err := parsePSK(e.Data)
	if err != nil {
		return nil, err
	}
	clientID, psk, issued, err := k.Open(ticket)
	if err != nil {
		return nil, err
	}
	if maxAge > 0 && now.Sub(issued) > maxAge {
		return nil, fmt.Errorf("twiddle: ticket is %v old, limit %v", now.Sub(issued).Truncate(time.Second), maxAge)
	}
	newHash, err := binderHash(len(binder))
	if err != nil {
		return nil, err
	}

	probe := *h
	probe.Extensions = append([]Extension(nil), h.Extensions...)
	setPSK(&probe, ticket, age, make([]byte, len(binder)))
	m := hmac.New(newHash, binderKey(psk[:]))
	m.Write(truncateForBinder(probe.Marshal(), len(binder)))
	if !hmac.Equal(m.Sum(nil), binder) {
		return nil, errors.New("twiddle: binder does not verify")
	}

	eph, err := h.KeyShare()
	if err != nil {
		return nil, err
	}
	return &AuthResult{ClientID: clientID, PSK: psk, Issued: issued, ClientEphemeral: eph}, nil
}

// truncateForBinder drops the binders list, mirroring RFC 8446's Truncate().
func truncateForBinder(rec []byte, binderLen int) []byte {
	cut := 2 + 1 + binderLen
	if len(rec) < cut {
		return rec
	}
	return rec[:len(rec)-cut]
}

// setPSK writes pre_shared_key and moves it to the end. RFC 8446 §4.2.11
// requires it last, and that is what makes the binder truncation well defined.
// obfuscated_ticket_age is caller-supplied because this runs twice per
// authentication and any field differing between the two calls would break
// verification.
func setPSK(h *ClientHello, ticket []byte, age [4]byte, binder []byte) {
	d := make([]byte, 0, 11+len(ticket)+len(binder))
	d = appendU16(d, uint16(len(ticket)+6))
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
