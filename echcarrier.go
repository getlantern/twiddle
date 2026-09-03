package twiddle

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// The full-handshake carrier.
//
// Every opening this package emits is a RESUMPTION hello, because the ticket
// travels in pre_shared_key and there is no other authentication path. Real
// browsing is almost never resumption -- measured at 4.1% over 636 connections
// and 2.7% over 485 (harvest/testdata/resumption-ratio-*.log) -- so a censor
// filtering on the presence of pre_shared_key shrinks its candidate set about
// 25-fold for free. Worse, a resumption hello to an address the client was
// never seen completing a full handshake with is structurally impossible in
// real TLS. See docs/full-handshake-carrier.md.
//
// The fix is not to authenticate without a credential: provisioned clients
// always hold one, which is precisely why every hello is a resumption hello.
// It is to carry the ticket somewhere other than pre_shared_key. Here:
//
//	ECH payload  <- the ticket, padded to the drawn length with random bytes
//	random       <- HMAC over the whole hello, keyed from the psk
//	key_share    <- a real ephemeral, exactly as on the resumption path
//
// GREASE ECH's payload is the one field in a Chrome hello where 144 to 240
// uniform bytes are precisely what belongs. Chrome fills it with random bytes
// and redraws both the contents and the length every connection
// (echGREASELengths, measured in harvest/testdata/arrival-chrome152.log). A
// ticket is AEAD ciphertext, so it is the same object, and rerandECHGrease
// already rewrites that field on every emission.
//
// Ticket length is therefore FREE on this path, which it is not on the
// resumption path: there the ticket sets the emitted hello size and must match
// the identity being impersonated (see DefaultTicketLen). Inside the ECH
// payload only the PAYLOAD length is observable, and that is drawn from
// Chrome's own buckets. FullTicketLen is fixed at the smallest bucket so every
// bucket stays reachable and the length distribution is unchanged.
//
// Because the ticket survives, TicketKey.Open still yields clientID and issued,
// so ReplayCache applies to this path unchanged.
//
// One consequence to keep in view. docs/ech.md keeps a non-ECH hello pool as a
// deliberate escape hatch: the pool is data, so if China ever blocks 0xfe0d we
// can stop emitting ECH without shipping a build. This carrier couples
// authentication to that hedge. The coupling is survivable rather than fatal --
// a pool without a large enough ECH payload simply cannot offer this path and
// falls back to resumption, which is where we already are -- but it is real,
// and CanEmitFullHandshake is where it is enforced.

// FullTicketLen is the ticket length for the full-handshake carrier.
//
// It is the smallest value in echGREASELengths, so a ticket fits EVERY bucket
// Chrome draws from and the emitted payload-length distribution stays exactly
// Chrome's. A larger ticket would silently delete buckets from that
// distribution -- at 176 the 144 bucket becomes unreachable, and a
// microsoft-sized 256 fits none of them at all.
const FullTicketLen = 144

// fullMACKey derives the key for the random-field MAC. It is domain-separated
// from binderKey so a value lifted from one path cannot be replayed into the
// other, even though both are keyed from the same psk.
func fullMACKey(psk []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte("twiddle/full-mac/v1"))
	return m.Sum(nil)
}

// echPayload returns the outer ECH extension's payload as a slice ALIASING the
// extension data, so writes to it land in the hello.
//
// The enc length is read rather than assumed. Chrome's is 32 bytes today, which
// is where the measured 42-byte header comes from, but a hello whose enc is a
// different size is still well formed and must not be silently misparsed.
func echPayload(e *Extension) ([]byte, error) {
	d := e.Data
	if len(d) < 1 {
		return nil, errMalformed
	}
	if d[0] != 0x00 {
		return nil, errors.New("twiddle: ECH extension is not the outer form")
	}
	p := 1 + 2 + 2 + 1 // config_type, kdf, aead, config_id
	if len(d) < p+2 {
		return nil, errMalformed
	}
	p += 2 + int(binary.BigEndian.Uint16(d[p:p+2])) // enc
	if len(d) < p+2 {
		return nil, errMalformed
	}
	n := int(binary.BigEndian.Uint16(d[p : p+2]))
	p += 2
	if len(d) < p+n {
		return nil, errMalformed
	}
	return d[p : p+n], nil
}

// ECHPayloadLen reports the outer ECH payload size, or an error if the hello
// carries no usable one. It is what decides whether a pool can offer the
// full-handshake path at all.
func (h *ClientHello) ECHPayloadLen() (int, error) {
	e := h.Find(ExtECH)
	if e == nil {
		return 0, errors.New("twiddle: hello has no ECH extension")
	}
	pay, err := echPayload(e)
	if err != nil {
		return 0, err
	}
	return len(pay), nil
}

// SetECHTicketAuth installs a full-handshake authenticator: the ticket goes in
// the ECH payload, and the MAC over the finished hello goes in random.
//
// Call it last, for the same reason SetTicketAuth is called last -- the MAC
// covers the final byte layout, so anything that rewrites the hello afterwards
// invalidates it. Note that Rerandomize overwrites BOTH fields this uses, the
// random directly and the ECH payload through rerandECHGrease, so this must
// follow it and not merely follow SetKeyShare.
//
// Unlike the binder, which mirrors RFC 8446's Truncate() and therefore covers
// only a prefix, this MAC covers the whole hello. There is no truncation rule
// to honour here because the field is not a TLS binder, so the stronger
// construction is also the simpler one: SNI, key_share and the ECH padding are
// all bound.
func (h *ClientHello) SetECHTicketAuth(ticket []byte, psk []byte) error {
	if len(ticket) != FullTicketLen {
		return fmt.Errorf("twiddle: full-handshake ticket is %d bytes, want %d", len(ticket), FullTicketLen)
	}
	if h.Find(ExtPreSharedKey) != nil {
		return errors.New("twiddle: full-handshake opening still carries pre_shared_key")
	}
	e := h.Find(ExtECH)
	if e == nil {
		return errors.New("twiddle: hello has no ECH extension to carry the ticket")
	}
	pay, err := echPayload(e)
	if err != nil {
		return err
	}
	if len(pay) < FullTicketLen {
		return fmt.Errorf("twiddle: ECH payload is %d bytes, too small for a %d-byte ticket", len(pay), FullTicketLen)
	}
	copy(pay, ticket)
	// The remainder is padding to whatever length was drawn. rerandECHGrease
	// has already filled the whole payload with fresh random bytes, but fill it
	// again rather than depend on having been called after it: a caller that
	// skipped Rerandomize would otherwise emit a harvested browser's payload
	// tail verbatim on every connection.
	if _, err := rand.Read(pay[FullTicketLen:]); err != nil {
		return err
	}

	h.Random = [32]byte{}
	m := hmac.New(sha256.New, fullMACKey(psk))
	m.Write(h.Marshal())
	copy(h.Random[:], m.Sum(nil))
	return nil
}

// VerifyECHTicketAuth authenticates a full-handshake opening. maxAge bounds
// ticket lifetime; pass 0 to skip the check.
//
// The AuthResult is the same shape the resumption path returns, because the
// ticket is the same object -- which is what lets ReplayCache and
// DeriveSession stay untouched by this path.
func VerifyECHTicketAuth(h *ClientHello, k *TicketKey, maxAge time.Duration) (*AuthResult, error) {
	return verifyECHAt(h, k, maxAge, time.Now())
}

func verifyECHAt(h *ClientHello, k *TicketKey, maxAge time.Duration, now time.Time) (*AuthResult, error) {
	if h.Find(ExtPreSharedKey) != nil {
		return nil, errors.New("twiddle: hello carries pre_shared_key; it belongs to the resumption path")
	}
	e := h.Find(ExtECH)
	if e == nil {
		return nil, errors.New("twiddle: hello has no ECH extension")
	}
	pay, err := echPayload(e)
	if err != nil {
		return nil, err
	}
	if len(pay) < FullTicketLen {
		return nil, fmt.Errorf("twiddle: ECH payload is %d bytes, too small to carry a ticket", len(pay))
	}
	clientID, psk, issued, err := k.Open(pay[:FullTicketLen])
	if err != nil {
		return nil, err
	}
	if maxAge > 0 && now.Sub(issued) > maxAge {
		return nil, fmt.Errorf("twiddle: ticket is %v old, limit %v", now.Sub(issued).Truncate(time.Second), maxAge)
	}

	// Recompute over the hello with random cleared, which is the layout the
	// MAC was taken over. Extensions are shared with h rather than copied
	// because nothing here mutates them; only Random differs, and it is an
	// array, so the struct copy already separates it.
	mac := h.Random
	probe := *h
	probe.Random = [32]byte{}
	m := hmac.New(sha256.New, fullMACKey(psk[:]))
	m.Write(probe.Marshal())
	if !hmac.Equal(m.Sum(nil), mac[:]) {
		return nil, errors.New("twiddle: full-handshake MAC does not verify")
	}

	eph, err := h.KeyShare()
	if err != nil {
		return nil, err
	}
	return &AuthResult{ClientID: clientID, PSK: psk, Issued: issued, ClientEphemeral: eph}, nil
}
