package twiddle

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"
)

//go:embed pool/chrome.hex
var embeddedPool string

// DefaultPool returns the compiled-in ClientHello records, exactly as
// pool/chrome.hex holds them.
//
// Prefer LoadPool: this is its opt-in last tier, and the only one that cannot be
// refreshed without shipping a binary. Production callers should provision a
// device or config pool instead.
// Every pooled hello is a snapshot of one Chrome version, so as Chrome moves
// the pool turns from camouflage into a positive signal -- the uTLS
// preset-staleness problem relocated rather than solved.
//
// That decay is already measurable. These hellos carry BoringSSL's
// server_padding (0x12e0) and run 1725-1827 bytes; Chrome 152 has dropped
// 0x12e0, added 0xca34, and runs 1919-1983 bytes. Emitting this pool today
// reproduces no Chrome that exists.
//
// The records are also not internally consistent -- four carry 0x12e0 and four
// do not, because the capture arms mixed a fresh profile with an established
// one -- so callers wanting a single coherent build must partition them.
// LoadPool does that; this function does not, because its job is to report what
// the file contains.
//
// These are full-handshake hellos. A resumption hello is a full hello plus
// pre_shared_key, which SetTicketAuth appends, so full hellos are the right base.
func DefaultPool() [][]byte {
	p, err := ParsePool(embeddedPool)
	if err != nil {
		panic("twiddle: embedded pool is corrupt: " + err.Error())
	}
	return p
}

// ParsePool reads a pool file: one hex-encoded ClientHello record per line,
// blank lines and # comments ignored.
func ParsePool(s string) ([][]byte, error) {
	var out [][]byte
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rec, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("twiddle: pool line %d: %w", i+1, err)
		}
		if _, err := ParseClientHello(rec); err != nil {
			return nil, fmt.Errorf("twiddle: pool line %d: %w", i+1, err)
		}
		out = append(out, rec)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("twiddle: pool is empty")
	}
	return out, nil
}

// CredentialFromWire rebuilds a client credential from its provisioned form.
//
// The result is RESUMPTION-ONLY: it carries no full-handshake companion, so
// every opening it authenticates carries pre_shared_key. Provisioning that can
// supply both should call CredentialFromWireFull instead -- see
// docs/full-handshake-carrier.md for why emitting only resumption hellos is a
// distinguisher.
func CredentialFromWire(ticket []byte, psk []byte) (*Credential, error) {
	return CredentialFromWireFull(ticket, nil, psk)
}

// CredentialFromWireFull rebuilds a credential that can open either handshake
// shape. fullTicket is the FullTicketLen companion sealed over the same
// clientID, psk and issue time; nil degrades to resumption-only.
func CredentialFromWireFull(ticket, fullTicket, psk []byte) (*Credential, error) {
	if len(psk) != 32 {
		return nil, fmt.Errorf("twiddle: psk is %d bytes, want 32", len(psk))
	}
	if fullTicket != nil && len(fullTicket) != FullTicketLen {
		return nil, fmt.Errorf("twiddle: full ticket is %d bytes, want %d", len(fullTicket), FullTicketLen)
	}
	c := &Credential{Ticket: append([]byte(nil), ticket...)}
	if fullTicket != nil {
		c.FullTicket = append([]byte(nil), fullTicket...)
	}
	copy(c.PSK[:], psk)
	return c, nil
}

// TicketKeyFromWire rebuilds a server ticket key.
func TicketKeyFromWire(b []byte) (*TicketKey, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("twiddle: ticket key is %d bytes, want 32", len(b))
	}
	k := new(TicketKey)
	copy(k[:], b)
	return k, nil
}
