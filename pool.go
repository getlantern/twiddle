package twiddle

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"
)

//go:embed pool/chrome.hex
var embeddedPool string

// DefaultPool returns ClientHello records harvested from real Chrome, one per
// connection.
//
// A built-in pool means the transport works without provisioning, but it is a
// FALLBACK, not the plan. Every pooled hello is a snapshot of one Chrome
// version, so as Chrome moves the pool turns from camouflage into a positive
// signal -- the uTLS preset-staleness problem relocated rather than solved. The
// pool is meant to be refreshed as config and ramped like any other change; see
// the shipping plan in getlantern/discovery-engine.
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
func CredentialFromWire(ticket []byte, psk []byte) (*Credential, error) {
	if len(psk) != 32 {
		return nil, fmt.Errorf("twiddle: psk is %d bytes, want 32", len(psk))
	}
	c := &Credential{Ticket: append([]byte(nil), ticket...)}
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
