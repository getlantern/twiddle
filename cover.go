package twiddle

import (
	"errors"
	"fmt"
	"strings"
)

// CoverProfile is one impersonated identity. Every fidelity parameter that
// varies by server lives here so a microsoft-selected egress cannot emit a
// cloudflare binder, cipher, or flight.
//
// Numbers are from harvest/testdata: ticket lengths from cmd/resume, PSK
// extension order from cmd/shresume, resumed burst sizes from
// tls13-burst-resumption.log (Xue Wb=3). BinderLen is the Hash.length of
// CipherSuite — 32 for SHA-256, 48 for SHA-384.
type CoverProfile struct {
	Host               string
	CipherSuite        uint16
	BinderLen          int
	TicketLen          int
	PSKFirst           bool
	ServerOpeningBurst int
	ClientFlight       int
}

// ErrUnknownCover is returned when a caller names a host we have not measured,
// or one whose ticket is too short to carry the authenticator (github.com).
var ErrUnknownCover = fmt.Errorf("twiddle: unknown cover identity")

var covers = map[string]CoverProfile{
	"www.cloudflare.com": {
		Host:               "www.cloudflare.com",
		CipherSuite:        TLS_AES_128_GCM_SHA256,
		BinderLen:          32,
		TicketLen:          176,
		PSKFirst:           true,
		ServerOpeningBurst: 1291,
		ClientFlight:       149,
	},
	"www.google.com": {
		Host:               "www.google.com",
		CipherSuite:        TLS_AES_128_GCM_SHA256,
		BinderLen:          32,
		TicketLen:          230,
		PSKFirst:           true,
		ServerOpeningBurst: 1291,
		ClientFlight:       145,
	},
	"www.microsoft.com": {
		Host:               "www.microsoft.com",
		CipherSuite:        TLS_AES_256_GCM_SHA384,
		BinderLen:          48,
		TicketLen:          256,
		PSKFirst:           false,
		ServerOpeningBurst: 1333,
		ClientFlight:       164,
	},
}

// CoverFor returns the measured profile for host. Unknown names, and names we
// measured but cannot impersonate, are rejected rather than partially faked.
func CoverFor(host string) (CoverProfile, error) {
	p, ok := covers[strings.ToLower(host)]
	if !ok {
		return CoverProfile{}, fmt.Errorf("%w: %s", ErrUnknownCover, host)
	}
	return p, nil
}

// MeasuredCovers lists impersonable identities in stable order.
func MeasuredCovers() []string {
	return []string{"www.cloudflare.com", "www.google.com", "www.microsoft.com"}
}

// Valid reports whether p is exactly a measured identity. A half-filled
// profile — or one that mixes one host's ticket length with another's binder —
// is how microsoft-selected egresses previously emitted a 32-byte SHA-256
// binder.
func (p CoverProfile) Valid() error {
	known, err := CoverFor(p.Host)
	if err != nil {
		return err
	}
	if p.CipherSuite != known.CipherSuite || p.BinderLen != known.BinderLen ||
		p.TicketLen != known.TicketLen || p.PSKFirst != known.PSKFirst ||
		p.ServerOpeningBurst != known.ServerOpeningBurst || p.ClientFlight != known.ClientFlight {
		return fmt.Errorf("twiddle: cover profile for %s does not match the measured identity", p.Host)
	}
	return nil
}

func (p CoverProfile) validateClientHello(h *ClientHello) ([]byte, error) {
	if !strings.EqualFold(h.SNI(), p.Host) {
		return nil, fmt.Errorf("twiddle: ClientHello SNI %q does not match cover %q", h.SNI(), p.Host)
	}
	offersCipher := false
	for _, suite := range h.CipherSuites {
		if suite == p.CipherSuite {
			offersCipher = true
			break
		}
	}
	if !offersCipher {
		return nil, fmt.Errorf("twiddle: ClientHello does not offer cover cipher %#04x", p.CipherSuite)
	}
	e := h.Find(ExtPreSharedKey)
	if e == nil {
		return nil, errors.New("twiddle: ClientHello carries no pre_shared_key")
	}
	ticket, _, binder, err := parsePSK(e.Data)
	if err != nil {
		return nil, err
	}
	if len(ticket) != p.TicketLen {
		return nil, fmt.Errorf("twiddle: ClientHello ticket length %d does not match cover %d", len(ticket), p.TicketLen)
	}
	if len(binder) != p.BinderLen {
		return nil, fmt.Errorf("twiddle: ClientHello binder length %d does not match cover %d", len(binder), p.BinderLen)
	}
	return ticket, nil
}

// ServerEncryptedWire is the application_data record that follows ServerHello
// and CCS in the first server burst. The burst was measured as a whole
// (1291–1333 B); the encrypted remainder is that minus the 1221-byte
// ServerHello and the 6-byte CCS. Using the burst total as the encrypted
// payload was the size bug: the server then wrote [1221, 6, ~1400].
func (p CoverProfile) ServerEncryptedWire() int {
	return p.ServerOpeningBurst - ServerHelloResumedLen - len(ChangeCipherSpec())
}

// ClientEncryptedWire is the application_data record that follows the client
// CCS. Measured client flights are 145–164 B including the 6-byte CCS.
func (p CoverProfile) ClientEncryptedWire() int {
	return p.ClientFlight - len(ChangeCipherSpec())
}

// TicketLenForCover returns the measured ticket length, including for a known
// but unimpersonable host, or DefaultTicketLen for an unmeasured host. Prefer
// CoverFor: this exists so existing callers that only needed the length keep
// compiling.
func TicketLenForCover(host string) int {
	if p, err := CoverFor(host); err == nil {
		return p.TicketLen
	}
	if host == "github.com" {
		return 32
	}
	return DefaultTicketLen
}

// PSKFirstForCover reports the measured ServerHello extension order.
func PSKFirstForCover(host string) bool {
	if p, err := CoverFor(host); err == nil {
		return p.PSKFirst
	}
	return false
}
