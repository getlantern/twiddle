package twiddle

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
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
	Host        string
	CipherSuite uint16
	BinderLen   int
	TicketLen   int
	PSKFirst    bool
	// ResumedRemainder is the encrypted record SEQUENCE the cover sends after
	// ServerHello and ChangeCipherSpec -- not a total.
	//
	// The distinction is the whole point: cloudflare and google coalesce
	// EncryptedExtensions and Finished into one 64 B record, while microsoft
	// sends 32 then 74. Modelled as a single 106 B total, microsoft's byte
	// count matched while we put 3 server records on the wire where the real
	// identity puts 4. The total is what a sum models; the sequence is what an
	// observer counts.
	ResumedRemainder []int

	// FullRemainder is the same sequence for a FULL handshake, where the
	// remainder carries the certificate and is one to two orders of magnitude
	// larger: 3848 / 3921 / 8273 B against 64 / 64 / 106 resumed.
	//
	// It is EMPTY in the table on purpose. Unlike the resumed remainder, this
	// one cannot be a constant: it moves run to run as the DER-encoded ECDSA
	// signature in CertificateVerify changes length (cloudflare 3847/3848/3848,
	// google 3920/3921/3921, while microsoft's fixed-length RSA signature holds
	// 8273), and it changes outright on every certificate rotation. A cover
	// emitting a full handshake must have this filled by coverprobe against the
	// live upstream; a stale constant here would be worse than none.
	FullRemainder []int

	// FullRemainderJitter is the per-position range, in bytes, over which each
	// full-handshake remainder record was observed to vary. Same length as
	// FullRemainder when set.
	//
	// It exists because the certificate flight is not a constant even between
	// two connections a second apart: cloudflare was measured at 3847 and 3848,
	// google at 3920 and 3921, while microsoft held 8273 exactly. That is what
	// a DER-encoded ECDSA signature in CertificateVerify does -- its length
	// varies with the integers it encodes -- and microsoft's fixed-length RSA
	// signature is why it does not move.
	//
	// An emitter that sends FullRemainder verbatim would be the only host on
	// the network whose certificate flight is byte-identical every time. The
	// baseline is therefore the smallest length observed and the emitted length
	// is drawn from [baseline, baseline+jitter].
	FullRemainderJitter []int

	// ResumedClientFlight is a TOTAL, deliberately, because only the total is
	// measured. It comes from Chrome captures
	// (harvest/testdata/tls13-burst-resumption.log); the record split within it
	// is unknown, and a Go TLS client is not a valid probe for it -- see the
	// caveat in harvest/testdata/postflight-resumed.log. Do not turn this into
	// a sequence until Chrome has been captured.
	ResumedClientFlight int
}

// ErrUnknownCover is returned when a caller names a host we have not measured,
// or one whose ticket is too short to carry the authenticator (github.com).
var ErrUnknownCover = fmt.Errorf("twiddle: unknown cover identity")

var covers = map[string]CoverProfile{
	"www.cloudflare.com": {
		Host:                "www.cloudflare.com",
		CipherSuite:         TLS_AES_128_GCM_SHA256,
		BinderLen:           32,
		TicketLen:           176,
		PSKFirst:            true,
		ResumedRemainder:    []int{64},
		ResumedClientFlight: 149,
	},
	"www.google.com": {
		Host:                "www.google.com",
		CipherSuite:         TLS_AES_128_GCM_SHA256,
		BinderLen:           32,
		TicketLen:           230,
		PSKFirst:            true,
		ResumedRemainder:    []int{64},
		ResumedClientFlight: 145,
	},
	"www.microsoft.com": {
		Host:                "www.microsoft.com",
		CipherSuite:         TLS_AES_256_GCM_SHA384,
		BinderLen:           48,
		TicketLen:           256,
		PSKFirst:            false,
		ResumedRemainder:    []int{32, 74},
		ResumedClientFlight: 164,
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
		!slices.Equal(p.ResumedRemainder, known.ResumedRemainder) || p.ResumedClientFlight != known.ResumedClientFlight {
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

// FullOpeningBurst totals a full handshake's first server burst. Zero when
// FullRemainder is unset, which is the table's default: the full profile is
// probe-supplied, never assumed.
func (p CoverProfile) FullOpeningBurst() int {
	if len(p.FullRemainder) == 0 {
		return 0
	}
	total := ServerHelloFullLen + len(ChangeCipherSpec())
	for _, n := range p.FullRemainder {
		total += n
	}
	return total
}

// CanEmitFullHandshake reports whether this profile has been given a measured
// full-handshake shape. Without one, an egress must not offer that carrier:
// emitting a guessed certificate flight is worse than only offering the
// resumed path.
func (p CoverProfile) CanEmitFullHandshake() bool {
	return len(p.FullRemainder) > 0
}

// ResumedOpeningBurst totals the first server burst: ServerHello, the
// ChangeCipherSpec, and every encrypted remainder record. Derived from the
// sequence so the two can never disagree.
func (p CoverProfile) ResumedOpeningBurst() int {
	total := ServerHelloResumedLen + len(ChangeCipherSpec())
	for _, n := range p.ResumedRemainder {
		total += n
	}
	return total
}

// ClientEncryptedWire is the application_data record that follows the client
// CCS. Measured client flights are 145–164 B including the 6-byte CCS.
func (p CoverProfile) ClientEncryptedWire() int {
	return p.ResumedClientFlight - len(ChangeCipherSpec())
}

// TicketLenForCover returns the measured ticket length, including for a known
// but unimpersonable host, or DefaultTicketLen for an unmeasured host. Prefer
// CoverFor: this exists so existing callers that only needed the length keep
// compiling.
func TicketLenForCover(host string) int {
	if p, err := CoverFor(host); err == nil {
		return p.TicketLen
	}
	// EqualFold, because CoverFor lowercases before its lookup and a fallback
	// that does not would answer differently for "GitHub.com" than for
	// "github.com" -- a silent 176 where the record says 32.
	if strings.EqualFold(host, "github.com") {
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

// ProbeResult is what one cover probe learned from the live upstream. The
// probe itself lives in the coverprobe subpackage, which needs a TLS
// implementation to reach a resumed handshake; this type and Adopt do not, so
// they stay here where the profile does.
type ProbeResult struct {
	Host string
	// Full says the probe measured a FULL handshake rather than a resumed one.
	// The two have different ServerHello lengths and wildly different
	// remainders, so a result adopted into the wrong variant would be silently
	// catastrophic -- hence a field rather than inference from the numbers.
	Full bool
	// ServerHello is the first handshake record's wire length.
	ServerHello int
	// Remainder is the encrypted record SEQUENCE after ServerHello and the
	// ChangeCipherSpec -- the field a single total could not express.
	Remainder []int
	// OpeningBurst is ServerHello + ChangeCipherSpec + every remainder record.
	OpeningBurst int
	Elapsed      time.Duration
}

const (
	// maxRemainderRecords bounds a plausible opening. Measured servers send one
	// or two; more than a handful is not the shape this transport imitates.
	maxRemainderRecords = 4
	// maxBurstDrift is how far a probe may move the opening burst before it
	// looks like a different server rather than the same one having changed.
	// The measured spread across three covers is 42 B, 1291 to 1333.
	maxBurstDrift = 256

	// A full handshake's burst has no constant to compare against, so it is
	// bounded instead. Measured at 5069, 5142 and 9886; the range allows for a
	// small chain on one side and a long one with many intermediates on the
	// other, while still rejecting a resumed burst or a multi-megabyte answer
	// from something that is not the cover.
	minFullBurst = 2000
	maxFullBurst = 32768
)

// Adopt folds a probe into a profile and returns what the egress should emit.
//
// Only what the probe actually measured is replaced, and only into the variant
// it measured. The resumption-derived fields -- cipher, binder length, ticket
// length, PSK order -- come from p, because they describe the handshake rather
// than the opening burst.
//
// A probe that disagrees with the known identity is REJECTED rather than
// adopted, and rejection is the point: whatever a probe returns would otherwise
// be emitted by every client on that egress, so a CDN edge, a captive portal or
// a hostile upstream answering in the cover's place must not silently become
// the profile. Fail closed, and let the caller decide whether to keep serving
// on the last good profile or refuse to start.
//
// The two variants are validated differently, because only one has a baseline.
// The resumed remainder is a stable measured constant, so a probe is checked
// against it. The full remainder is the certificate: there is no constant to
// compare to -- it moves run to run and on every rotation -- so it is checked
// structurally instead, on the ServerHello length, the record count and a
// plausible size range.
func (p CoverProfile) Adopt(res ProbeResult) (CoverProfile, error) {
	if res.Host != p.Host {
		return p, fmt.Errorf("twiddle: probe of %s cannot update the %s profile", res.Host, p.Host)
	}
	if len(res.Remainder) == 0 || len(res.Remainder) > maxRemainderRecords {
		return p, fmt.Errorf("twiddle: probe of %s returned %d remainder records, outside 1..%d",
			res.Host, len(res.Remainder), maxRemainderRecords)
	}
	for _, n := range res.Remainder {
		if n <= recordHeaderLen {
			return p, fmt.Errorf("twiddle: probe of %s returned a %d B remainder record", res.Host, n)
		}
	}

	if res.Full {
		if res.ServerHello != ServerHelloFullLen {
			return p, fmt.Errorf("twiddle: full probe of %s returned a %d B ServerHello, not the %d B full shape",
				res.Host, res.ServerHello, ServerHelloFullLen)
		}
		if res.OpeningBurst < minFullBurst || res.OpeningBurst > maxFullBurst {
			return p, fmt.Errorf("twiddle: full probe of %s returned a %d B opening burst, outside the plausible %d..%d for a certificate flight",
				res.Host, res.OpeningBurst, minFullBurst, maxFullBurst)
		}
		out := p
		out.FullRemainder = append([]int(nil), res.Remainder...)
		return out, nil
	}

	if res.ServerHello != ServerHelloResumedLen {
		return p, fmt.Errorf("twiddle: resumed probe of %s returned a %d B ServerHello, not the %d B resumed shape we synthesise",
			res.Host, res.ServerHello, ServerHelloResumedLen)
	}
	known := p.ResumedOpeningBurst()
	if delta := res.OpeningBurst - known; delta < -maxBurstDrift || delta > maxBurstDrift {
		return p, fmt.Errorf("twiddle: resumed probe of %s returned a %d B opening burst, %+d from the measured %d; not adopting",
			res.Host, res.OpeningBurst, delta, known)
	}
	out := p
	out.ResumedRemainder = append([]int(nil), res.Remainder...)
	return out, nil
}
