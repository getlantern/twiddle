// Package coverprobe measures a cover identity from the upstream it
// impersonates, so an egress emits what that server actually does instead of a
// table someone has to keep current.
//
// It lives under harvest/, with the rest of the measurement tooling, for one
// reason: it imports crypto/tls, and nothing twiddle ships may.
//
// "This module depends on no TLS library for its own operation" is not a slogan
// — it is why the transport is free of the preset-staleness treadmill that uTLS
// lives on, and it should stay checkable by grep rather than by argument.
// Measuring a RESUMED opening genuinely requires a TLS implementation: the
// shape only exists after a server has issued a ticket, and reaching that means
// completing a real handshake. So the dependency is real and the answer is to
// put it where it cannot reach a shipped binary, next to cmd/postflight and
// cmd/resume which already have it.
//
// That does not cost runtime probing. ProbeResult and CoverProfile.Adopt live
// in core twiddle and need no TLS, so anything that ALREADY links a TLS stack —
// lantern-box does, through sing-box — can probe with its own and feed the
// result through Adopt. What it must not do is acquire the dependency by
// importing twiddle.
//
// The naive approach does not work and it is worth recording why. A probe that
// emits a twiddle hello and never completes the handshake — cmd/flight's
// approach — measures a FULL handshake: the server answers with a 1215 B
// ServerHello and a multi-kilobyte remainder carrying Certificate and
// CertificateVerify. Measured against the live covers: cloudflare [2809],
// google [12127], microsoft [41 8273 286 74]. Our transport always presents a
// resumption hello, whose opening is 1221 B and a 64 or 106 B remainder. You
// cannot reach that shape without a ticket the server itself issued, so the
// probe has to hold a real session first.
package coverprobe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	tw "github.com/getlantern/twiddle"
)

// Dialer opens a raw connection to the cover. Injected so an egress can route
// the probe the way it routes its masquerade traffic.
type Dialer func(ctx context.Context) (net.Conn, error)

// Probe establishes a session with host, resumes it, and reports the RESUMED
// opening. ProbeBoth reports the full handshake as well.
//
// The client here is Go's crypto/tls, not Chrome, which is a valid probe for
// what the SERVER emits and not for what a client does — the server's opening
// follows the negotiated parameters. The empirical check that this holds: a Go
// client measured ServerHello 1221 and remainders 64/64/[32 74], matching what
// Chrome captures produced in harvest/testdata/tls13-burst-resumption.log. Do
// not use this to derive anything client-side; see the caveat in
// harvest/testdata/postflight-resumed.log.
func Probe(ctx context.Context, dial Dialer, host string) (tw.ProbeResult, error) {
	_, resumed, err := ProbeBoth(ctx, dial, host)
	return resumed, err
}

// ProbeBoth reports the full handshake and the resumed one from a single pair
// of connections against the same server, so the two are directly comparable.
//
// The full handshake is not a by-product: only ~4% of real browsing connections
// are resumptions, so it is the shape the population actually takes, and its
// remainder — the certificate flight — cannot come from a table because it
// moves run to run and on every rotation. An egress offering that carrier has
// to probe for it.
//
// The connection that banks the ticket is the same one the full profile is read
// from, which is why the request that triggers ticket issuance is sent only
// AFTER the full opening has been captured. cloudflare and google issue no
// ticket until application data has flowed, so without that request there is
// nothing to resume with — and with it sent too early, the full profile would
// be polluted by the response.
func ProbeBoth(ctx context.Context, dial Dialer, host string) (full, resumed tw.ProbeResult, err error) {
	full.Host, resumed.Host = host, host
	full.Full = true

	cache := tls.NewLRUClientSessionCache(4)
	// bank: this connection must also elicit a ticket, or there is nothing to
	// resume. The request goes out only after the opening is frozen.
	fullTap := &recorder{}
	if err := session(ctx, dial, host, cache, fullTap, true); err != nil {
		return full, resumed, fmt.Errorf("coverprobe %s: full handshake: %w", host, err)
	}
	if fullTap.resumed {
		return full, resumed, fmt.Errorf("coverprobe %s: first connection resumed; the full profile would be wrong", host)
	}
	if err := readOpening(&full, fullTap, tw.ServerHelloFullLen, host); err != nil {
		return full, resumed, err
	}

	tap := &recorder{}
	if err := session(ctx, dial, host, cache, tap, false); err != nil {
		return full, resumed, fmt.Errorf("coverprobe %s: resumed handshake: %w", host, err)
	}
	if !tap.resumed {
		return full, resumed, fmt.Errorf("coverprobe %s: %w, so this is not the opening we imitate", host, ErrNoResume)
	}
	if err := readOpening(&resumed, tap, tw.ServerHelloResumedLen, host); err != nil {
		return full, resumed, err
	}
	return full, resumed, nil
}

// readOpening turns one tapped connection's server records into a ProbeResult.
func readOpening(res *tw.ProbeResult, tap *recorder, wantServerHello int, host string) error {
	recs := tap.serverRecords()
	if len(recs) < 3 {
		return fmt.Errorf("coverprobe %s: server sent %d records, want ServerHello + ccs + remainder", host, len(recs))
	}
	if recs[0].typ != contentHandshake {
		return fmt.Errorf("coverprobe %s: first record is type %#02x, not a handshake", host, recs[0].typ)
	}
	res.ServerHello = recs[0].wire
	if res.ServerHello != wantServerHello {
		return fmt.Errorf("coverprobe %s: ServerHello is %d B, want %d for this handshake type",
			host, res.ServerHello, wantServerHello)
	}
	if recs[1].typ != contentCCS {
		return fmt.Errorf("coverprobe %s: second record is type %#02x, not a ChangeCipherSpec", host, recs[1].typ)
	}
	ccs := recs[1].wire

	// Everything after the CCS, up to the first record that arrives after the
	// burst has clearly ended, is the encrypted remainder.
	for _, r := range recs[2:] {
		if r.typ == contentAlert {
			return fmt.Errorf("coverprobe %s: upstream sent an alert during the opening", host)
		}
		if r.typ != contentAppData {
			break
		}
		res.Remainder = append(res.Remainder, r.wire)
	}
	if len(res.Remainder) == 0 {
		return fmt.Errorf("coverprobe %s: no encrypted remainder after the ChangeCipherSpec", host)
	}
	res.OpeningBurst = res.ServerHello + ccs
	for _, n := range res.Remainder {
		res.OpeningBurst += n
	}
	res.Elapsed = tap.elapsed
	return nil
}

// session runs one connection. When tap is non-nil it records the wire and
// stops right after the handshake, so what it holds is the opening and nothing
// else.
func session(ctx context.Context, dial Dialer, host string, cache tls.ClientSessionCache, tap *recorder, bank bool) error {
	raw, err := dial(ctx)
	if err != nil {
		return err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}

	conn := net.Conn(raw)
	if tap != nil {
		tap.Conn = raw
		tap.start = time.Now()
		conn = tap
	}
	tc := tls.Client(conn, &tls.Config{
		ServerName:         host,
		ClientSessionCache: cache,
		MinVersion:         tls.VersionTLS13,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	tap.resumed = tc.ConnectionState().DidResume
	tap.elapsed = time.Since(tap.start)
	// Freeze here: everything recorded from now on is the response to the
	// banking request, and letting it into the record list would append the
	// HTTP body to the remainder.
	tap.freeze()

	if bank {
		// cloudflare and google issue no ticket until application data has
		// flowed, so without this there is nothing to resume with. It runs
		// after the freeze precisely so it cannot pollute what was measured.
		_, _ = tc.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"))
		_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16<<10)
		for {
			if _, err := tc.Read(buf); err != nil {
				break
			}
		}
	}
	return tc.Close()
}

const (
	contentCCS       = 0x14
	contentAlert     = 0x15
	contentHandshake = 0x16
	contentAppData   = 0x17
	recordHeaderLen  = 5
)

type record struct {
	typ  byte
	wire int
}

// recorder splits the inbound byte stream into records. The 5-byte header is
// cleartext even when the payload is not, which is exactly what an observer
// gets.
type recorder struct {
	net.Conn
	start   time.Time
	elapsed time.Duration
	resumed bool

	mu     sync.Mutex
	buf    []byte
	recs   []record
	frozen []record
}

// freeze fixes what serverRecords reports, so traffic after the opening cannot
// be mistaken for part of it.
func (r *recorder) freeze() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frozen = make([]record, len(r.recs))
	copy(r.frozen, r.recs)
}

func (r *recorder) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if n > 0 {
		r.mu.Lock()
		r.buf = append(r.buf, b[:n]...)
		for len(r.buf) >= recordHeaderLen {
			sz := recordHeaderLen + int(binary.BigEndian.Uint16(r.buf[3:5]))
			if len(r.buf) < sz {
				break
			}
			r.recs = append(r.recs, record{typ: r.buf[0], wire: sz})
			r.buf = r.buf[sz:]
		}
		r.mu.Unlock()
	}
	return n, err
}

func (r *recorder) serverRecords() []record {
	r.mu.Lock()
	defer r.mu.Unlock()
	src := r.recs
	if r.frozen != nil {
		src = r.frozen
	}
	out := make([]record, len(src))
	copy(out, src)
	return out
}

// SampleFull probes the full handshake n times and reports the baseline
// remainder together with the range each record was seen to move over.
//
// One probe cannot tell a constant from a variable, and the full remainder is a
// variable: the DER-encoded ECDSA signature in CertificateVerify changes length
// between connections. Emitting a single observation verbatim would make us the
// only host on the network whose certificate flight never varies -- so the
// spread has to be measured, not assumed.
//
// The baseline is the smallest length seen at each position and the jitter is
// the observed range. A run where the record COUNT changes between samples is
// rejected: that is a different server answering, not the same one jittering.
// ErrNoResume reports that an upstream declined to resume the session it had
// just issued a ticket for.
//
// It is a sentinel because it is the one probe failure that leaves a USABLE
// result behind: ProbeBoth completes and reads the full opening before it
// attempts the resumed one, so a result carrying this error has a valid full
// profile and only an unperformed resumed check.
//
// The condition is common rather than rare. Cloudflare declines most of the
// time -- a second connection lands on a different edge server from the one
// that issued the ticket, so the ticket does not decrypt and the server falls
// back to a full handshake. Nothing is wrong with the cover or with us when
// that happens, which is why SampleFull treats it as success and why retrying
// it is pointless.
var ErrNoResume = errors.New("upstream did not resume")

func SampleFull(ctx context.Context, dial Dialer, host string, n int) (tw.ProbeResult, []int, error) {
	if n < 2 {
		return tw.ProbeResult{}, nil, fmt.Errorf("coverprobe %s: SampleFull needs at least 2 samples to see a range", host)
	}
	var base tw.ProbeResult
	var lo, hi []int
	for i := 0; i < n; i++ {
		// What this function measures is the FULL profile. The resumed leg is
		// ProbeBoth's own consistency check and is not sampled here, so a
		// sample whose ONLY failure was that the upstream declined to resume
		// still carries everything being measured, and is accepted.
		//
		// This is not leniency for its own sake: requiring the resumed leg made
		// this unusable against cloudflare, which declines most of the time, so
		// the check was holding the measurement hostage to a behaviour it was
		// not measuring. Every other error is still fatal.
		full, _, err := ProbeBoth(ctx, dial, host)
		if err != nil && !errors.Is(err, ErrNoResume) {
			return base, nil, fmt.Errorf("coverprobe %s: sample %d: %w", host, i+1, err)
		}
		if i == 0 {
			base = full
			lo = append([]int(nil), full.Remainder...)
			hi = append([]int(nil), full.Remainder...)
			continue
		}
		if len(full.Remainder) != len(lo) {
			return base, nil, fmt.Errorf("coverprobe %s: sample %d returned %d remainder records, first returned %d — not the same server",
				host, i+1, len(full.Remainder), len(lo))
		}
		for j, v := range full.Remainder {
			if v < lo[j] {
				lo[j] = v
			}
			if v > hi[j] {
				hi[j] = v
			}
		}
	}
	jitter := make([]int, len(lo))
	for i := range lo {
		jitter[i] = hi[i] - lo[i]
	}
	base.Remainder = lo
	// Carried inside the result as well as returned, so CoverProfile.Adopt gets
	// the baseline and its range together. Adopting a baseline without the
	// range is what produces an emitter whose certificate flight never varies.
	base.RemainderJitter = jitter
	base.OpeningBurst = tw.ServerHelloFullLen + len(tw.ChangeCipherSpec())
	for _, v := range lo {
		base.OpeningBurst += v
	}
	return base, jitter, nil
}
