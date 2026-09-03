// Package coverprobe measures a cover identity from the upstream it
// impersonates, so an egress emits what that server actually does instead of a
// table someone has to keep current.
//
// It is a SEPARATE PACKAGE on purpose. Measuring a resumed opening means
// completing a real handshake and resuming it, which needs a TLS
// implementation — and the twiddle transport is built on depending on none.
// Keeping the dependency here means core twiddle stays free of it and an egress
// takes it deliberately, by importing this.
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
	"fmt"
	"net"
	"sync"
	"time"

	tw "github.com/getlantern/twiddle"
)

// Dialer opens a raw connection to the cover. Injected so an egress can route
// the probe the way it routes its masquerade traffic.
type Dialer func(ctx context.Context) (net.Conn, error)

// Probe establishes a session with host, resumes it, and reports the resumed
// opening the way an observer sees it.
//
// The client here is Go's crypto/tls, not Chrome, which is a valid probe for
// what the SERVER emits and not for what a client does — the server's opening
// follows the negotiated parameters. The empirical check that this holds: a Go
// client measured ServerHello 1221 and remainders 64/64/[32 74], matching what
// Chrome captures produced in harvest/testdata/tls13-burst-resumption.log. Do
// not use this to derive anything client-side; see the caveat in
// harvest/testdata/postflight-resumed.log.
func Probe(ctx context.Context, dial Dialer, host string) (tw.ProbeResult, error) {
	var res tw.ProbeResult
	res.Host = host

	cache := tls.NewLRUClientSessionCache(4)
	// First connection banks a ticket; nothing about it is reported.
	if err := session(ctx, dial, host, cache, nil); err != nil {
		return res, fmt.Errorf("coverprobe %s: priming handshake: %w", host, err)
	}

	tap := &recorder{}
	if err := session(ctx, dial, host, cache, tap); err != nil {
		return res, fmt.Errorf("coverprobe %s: resumed handshake: %w", host, err)
	}
	if !tap.resumed {
		return res, fmt.Errorf("coverprobe %s: upstream did not resume, so this is not the opening we imitate", host)
	}

	recs := tap.serverRecords()
	if len(recs) < 3 {
		return res, fmt.Errorf("coverprobe %s: server sent %d records, want ServerHello + ccs + remainder", host, len(recs))
	}
	if recs[0].typ != contentHandshake {
		return res, fmt.Errorf("coverprobe %s: first record is type %#02x, not a handshake", host, recs[0].typ)
	}
	res.ServerHello = recs[0].wire
	if recs[1].typ != contentCCS {
		return res, fmt.Errorf("coverprobe %s: second record is type %#02x, not a ChangeCipherSpec", host, recs[1].typ)
	}
	ccs := recs[1].wire

	// Everything after the CCS, up to the first record that arrives after the
	// burst has clearly ended, is the encrypted remainder.
	for _, r := range recs[2:] {
		if r.typ == contentAlert {
			return res, fmt.Errorf("coverprobe %s: upstream sent an alert during the opening", host)
		}
		if r.typ != contentAppData {
			break
		}
		res.Remainder = append(res.Remainder, r.wire)
	}
	if len(res.Remainder) == 0 {
		return res, fmt.Errorf("coverprobe %s: no encrypted remainder after the ChangeCipherSpec", host)
	}
	res.OpeningBurst = res.ServerHello + ccs
	for _, n := range res.Remainder {
		res.OpeningBurst += n
	}
	res.Elapsed = tap.elapsed
	return res, nil
}

// session runs one connection. When tap is non-nil it records the wire and
// stops right after the handshake, so what it holds is the opening and nothing
// else.
func session(ctx context.Context, dial Dialer, host string, cache tls.ClientSessionCache, tap *recorder) error {
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
	if tap != nil {
		tap.resumed = tc.ConnectionState().DidResume
		tap.elapsed = time.Since(tap.start)
		return tc.Close()
	}

	// Priming run: read enough for the ticket to arrive and be cached, then
	// close cleanly so it is usable.
	_, _ = tc.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"))
	_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16<<10)
	for {
		if _, err := tc.Read(buf); err != nil {
			break
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

	mu   sync.Mutex
	buf  []byte
	recs []record
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
	out := make([]record, len(r.recs))
	copy(out, r.recs)
	return out
}
