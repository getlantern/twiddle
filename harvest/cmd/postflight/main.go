// postflight measures the opening, the post-handshake records and the teardown
// of a real TLS 1.3 server, for BOTH a full and a resumed handshake.
//
// Both matter, and the full one matters more than it looks. Only ~4% of real
// browsing connections are resumptions -- measured in
// harvest/testdata/resumption-ratio-session.log, because a page load opens each
// origin's connections in a parallel burst before any ticket exists -- so the
// full handshake is the shape the overwhelming majority of the population
// takes.
//
// Everything else in harvest stops at the opening burst. Two numbers twiddle
// emits live past it and were never measured:
//
//	sessionTicketWire = 370   a "plausible" NewSessionTicket record, and one of
//	                          them -- while TLS 1.3 servers commonly send two
//	Conn.Close()              closes the socket, sending no close_notify, where
//	                          a real TLS 1.3 endpoint normally sends an alert
//	                          record first
//
// Both are as observable as the opening: a censor watching record sizes and
// directions sees the post-handshake sequence and the last record before FIN
// just as cheaply as it sees the first.
//
// Method. Resume against the host, then hold a QUIET READ WINDOW: send nothing
// and read with a deadline. Anything the server sends in that window is a
// post-handshake handshake message, because nothing was requested -- which
// isolates NewSessionTicket from application data without needing to decrypt.
// Then close and record what each side emits.
//
// Post-handshake records are all outer type 0x17 in TLS 1.3, so this reports
// what an observer can actually use -- direction, outer type, length, timing --
// rather than pretending to see inside.
//
//	go run ./cmd/postflight
//	go run ./cmd/postflight -hosts www.google.com,www.microsoft.com -quiet 800ms
package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	hosts = flag.String("hosts", "www.cloudflare.com,www.google.com,www.microsoft.com",
		"comma-separated cover identities to measure")
	quiet   = flag.Duration("quiet", 700*time.Millisecond, "quiet read window after the resumed handshake")
	timeout = flag.Duration("timeout", 12*time.Second, "per-host dial and handshake budget")
)

// rec is one TLS record as an observer sees it: the 5-byte header is cleartext
// even when the payload is not.
type rec struct {
	dir  string // "S" server->client, "C" client->server
	typ  byte
	size int // full record size on the wire, header included
	at   time.Duration
}

func (r rec) String() string {
	return fmt.Sprintf("%s %s %d B @ %.1fms", r.dir, typeName(r.typ), r.size, float64(r.at.Microseconds())/1000)
}

func typeName(t byte) string {
	switch t {
	case 0x14:
		return "ccs      "
	case 0x15:
		return "ALERT    "
	case 0x16:
		return "handshake"
	case 0x17:
		return "appdata  "
	}
	return fmt.Sprintf("0x%02x     ", t)
}

// tapConn records every record crossing it, in both directions.
type tapConn struct {
	net.Conn
	t0 time.Time

	mu       sync.Mutex
	recs     []rec
	inBuf    []byte
	outBuf   []byte
	splitDir map[string]*[]byte
}

func newTap(c net.Conn) *tapConn {
	t := &tapConn{Conn: c, t0: time.Now()}
	t.splitDir = map[string]*[]byte{"S": &t.inBuf, "C": &t.outBuf}
	return t
}

// feed accumulates a direction's byte stream and emits one rec per complete
// record. A record can span reads, and several can arrive in one.
func (t *tapConn) feed(dir string, b []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	buf := t.splitDir[dir]
	*buf = append(*buf, b...)
	for len(*buf) >= 5 {
		n := 5 + int(binary.BigEndian.Uint16((*buf)[3:5]))
		if len(*buf) < n {
			return
		}
		t.recs = append(t.recs, rec{dir: dir, typ: (*buf)[0], size: n, at: time.Since(t.t0)})
		*buf = (*buf)[n:]
	}
}

func (t *tapConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if n > 0 {
		t.feed("S", b[:n])
	}
	return n, err
}

func (t *tapConn) Write(b []byte) (int, error) {
	n, err := t.Conn.Write(b)
	if n > 0 {
		t.feed("C", b[:n])
	}
	return n, err
}

func (t *tapConn) records() []rec {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]rec, len(t.recs))
	copy(out, t.recs)
	return out
}

func main() {
	flag.Parse()
	fmt.Printf("postflight: opening, post-handshake and teardown record profile, full and resumed TLS 1.3\n")
	fmt.Printf("quiet window %v, per-host budget %v\n\n", *quiet, *timeout)

	var failures int
	for _, host := range strings.Split(*hosts, ",") {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if err := measure(host); err != nil {
			fmt.Printf("%-22s FAILED: %v\n\n", host, err)
			failures++
		}
	}
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "%d host(s) failed\n", failures)
		os.Exit(1)
	}
}

func measure(host string) error {
	cache := tls.NewLRUClientSessionCache(4)
	addr := net.JoinHostPort(host, "443")

	// Both handshakes are reported. The first is a FULL handshake -- the shape
	// ~96% of real browsing connections actually take
	// (harvest/testdata/resumption-ratio-session.log measured 4.1% resumption,
	// because a page load opens each origin's connections in a parallel burst
	// before any ticket exists). It also happens to bank the ticket the second
	// connection resumes with, so one run yields both profiles from the same
	// client against the same server, directly comparable.
	if err := once(host, addr, cache, "full"); err != nil {
		return fmt.Errorf("full handshake: %w", err)
	}
	return once(host, addr, cache, "resumed")
}

func once(host, addr string, cache tls.ClientSessionCache, kind string) error {
	raw, err := net.DialTimeout("tcp", addr, *timeout)
	if err != nil {
		return err
	}
	tap := newTap(raw)
	defer tap.Close()

	tc := tls.Client(tap, &tls.Config{
		ServerName:         host,
		ClientSessionCache: cache,
		MinVersion:         tls.VersionTLS13,
	})
	tap.SetDeadline(time.Now().Add(*timeout))
	if err := tc.Handshake(); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	st := tc.ConnectionState()
	if kind == "resumed" && !st.DidResume {
		return fmt.Errorf("did not resume (version %x, cipher %x) — cannot measure the resumed profile",
			st.Version, st.CipherSuite)
	}
	if kind == "full" && st.DidResume {
		return fmt.Errorf("resumed on the first connection; the full profile would be wrong")
	}
	handshakeDone := len(tap.records())

	// Quiet window: request nothing. Anything arriving is post-handshake
	// handshake traffic, i.e. NewSessionTicket. This is where the full and
	// resumed profiles differ most: a server that issues tickets does it here,
	// on the connection that had no ticket to begin with.
	tc.SetReadDeadline(time.Now().Add(*quiet))
	buf := make([]byte, 16<<10)
	for {
		if _, err := tc.Read(buf); err != nil {
			break
		}
	}
	afterQuiet := tap.records()

	// On the full handshake, bank a ticket for the resumed run. This happens
	// AFTER the quiet window is captured, so it cannot contaminate the
	// unprompted count -- which is the point, because cloudflare and google
	// issue no ticket until application data has flowed, and without one there
	// is nothing to resume.
	if kind == "full" {
		_ = tc.SetReadDeadline(time.Now().Add(*quiet))
		_, _ = tc.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"))
		drain := make([]byte, 16<<10)
		for {
			if _, err := tc.Read(drain); err != nil {
				break
			}
		}
	}
	// Re-baseline AFTER banking, so the response body does not land in the
	// teardown section.
	beforeClose := tap.records()

	// Clean close: Go's crypto/tls sends close_notify here, so this shows both
	// what a real client emits and whether the server answers in kind.
	tap.SetDeadline(time.Now().Add(2 * time.Second))
	closeErr := tc.Close()
	time.Sleep(150 * time.Millisecond)
	final := tap.records()

	fmt.Printf("%s  (%s, version %x cipher %x)\n", host, kind, st.Version, st.CipherSuite)
	fmt.Printf("  opening (%d records):\n", handshakeDone)
	for _, r := range final[:handshakeDone] {
		fmt.Printf("    %s\n", r)
	}

	quietRecs := afterQuiet[handshakeDone:]
	fmt.Printf("  quiet window, nothing requested (%d records) <- NewSessionTicket lives here:\n", len(quietRecs))
	for _, r := range quietRecs {
		fmt.Printf("    %s\n", r)
	}
	var srvQuiet []int
	for _, r := range quietRecs {
		if r.dir == "S" {
			srvQuiet = append(srvQuiet, r.size)
		}
	}
	fmt.Printf("    => server sent %d record(s) unprompted, sizes %v\n", len(srvQuiet), srvQuiet)

	tearRecs := final[len(beforeClose):]
	fmt.Printf("  teardown (%d records), close err=%v:\n", len(tearRecs), closeErr)
	for _, r := range tearRecs {
		fmt.Printf("    %s\n", r)
	}
	if kind == "full" {
		fmt.Printf("    (ticket banking: the request below is sent AFTER the quiet window, so the\n")
		fmt.Printf("     unprompted count above is unaffected by it)\n")
	}
	var cTear, sTear []int
	for _, r := range tearRecs {
		if r.dir == "C" {
			cTear = append(cTear, r.size)
		} else {
			sTear = append(sTear, r.size)
		}
	}
	fmt.Printf("    => client emitted %v at close, server %v\n", cTear, sTear)
	fmt.Println()
	return nil
}
