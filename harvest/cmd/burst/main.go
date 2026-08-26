// burst measures the size/direction/timing sequence a TLS 1.3 handshake puts on
// the wire, for a full handshake and for a resumed one against the same server.
//
// This is the feature representation used by Xue et al. (USENIX Security 2024)
// to fingerprint encapsulated TLS handshakes: each flow becomes a sequence of
// signed integers where magnitude is payload size and sign is direction, then
// consecutive same-direction packets are aggregated into bursts. Their TLS 1.3
// classifier slides a 3-burst window (Wb = 2*RT+1) over that sequence.
//
// The question this answers: does a RESUMED handshake produce the same burst
// triple as a full one? The paper conjectures resumption is a major source of
// false negatives but does not measure it.
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sort"
	"time"
)

type ev struct {
	out bool
	n   int
	t   time.Duration
}

type tap struct {
	net.Conn
	t0     time.Time
	events []ev
	done   bool
}

func (c *tap) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && !c.done {
		c.events = append(c.events, ev{false, n, time.Since(c.t0)})
	}
	return n, err
}

func (c *tap) Write(b []byte) (int, error) {
	if !c.done {
		c.events = append(c.events, ev{true, len(b), time.Since(c.t0)})
	}
	return c.Conn.Write(b)
}

// bursts aggregates consecutive same-direction events, as the paper does.
func bursts(evs []ev) []int {
	var out []int
	for _, e := range evs {
		v := e.n
		if !e.out {
			v = -v
		}
		if len(out) > 0 && (out[len(out)-1] > 0) == (v > 0) {
			out[len(out)-1] += v
			continue
		}
		out = append(out, v)
	}
	return out
}

func seqStr(evs []ev) string {
	s := ""
	for i, e := range evs {
		if i >= 8 {
			s += " ..."
			break
		}
		sign := "+"
		if !e.out {
			sign = "-"
		}
		s += fmt.Sprintf("%s%d ", sign, e.n)
	}
	return s
}

func run(host string) {
	cache := tls.NewLRUClientSessionCache(8)
	var full, res []ev
	var resumed bool

	for i := 0; i < 2; i++ {
		raw, err := net.DialTimeout("tcp", host+":443", 8*time.Second)
		if err != nil {
			fmt.Println("  dial:", err)
			return
		}
		tp := &tap{Conn: raw, t0: time.Now()}
		c := tls.Client(tp, &tls.Config{
			ServerName:         host,
			ClientSessionCache: cache,
			MinVersion:         tls.VersionTLS13,
		})
		c.SetDeadline(time.Now().Add(10 * time.Second))
		if err := c.Handshake(); err != nil {
			fmt.Println("  handshake:", err)
			raw.Close()
			return
		}
		// one application exchange, then stop recording
		c.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"))
		buf := make([]byte, 4096)
		c.Read(buf)
		tp.done = true
		if i == 0 {
			full = tp.events
			io := make([]byte, 8192)
			for {
				if _, err := c.Read(io); err != nil {
					break
				}
			}
		} else {
			res = tp.events
			resumed = c.ConnectionState().DidResume
		}
		c.Close()
		raw.Close()
		time.Sleep(400 * time.Millisecond)
	}
	if full == nil || res == nil {
		fmt.Println("  incomplete")
		return
	}

	bf, br := bursts(full), bursts(res)
	fmt.Printf("  FULL     seq: %s\n", seqStr(full))
	fmt.Printf("           bursts: %v\n", bf)
	fmt.Printf("  RESUMED  seq: %s   (DidResume=%v)\n", seqStr(res), resumed)
	fmt.Printf("           bursts: %v\n", br)

	// the server burst is the discriminating one: a full handshake carries a
	// certificate chain, a resumed handshake does not.
	sf, sr := firstServerBurst(bf), firstServerBurst(br)
	if sf != 0 && sr != 0 {
		fmt.Printf("  >> first server burst: full %d B  vs  resumed %d B   (resumed is %.1f%% of full)\n",
			-sf, -sr, 100*float64(sr)/float64(sf))
	}
}

func firstServerBurst(b []int) int {
	for _, v := range b {
		if v < 0 {
			return v
		}
	}
	return 0
}

func main() {
	hosts := os.Args[1:]
	if len(hosts) == 0 {
		hosts = []string{"www.google.com", "www.cloudflare.com", "www.microsoft.com",
			"github.com", "www.wikipedia.org", "www.amazon.com"}
	}
	sort.Strings(hosts)
	fmt.Println("Xue et al. burst representation: signed payload sizes, consecutive")
	fmt.Println("same-direction packets aggregated. TLS 1.3 classifier window Wb=3.")
	for _, h := range hosts {
		fmt.Printf("\n=== %s\n", h)
		run(h)
	}
}
