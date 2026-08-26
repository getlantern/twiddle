// resumeratio measures what fraction of a real browsing session's TLS
// connections are resumptions.
//
// This is the gating number for twiddle's routing rule: resumed inner
// handshakes go passthrough (weak burst triple), full handshakes go through the
// wrapped mux tunnel. How much traffic each path carries decides whether the
// design holds.
//
// It runs as an HTTP CONNECT proxy so a real browser can be pointed at it. No
// TLS interception: we peek the first record of each tunnel, check the
// ClientHello for pre_shared_key (extension 41), and relay verbatim.
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type stats struct {
	mu       sync.Mutex
	full     int
	resumed  int
	notTLS   int
	perHost  map[string][2]int // host -> [full, resumed]
}

func (s *stats) record(host string, isTLS, psk bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perHost == nil {
		s.perHost = map[string][2]int{}
	}
	if !isTLS {
		s.notTLS++
		return
	}
	v := s.perHost[host]
	if psk {
		s.resumed++
		v[1]++
	} else {
		s.full++
		v[0]++
	}
	s.perHost[host] = v
}

// hasPSK reports whether a ClientHello record carries pre_shared_key (ext 41).
func hasPSK(rec []byte) (isTLS, psk bool) {
	if len(rec) < 6 || rec[0] != 0x16 {
		return false, false
	}
	b := rec[5:]
	if len(b) < 4 || b[0] != 0x01 {
		return false, false
	}
	p := 4 + 2 + 32
	if p >= len(b) {
		return true, false
	}
	p += 1 + int(b[p])
	if p+2 > len(b) {
		return true, false
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	if p >= len(b) {
		return true, false
	}
	p += 1 + int(b[p])
	if p+2 > len(b) {
		return true, false
	}
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	p += 2
	for p+4 <= end && p+4 <= len(b) {
		id := binary.BigEndian.Uint16(b[p : p+2])
		ln := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		if id == 41 {
			return true, true
		}
		p += 4 + ln
	}
	return true, false
}

func handle(cw net.Conn, host string, st *stats) {
	defer cw.Close()
	up, err := net.DialTimeout("tcp", host, 8*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	cw.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go io.Copy(cw, up)

	var buf []byte
	seen := false
	b := make([]byte, 32*1024)
	for {
		cw.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := cw.Read(b)
		if n > 0 {
			if !seen {
				buf = append(buf, b[:n]...)
				if len(buf) >= 5 {
					rl := int(binary.BigEndian.Uint16(buf[3:5]))
					if len(buf) >= 5+rl || len(buf) > 4096 {
						seen = true
						isTLS, psk := hasPSK(buf)
						st.record(strings.Split(host, ":")[0], isTLS, psk)
					}
				}
			}
			if _, err := up.Write(b[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func main() {
	addr := "127.0.0.1:18500"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	st := &stats{}

	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				return
			}
			go handle(conn, r.Host, st)
		}),
	}

	// report on SIGTERM-ish: print when stdin closes or after the deadline
	go func() {
		bufio.NewReader(os.Stdin).ReadString('\n')
		report(st)
		os.Exit(0)
	}()
	go func() {
		time.Sleep(15 * time.Minute)
		report(st)
		os.Exit(0)
	}()
	fmt.Printf("CONNECT proxy on %s — point Chrome at it\n", addr)
	srv.ListenAndServe()
}

func report(st *stats) {
	st.mu.Lock()
	defer st.mu.Unlock()
	tot := st.full + st.resumed
	fmt.Printf("\n=== TLS connections: %d  (full %d, resumed %d)   non-TLS tunnels: %d\n",
		tot, st.full, st.resumed, st.notTLS)
	if tot > 0 {
		fmt.Printf("=== RESUMPTION SHARE: %.1f%%\n", 100*float64(st.resumed)/float64(tot))
	}
	type row struct {
		h    string
		f, r int
	}
	var rows []row
	for h, v := range st.perHost {
		rows = append(rows, row{h, v[0], v[1]})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].f+rows[i].r > rows[j].f+rows[j].r })
	fmt.Println("--- top origins (full/resumed) ---")
	for i, r := range rows {
		if i >= 15 {
			fmt.Printf("    ... and %d more origins\n", len(rows)-15)
			break
		}
		fmt.Printf("  %-42s %2d / %2d\n", r.h, r.f, r.r)
	}
	fmt.Printf("--- distinct origins contacted: %d\n", len(rows))
}
