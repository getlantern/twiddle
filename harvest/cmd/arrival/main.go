// Measures how a real browser's opening flight is PACKETISED, which is the one
// axis the rest of the harvest tooling ignores: every other tool reads a
// complete ClientHello out of a stream and never asks how many writes or
// datagrams carried it.
//
// It matters because twiddle emits its hello with a single Write. That is only
// correct if Chrome does the same, and the answer differs by transport:
//
//	TCP  -- one socket write, segmented by the kernel at the path MSS.
//	QUIC -- the ClientHello does not fit one Initial packet at post-quantum
//	        key sizes, so it spans several, and Chrome's Chaos Protection
//	        deliberately splits and reorders the CRYPTO frames across them.
//
// Run it, then point a browser at the printed addresses. Neither listener ever
// answers, which is all the measurement needs: the client sends its opening
// flight on connect, then retransmits, and the retransmit schedule is itself
// visible in the timings.
//
//	go run ./cmd/arrival
//	# TCP:  open https://127.0.0.1:<tcp port>/
//	# QUIC: chrome --origin-to-force-quic-on=127.0.0.1:<udp port> \
//	#              https://127.0.0.1:<udp port>/
//
// Loopback has a 16384-byte MTU, so the TCP arm does NOT show MSS
// segmentation -- read boundaries there approximate the sender's WRITE
// boundaries, which is the app-level question. Path segmentation is a function
// of MSS and the total hello length, both of which are observable without a
// browser.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

var (
	conns  = flag.Int("conns", 4, "stop after this many TCP connections")
	hexOut = flag.String("hex", "", "append each captured TCP ClientHello to this file as hex")
	wait   = flag.Duration("wait", 30*time.Second, "how long to listen")
)

func main() {
	flag.Parse()

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal(err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		fatal(err)
	}
	fmt.Printf("TCP  https://%s/\n", tcp.Addr())
	fmt.Printf("QUIC --origin-to-force-quic-on=%s\n\n", udp.LocalAddr())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); serveTCP(tcp) }()
	go func() { defer wg.Done(); serveUDP(udp) }()

	time.AfterFunc(*wait, func() { tcp.Close(); udp.Close() })
	wg.Wait()
}

// serveTCP logs one line per Read, so a hello delivered in a single write is
// distinguishable from one the sender split itself.
func serveTCP(ln net.Listener) {
	for i := 1; i <= *conns; i++ {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn, id int) {
			defer c.Close()
			t0 := time.Now()
			var rec []byte
			var reads []string
			tmp := make([]byte, 32*1024)
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			for {
				n, err := c.Read(tmp)
				if n > 0 {
					reads = append(reads, fmt.Sprintf("%dB@%.2fms", n, ms(time.Since(t0))))
					rec = append(rec, tmp[:n]...)
				}
				if len(rec) >= recordHeaderLen {
					if want := recordHeaderLen + int(binary.BigEndian.Uint16(rec[3:5])); len(rec) >= want {
						rec = rec[:want]
						break
					}
				}
				if err != nil {
					break
				}
			}
			if len(rec) < recordHeaderLen {
				return
			}
			fmt.Printf("tcp %d: ClientHello %d B in %d write(s): %v\n",
				id, len(rec), len(reads), reads)
			if *hexOut != "" {
				appendHex(*hexOut, rec)
			}
		}(c, i)
	}
}

// serveUDP logs every datagram with its QUIC long-header packet type, so the
// Initial flight can be counted. Retransmissions are expected and useful --
// nothing here ever answers, so the backoff schedule shows up too.
func serveUDP(c *net.UDPConn) {
	buf := make([]byte, 64*1024)
	var t0 time.Time
	n := 0
	for {
		k, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n == 0 {
			t0 = time.Now()
		}
		n++
		fmt.Printf("udp %d: %4d B  %-9s  from :%d @ %.2fms\n",
			n, k, packetType(buf[:k]), from.Port, ms(time.Since(t0)))
	}
}

// packetType decodes just enough of the QUIC header to name the packet.
func packetType(b []byte) string {
	if len(b) == 0 {
		return "empty"
	}
	if b[0]&0x80 == 0 {
		return "1-RTT"
	}
	switch (b[0] & 0x30) >> 4 {
	case 0:
		return "Initial"
	case 1:
		return "0-RTT"
	case 2:
		return "Handshake"
	default:
		return "Retry"
	}
}

const recordHeaderLen = 5

func appendHex(path string, rec []byte) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer f.Close()
	fmt.Fprintln(f, hex.EncodeToString(rec))
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
