// flight measures the record profile a real TLS 1.3 server returns: the
// ServerHello, the ChangeCipherSpec, and the encrypted flight that follows.
//
// It emits a hello from twiddle's own pool rather than using a TLS library to
// build one. That is deliberate on two counts: it removes any dependency whose
// output might differ from what we actually ship, and it exercises the emitter
// the transport uses, so a fidelity bug shows up here rather than in the field.
//
// The handshake is never completed. Everything we want arrives before any
// Finished, so a key_share the server cannot agree with costs nothing.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/getlantern/twiddle"
)

func recordName(t byte) string {
	switch t {
	case 0x16:
		return "Handshake"
	case 0x14:
		return "ChangeCipherSpec"
	case 0x17:
		return "ApplicationData"
	case 0x15:
		return "Alert"
	}
	return fmt.Sprintf("0x%02x", t)
}

func run(host string, pool [][]byte) {
	h, err := twiddle.ParseClientHello(pool[0])
	if err != nil {
		fmt.Println("  pool:", err)
		return
	}
	if err := h.SetSNI(host); err != nil {
		fmt.Println("  sni:", err)
		return
	}
	if err := h.Rerandomize(); err != nil {
		fmt.Println("  rerandomize:", err)
		return
	}
	if err := h.Shuffle(); err != nil {
		fmt.Println("  shuffle:", err)
		return
	}
	wire := h.Marshal()

	c, err := net.DialTimeout("tcp", host+":443", 8*time.Second)
	if err != nil {
		fmt.Println("  dial:", err)
		return
	}
	defer c.Close()
	start := time.Now()
	if _, err := c.Write(wire); err != nil {
		fmt.Println("  write:", err)
		return
	}
	fmt.Printf("  -> ClientHello %d bytes\n", len(wire))

	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	for i := 1; ; i++ {
		var hdr [5]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[3:5]))
		if _, err := io.ReadFull(c, make([]byte, n)); err != nil {
			return
		}
		fmt.Printf("  <- #%-2d %-16s len=%5d  t=+%dms\n", i, recordName(hdr[0]), n,
			time.Since(start).Milliseconds())
		if i >= 8 {
			return
		}
	}
}

func main() {
	hosts := os.Args[1:]
	if len(hosts) == 0 {
		hosts = []string{"www.google.com", "www.cloudflare.com", "www.microsoft.com"}
	}
	pool := twiddle.DefaultPool()
	for _, h := range hosts {
		fmt.Printf("\n=== %s\n", h)
		run(h, pool)
	}
}
