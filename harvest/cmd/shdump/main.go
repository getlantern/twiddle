// shdump captures a real server's ServerHello and prints its exact field
// layout, so a synthesised one can be matched byte budget for byte budget.
//
// Emits from twiddle's own pool; see harvest/cmd/flight for why. Use
// harvest/cmd/shresume for the full-versus-resumed comparison.
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

func dump(host string, pool [][]byte) {
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
	c, err := net.DialTimeout("tcp", host+":443", 8*time.Second)
	if err != nil {
		fmt.Println("  dial:", err)
		return
	}
	defer c.Close()
	if _, err := c.Write(h.Marshal()); err != nil {
		fmt.Println("  write:", err)
		return
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))

	var hdr [5]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		fmt.Println("  read:", err)
		return
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	body := make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		fmt.Println("  read:", err)
		return
	}
	if hdr[0] != 0x16 || len(body) < 4 || body[0] != 0x02 {
		fmt.Printf("  not a ServerHello (type %#02x)\n", hdr[0])
		return
	}
	fmt.Printf("  RECORD total %d  (header 5 + handshake %d)\n", 5+n, n)

	b := body[4:]
	p := 0
	fmt.Printf("    legacy_version   2   %#04x\n", binary.BigEndian.Uint16(b[p:p+2]))
	p += 2
	fmt.Printf("    random          32\n")
	p += 32
	sl := int(b[p])
	fmt.Printf("    session_id     %3d   (1 len + %d echo)\n", 1+sl, sl)
	p += 1 + sl
	fmt.Printf("    cipher_suite     2   %#04x\n", binary.BigEndian.Uint16(b[p:p+2]))
	p += 2
	fmt.Printf("    compression      1\n")
	p++
	el := int(binary.BigEndian.Uint16(b[p : p+2]))
	fmt.Printf("    extensions_len   2   (block %d)\n", el)
	p += 2
	end := p + el
	for p+4 <= end && p+4 <= len(b) {
		t := binary.BigEndian.Uint16(b[p : p+2])
		n := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		name := map[uint16]string{0x002b: "supported_versions", 0x0033: "key_share", 0x0029: "pre_shared_key"}[t]
		if name == "" {
			name = fmt.Sprintf("%#04x", t)
		}
		fmt.Printf("      %-20s ext %4d  (4 hdr + %d data)", name, 4+n, n)
		if t == 0x0033 && n >= 4 {
			fmt.Printf("   group %#04x, key %d B",
				binary.BigEndian.Uint16(b[p+4:p+6]), int(binary.BigEndian.Uint16(b[p+6:p+8])))
		}
		fmt.Println()
		p += 4 + n
	}
}

func main() {
	hosts := os.Args[1:]
	if len(hosts) == 0 {
		hosts = []string{"www.google.com", "www.cloudflare.com", "www.microsoft.com", "www.amazon.com"}
	}
	pool := twiddle.DefaultPool()
	for _, h := range hosts {
		fmt.Printf("\n=== %s\n", h)
		dump(h, pool)
	}
}
