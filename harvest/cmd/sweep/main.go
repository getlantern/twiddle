// Capture N ClientHellos to the SAME hostname and dump per-extension lengths.
// Decides whether ECH GREASE length is a function of SNI or random per connection.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

func main() {
	ln, _ := net.Listen("tcp", "127.0.0.1:8443")
	defer ln.Close()
	fmt.Println("LISTENING")
	seen := 0
	for seen < 8 {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		h := make([]byte, 5)
		if _, e := io.ReadFull(c, h); e != nil {
			c.Close()
			continue
		}
		b := make([]byte, int(binary.BigEndian.Uint16(h[3:5])))
		io.ReadFull(c, b)
		c.Close()
		if h[0] != 0x16 {
			continue
		}
		p := 4 + 2 + 32
		p += 1 + int(b[p])
		cl := int(binary.BigEndian.Uint16(b[p : p+2]))
		p += 2 + cl
		p += 1 + int(b[p])
		if p+2 > len(b) {
			continue
		}
		end := p + 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
		p += 2
		ech, sni, total := -1, "", len(b)+5
		for p+4 <= end && p+4 <= len(b) {
			id := binary.BigEndian.Uint16(b[p : p+2])
			ln2 := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
			if id == 0xfe0d {
				ech = ln2
			}
			if id == 0 && ln2 > 5 {
				sni = string(b[p+9 : p+4+ln2])
			}
			p += 4 + ln2
		}
		if sni == "" {
			continue
		}
		seen++
		fmt.Printf("  #%d sni=%-42q hello=%4d  ECH(0xfe0d)=%d\n", seen, sni, total, ech)
	}
}
