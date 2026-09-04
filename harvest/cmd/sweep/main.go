// Capture N ClientHellos to the SAME hostname and dump per-extension lengths.
// Decides whether ECH GREASE length is a function of SNI or random per connection.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	tw "github.com/getlantern/twiddle"
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
		// The error was ignored here, and the hand-rolled parse below indexed
		// b[38] before checking any length -- so a peer sending a short
		// handshake record panicked this tool. It listens on a socket, so
		// "a peer" is anything that can reach it.
		if _, e := io.ReadFull(c, b); e != nil {
			c.Close()
			continue
		}
		c.Close()
		if h[0] != 0x16 {
			continue
		}

		// The library's parser rather than a second hand-rolled one. It
		// validates every fixed-width and length-delimited field, it is what
		// the rest of the repo is tested against, and it is less code than the
		// bounds checks the previous version was missing.
		hello, e := tw.ParseClientHello(append(h, b...))
		if e != nil {
			continue
		}
		sni, total := hello.SNI(), len(h)+len(b)
		ech := -1
		if e := hello.Find(tw.ExtECH); e != nil {
			ech = len(e.Data)
		}
		if sni == "" {
			continue
		}
		seen++
		fmt.Printf("  #%d sni=%-42q hello=%4d  ECH(0xfe0d)=%d\n", seen, sni, total, ech)
	}
}
