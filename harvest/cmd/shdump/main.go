// shdump captures a real server's ServerHello and prints its exact field
// layout, so a synthesised one can be matched byte budget for byte budget.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	tls "github.com/metacubex/utls"
)

type tap struct {
	net.Conn
	buf  []byte
	done bool
}

func (c *tap) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && !c.done {
		c.buf = append(c.buf, b[:n]...)
		if len(c.buf) >= 5 {
			if rl := int(binary.BigEndian.Uint16(c.buf[3:5])); len(c.buf) >= 5+rl {
				c.done = true
			}
		}
	}
	return n, err
}

func dump(host string) {
	cache := tls.NewLRUClientSessionCache(4)
	for pass := 0; pass < 2; pass++ {
		label := "FULL handshake"
		if pass == 1 {
			label = "RESUMED handshake"
		}
		fmt.Printf("  --- %s ---\n", label)
		dumpOne(host, cache)
	}
}

func dumpOne(host string, cache tls.ClientSessionCache) {
	raw, err := net.DialTimeout("tcp", host+":443", 8*time.Second)
	if err != nil {
		fmt.Println("  dial:", err)
		return
	}
	defer raw.Close()
	tp := &tap{Conn: raw}
	c := tls.UClient(tp, &tls.Config{ServerName: host, ClientSessionCache: cache}, tls.HelloChrome_Auto)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := c.Handshake(); err == nil {
		st := c.ConnectionState()
		defer func() { fmt.Printf("    -> DidResume=%v\n", st.DidResume) }()
		c.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"))
		io.Copy(io.Discard, io.LimitReader(c, 4096))
	}

	rec := tp.buf
	if len(rec) < 9 || rec[0] != 0x16 || rec[5] != 0x02 {
		fmt.Printf("  no ServerHello captured (%d bytes, first=%x)\n", len(rec), rec[:min(4, len(rec))])
		return
	}
	rl := int(binary.BigEndian.Uint16(rec[3:5]))
	rec = rec[:5+rl]
	fmt.Printf("  RECORD total %d  (header 5 + handshake %d)\n", len(rec), rl)

	b := rec[9:]
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
	for p+4 <= end {
		t := binary.BigEndian.Uint16(b[p : p+2])
		n := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		name := map[uint16]string{0x002b: "supported_versions", 0x0033: "key_share", 0x0029: "pre_shared_key", 0x0000: "server_name"}[t]
		if name == "" {
			name = fmt.Sprintf("%#04x", t)
		}
		fmt.Printf("      %-20s ext %4d  (4 hdr + %d data)", name, 4+n, n)
		if t == 0x0033 && n >= 4 {
			g := binary.BigEndian.Uint16(b[p+4 : p+6])
			kl := int(binary.BigEndian.Uint16(b[p+6 : p+8]))
			fmt.Printf("   group %#04x, key %d B", g, kl)
		}
		fmt.Println()
		p += 4 + n
	}
}

func min(a, b int) int { if a < b { return a }; return b }

func main() {
	hosts := os.Args[1:]
	if len(hosts) == 0 {
		hosts = []string{"www.google.com", "www.cloudflare.com", "www.microsoft.com", "www.amazon.com"}
	}
	for _, h := range hosts {
		fmt.Printf("\n=== %s\n", h)
		dump(h)
	}
}
