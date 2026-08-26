// shresume measures how a real server's ServerHello changes between a full and
// a resumed handshake. The absolute size depends on the client's offered groups,
// so what matters here is the DELTA: a resumed ServerHello must carry
// pre_shared_key to name the identity it accepted, and nothing else changes.
package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"
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

func exts(rec []byte) (total int, list []string, hasPSK bool) {
	if len(rec) < 9 || rec[5] != 0x02 {
		return 0, nil, false
	}
	rl := int(binary.BigEndian.Uint16(rec[3:5]))
	total = 5 + rl
	b := rec[9:]
	p := 2 + 32
	p += 1 + int(b[p])
	p += 3
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	p += 2
	for p+4 <= end && p+4 <= len(b) {
		t := binary.BigEndian.Uint16(b[p : p+2])
		n := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		name := map[uint16]string{0x002b: "supported_versions", 0x0033: "key_share", 0x0029: "pre_shared_key"}[t]
		if name == "" {
			name = fmt.Sprintf("%#04x", t)
		}
		list = append(list, fmt.Sprintf("%s(%d)", name, 4+n))
		if t == 0x0029 {
			hasPSK = true
		}
		p += 4 + n
	}
	return total, list, hasPSK
}

func run(host string) {
	cache := tls.NewLRUClientSessionCache(8)
	var sizes [2]int
	for i := 0; i < 2; i++ {
		raw, err := net.DialTimeout("tcp", host+":443", 8*time.Second)
		if err != nil {
			fmt.Println("  dial:", err)
			return
		}
		tp := &tap{Conn: raw}
		c := tls.Client(tp, &tls.Config{ServerName: host, ClientSessionCache: cache, MinVersion: tls.VersionTLS13})
		c.SetDeadline(time.Now().Add(10 * time.Second))
		if err := c.Handshake(); err != nil {
			fmt.Println("  handshake:", err)
			raw.Close()
			return
		}
		c.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"))
		io.Copy(io.Discard, io.LimitReader(c, 8192))
		total, list, psk := exts(tp.buf)
		sizes[i] = total
		kind := "full   "
		if i == 1 {
			kind = "resumed"
		}
		fmt.Printf("  %s  ServerHello %4d B   pre_shared_key=%-5v  exts: %v\n", kind, total, psk, list)
		c.Close()
		raw.Close()
		time.Sleep(300 * time.Millisecond)
	}
	if sizes[0] > 0 && sizes[1] > 0 {
		fmt.Printf("  >> delta full -> resumed: %+d bytes\n", sizes[1]-sizes[0])
	}
}

func main() {
	hosts := os.Args[1:]
	if len(hosts) == 0 {
		hosts = []string{"www.google.com", "www.cloudflare.com", "www.microsoft.com", "www.amazon.com", "www.wikipedia.org"}
	}
	for _, h := range hosts {
		fmt.Printf("\n=== %s\n", h)
		run(h)
	}
}
