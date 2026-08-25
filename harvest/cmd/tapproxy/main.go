// tapproxy records the first TLS record of every client connection and forwards
// the stream verbatim to an upstream TLS server. It exists so byte-exact
// ClientHello capture can be paired with a server that supports features Go's
// crypto/tls does not -- specifically TLS 1.3 0-RTT, which requires the server
// to advertise max_early_data_size in its NewSessionTicket before a browser
// will offer early_data at all.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	mu  sync.Mutex
	out *os.File
	n   int32
)

func handle(c net.Conn, upstream string) {
	defer c.Close()
	u, err := net.Dial("tcp", upstream)
	if err != nil {
		fmt.Println("  upstream:", err)
		return
	}
	defer u.Close()
	id := int(atomic.AddInt32(&n, 1))

	go io.Copy(c, u)

	var buf []byte
	captured := false
	b := make([]byte, 32*1024)
	for {
		c.SetReadDeadline(time.Now().Add(20 * time.Second))
		nr, err := c.Read(b)
		if nr > 0 {
			if !captured {
				buf = append(buf, b[:nr]...)
				if len(buf) >= 5 && buf[0] == 0x16 {
					if rl := int(binary.BigEndian.Uint16(buf[3:5])); len(buf) >= 5+rl {
						captured = true
						rec := buf[:5+rl]
						mu.Lock()
						fmt.Fprintf(out, "%d %s\n", id, hex.EncodeToString(rec))
						out.Sync()
						mu.Unlock()
						extra := len(buf) - len(rec)
						fmt.Printf("  hello #%d: %d bytes (%d more bytes in same flight)\n", id, len(rec), extra)
					}
				}
			}
			if _, err := u.Write(b[:nr]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func main() {
	listen, upstream := os.Args[1], os.Args[2]
	var err error
	out, err = os.Create("testdata/chrome-earlydata.hex")
	if err != nil {
		panic(err)
	}
	defer out.Close()
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		panic(err)
	}
	fmt.Printf("tap %s -> %s\n", listen, upstream)
	go func() { time.Sleep(120 * time.Second); fmt.Println("(timeout)"); os.Exit(0) }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(c, upstream)
	}
}
