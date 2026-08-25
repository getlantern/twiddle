// Dial a real TLS 1.3 server, send a Chrome ClientHello, and log the raw record
// sequence the server returns. Verifies that everything after ServerHello is
// opaque 0x17, and measures the certificate-flight profile we must imitate.
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

func name(t byte) string {
	switch t {
	case 0x14: return "ChangeCipherSpec"
	case 0x15: return "Alert"
	case 0x16: return "Handshake"
	case 0x17: return "ApplicationData"
	}
	return fmt.Sprintf("0x%02x", t)
}

func probe(host string) {
	c, err := net.DialTimeout("tcp", host+":443", 6*time.Second)
	if err != nil { fmt.Println("  dial:", err); return }
	defer c.Close()

	u := tls.UClient(c, &tls.Config{ServerName: host, InsecureSkipVerify: true}, tls.HelloChrome_Auto)
	if err := u.BuildHandshakeState(); err != nil { fmt.Println("  build:", err); return }
	hello := u.HandshakeState.Hello.Raw
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	if _, err := c.Write(rec); err != nil { fmt.Println("  write:", err); return }
	fmt.Printf("  -> ClientHello %d bytes\n", len(rec))

	c.SetReadDeadline(time.Now().Add(4 * time.Second))
	var n, appBytes, appRecs int
	t0 := time.Now()
	for {
		h := make([]byte, 5)
		if _, err := io.ReadFull(c, h); err != nil { break }
		l := int(binary.BigEndian.Uint16(h[3:5]))
		b := make([]byte, l)
		if _, err := io.ReadFull(c, b); err != nil { break }
		n++
		dt := time.Since(t0)
		if h[0] == 0x17 { appRecs++; appBytes += l }
		fmt.Printf("  <- #%-2d %-16s len=%5d  t=+%dms\n", n, name(h[0]), l, dt.Milliseconds())
		if n >= 12 { break }
	}
	fmt.Printf("  == %d records; the encrypted flight was %d ApplicationData records totalling %d bytes\n",
		n, appRecs, appBytes)
}

func main() {
	hosts := os.Args[1:]
	if len(hosts) == 0 { hosts = []string{"www.google.com", "www.cloudflare.com", "www.microsoft.com"} }
	for _, h := range hosts {
		fmt.Printf("\n=== %s\n", h)
		probe(h)
	}
}
