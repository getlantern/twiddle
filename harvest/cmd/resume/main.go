// Measure TLS 1.3 session resumption: do a full handshake to a real server,
// collect the NewSessionTicket, then reconnect and capture the resumption
// ClientHello. Reports how big the PSK extension is -- i.e. how much opaque,
// censor-unverifiable space a resumption hello hands us.
package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
)

// tap records the first TLS record written by the client
type tap struct {
	net.Conn
	first []byte
	done  bool
}

func (t *tap) Write(b []byte) (int, error) {
	if !t.done && len(b) > 5 && b[0] == 0x16 {
		t.first = append([]byte{}, b...)
		t.done = true
	}
	return t.Conn.Write(b)
}

func extSizes(rec []byte) (total int, exts map[uint16]int, order []uint16) {
	exts = map[uint16]int{}
	if len(rec) < 6 {
		return
	}
	b := rec[5:]
	total = len(rec)
	p := 4 + 2 + 32
	if p >= len(b) {
		return
	}
	p += 1 + int(b[p])
	if p+2 > len(b) {
		return
	}
	cl := int(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2 + cl
	if p >= len(b) {
		return
	}
	p += 1 + int(b[p])
	if p+2 > len(b) {
		return
	}
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	p += 2
	for p+4 <= end && p+4 <= len(b) {
		id := binary.BigEndian.Uint16(b[p : p+2])
		ln := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		exts[id] = ln
		order = append(order, id)
		p += 4 + ln
	}
	return
}

// extData returns the raw extension_data for one extension id
func extData(rec []byte, want uint16) []byte {
	if len(rec) < 6 {
		return nil
	}
	b := rec[5:]
	p := 4 + 2 + 32
	if p >= len(b) {
		return nil
	}
	p += 1 + int(b[p])
	if p+2 > len(b) {
		return nil
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	if p >= len(b) {
		return nil
	}
	p += 1 + int(b[p])
	if p+2 > len(b) {
		return nil
	}
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	p += 2
	for p+4 <= end && p+4 <= len(b) {
		id := binary.BigEndian.Uint16(b[p : p+2])
		ln := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		if id == want && p+4+ln <= len(b) {
			return b[p+4 : p+4+ln]
		}
		p += 4 + ln
	}
	return nil
}

// dumpPSK parses the OfferedPsks structure exactly: identities (opaque ticket +
// obfuscated_ticket_age) followed by binders. Both are opaque to any observer
// without the resumption secret.
func dumpPSK(d []byte) {
	if len(d) < 2 {
		return
	}
	idsEnd := 2 + int(binary.BigEndian.Uint16(d[0:2]))
	p := 2
	n := 0
	for p+2 <= idsEnd && p+2 <= len(d) {
		tl := int(binary.BigEndian.Uint16(d[p : p+2]))
		p += 2
		if p+tl+4 > len(d) {
			break
		}
		age := binary.BigEndian.Uint32(d[p+tl : p+tl+4])
		fmt.Printf("     identity[%d]: ticket %d B, obfuscated_ticket_age 0x%08x\n", n, tl, age)
		p += tl + 4
		n++
	}
	if idsEnd+2 > len(d) {
		return
	}
	bEnd := idsEnd + 2 + int(binary.BigEndian.Uint16(d[idsEnd:idsEnd+2]))
	p = idsEnd + 2
	for m := 0; p < bEnd && p < len(d); m++ {
		bl := int(d[p])
		fmt.Printf("     binder[%d]:   %d B  (HMAC over truncated ClientHello -- unverifiable without the PSK)\n", m, bl)
		p += 1 + bl
	}
	fmt.Printf("     framing overhead: %d B\n", len(d)-(idsEnd-2)-(bEnd-idsEnd-2))
}

func run(host string) {
	cache := tls.NewLRUClientSessionCache(8)
	var full, resumed []byte
	var didResume bool

	for i := 0; i < 2; i++ {
		raw, err := net.DialTimeout("tcp", host+":443", 6*time.Second)
		if err != nil {
			fmt.Println("  dial:", err)
			return
		}
		tp := &tap{Conn: raw}
		c := tls.Client(tp, &tls.Config{
			ServerName:         host,
			ClientSessionCache: cache,
			MinVersion:         tls.VersionTLS13,
		})
		c.SetDeadline(time.Now().Add(8 * time.Second))
		if err := c.Handshake(); err != nil {
			fmt.Println("  handshake:", err)
			raw.Close()
			return
		}
		st := c.ConnectionState()
		if i == 0 {
			full = tp.first
			// read a little so NewSessionTicket arrives
			c.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"))
			buf := make([]byte, 4096)
			c.Read(buf)
		} else {
			resumed = tp.first
			didResume = st.DidResume
		}
		c.Close()
		raw.Close()
		time.Sleep(300 * time.Millisecond)
	}

	if full == nil || resumed == nil {
		fmt.Println("  incomplete")
		return
	}
	ft, fe, _ := extSizes(full)
	rt, re, ro := extSizes(resumed)
	fmt.Printf("  full handshake hello : %4d bytes, %d extensions\n", ft, len(fe))
	fmt.Printf("  resumption hello     : %4d bytes, %d extensions   (DidResume=%v)\n", rt, len(re), didResume)
	fmt.Printf("  delta                : %+d bytes\n", rt-ft)
	if psk, ok := re[0x0029]; ok {
		fmt.Printf("  pre_shared_key (0x0029) = %d bytes", psk)
		if len(ro) > 0 && ro[len(ro)-1] == 0x0029 {
			fmt.Printf("  [LAST extension, as required]")
		}
		fmt.Println()
		if d := extData(resumed, 0x0029); d != nil {
			dumpPSK(d)
		}
	} else {
		fmt.Println("  no pre_shared_key in second hello — server did not issue a usable ticket")
	}
	for _, id := range []uint16{0x002d, 0x002a} {
		if v, ok := re[id]; ok {
			n := map[uint16]string{0x002d: "psk_key_exchange_modes", 0x002a: "early_data"}[id]
			fmt.Printf("  %s (0x%04x) present, %d bytes\n", n, id, v)
		}
	}
}

func main() {
	hosts := os.Args[1:]
	if len(hosts) == 0 {
		hosts = []string{"www.google.com", "www.cloudflare.com", "www.microsoft.com", "github.com"}
	}
	for _, h := range hosts {
		fmt.Printf("\n=== %s\n", h)
		run(h)
	}
}
