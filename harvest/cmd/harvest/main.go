// Harvest a ClientHello from site A, retarget it to site B with a chosen
// authenticator injected, and diff against what the browser ACTUALLY sends to B.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	tls "github.com/metacubex/utls"
)

func readRecord(c net.Conn) ([]byte, error) {
	h := make([]byte, 5)
	if _, err := io.ReadFull(c, h); err != nil { return nil, err }
	if h[0] != 0x16 { return nil, fmt.Errorf("not handshake") }
	b := make([]byte, int(binary.BigEndian.Uint16(h[3:5])))
	if _, err := io.ReadFull(c, b); err != nil { return nil, err }
	return append(h, b...), nil
}

func dissect(rec []byte) (ciphers, exts []uint16, sni string) {
	b := rec[5:]
	p := 4 + 2 + 32
	p += 1 + int(b[p])
	cl := int(binary.BigEndian.Uint16(b[p : p+2])); p += 2
	for i := 0; i < cl; i += 2 { ciphers = append(ciphers, binary.BigEndian.Uint16(b[p+i:p+i+2])) }
	p += cl
	p += 1 + int(b[p])
	if p+2 > len(b) { return }
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:p+2])); p += 2
	for p+4 <= end && p+4 <= len(b) {
		id := binary.BigEndian.Uint16(b[p : p+2]); ln := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		exts = append(exts, id)
		if id == 0 && ln > 5 { sni = string(b[p+9 : p+4+ln]) }
		p += 4 + ln
	}
	return
}

func extLens(rec []byte) map[uint16]int {
	m := map[uint16]int{}
	b := rec[5:]
	p := 4 + 2 + 32
	p += 1 + int(b[p])
	cl := int(binary.BigEndian.Uint16(b[p : p+2])); p += 2 + cl
	p += 1 + int(b[p])
	if p+2 > len(b) { return m }
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:p+2])); p += 2
	for p+4 <= end && p+4 <= len(b) {
		id := binary.BigEndian.Uint16(b[p : p+2]); ln := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		if !isGrease(id) { m[id] = ln } else { m[0x0a0a] += ln }
		p += 4 + ln
	}
	return m
}

func isGrease(x uint16) bool { return (x&0x0f0f) == 0x0a0a && (x>>8) == (x&0xff) }
func mask(v []uint16) []uint16 {
	o := make([]uint16, len(v))
	for i, x := range v { if isGrease(x) { o[i] = 0x0a0a } else { o[i] = x } }
	return o
}
func eq(a, b []uint16) bool {
	if len(a) != len(b) { return false }
	for i := range a { if a[i] != b[i] { return false } }
	return true
}
func hx(v []uint16) string {
	s := make([]string, len(v)); for i, x := range v { s[i] = fmt.Sprintf("%04x", x) }
	return strings.Join(s, " ")
}

// build a hello from spec, retargeted to sni, with auth injected into the chosen carrier
func emit(spec *tls.ClientHelloSpec, sni string, auth []byte, carrier string) ([]byte, error) {
	p, _ := net.Pipe()
	u := tls.UClient(p, &tls.Config{ServerName: sni, InsecureSkipVerify: true}, tls.HelloCustom)
	if err := u.ApplyPreset(spec); err != nil { return nil, err }
	if err := u.BuildHandshakeState(); err != nil { return nil, err }
	switch carrier {
	case "random":
		if err := u.SetClientRandom(auth); err != nil { return nil, err }
	case "session_id":
		copy(u.HandshakeState.Hello.SessionId, auth)
	}
	if carrier != "" {
		if err := u.MarshalClientHello(); err != nil { return nil, err }
	}
	o := u.HandshakeState.Hello.Raw
	return append([]byte{0x16, 0x03, 0x01, byte(len(o) >> 8), byte(len(o))}, o...), nil
}

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:8443")
	if err != nil { fmt.Println(err); os.Exit(1) }
	defer ln.Close()
	fmt.Println("LISTENING"); os.Stdout.Sync()

	var caps [][]byte
	for len(caps) < 2 {
		c, err := ln.Accept()
		if err != nil { continue }
		r, err := readRecord(c); c.Close()
		if err != nil { continue }
		_, _, sni := dissect(r)
		if sni == "" { continue }
		if len(caps) == 1 { _, _, s0 := dissect(caps[0]); if s0 == sni { continue } }
		caps = append(caps, r)
		fmt.Printf("  captured #%d  sni=%q  %d bytes\n", len(caps), sni, len(r))
	}

	A, B := caps[0], caps[1]
	_, aExt, aSNI := dissect(A)
	bCip, bExt, bSNI := dissect(B)
	fmt.Printf("\n=== A: sni=%q len=%d   B: sni=%q len=%d   (sni delta %+d)\n",
		aSNI, len(A), bSNI, len(B), len(bSNI)-len(aSNI))
	fmt.Printf("    length delta B-A = %+d\n", len(B)-len(A))

	// which extension accounts for the length delta between A and B?
	la, lb := extLens(A), extLens(B)
	fmt.Println("\n=== per-extension length: chrome->A vs chrome->B")
	seen := map[uint16]bool{}
	var ids []uint16
	for _, x := range aExt { if !seen[x] { seen[x] = true; ids = append(ids, x) } }
	for _, x := range bExt { if !seen[x] { seen[x] = true; ids = append(ids, x) } }
	total := 0
	for _, id := range ids {
		k := id; if isGrease(id) { k = 0x0a0a }
		d := lb[k] - la[k]
		if d != 0 {
			fmt.Printf("    ext 0x%04x  A=%4d  B=%4d  delta=%+d\n", k, la[k], lb[k], d)
			total += d
		}
	}
	fmt.Printf("    ---- extension deltas sum: %+d   (whole-hello delta %+d)\n", total, len(B)-len(A))

	fp := &tls.Fingerprinter{AllowBluntMimicry: true}
	specA, err := fp.FingerprintClientHello(A)
	if err != nil { fmt.Println("fingerprint A:", err); os.Exit(1) }

	auth := make([]byte, 32)
	for i := range auth { auth[i] = byte(0xA0 + i%16) }

	for _, carrier := range []string{"", "random", "session_id"} {
		name := carrier; if name == "" { name = "(none)" }
		fmt.Printf("\n=== harvest A -> retarget to B's SNI, auth carrier = %s\n", name)
		out, err := emit(specA, bSNI, auth, carrier)
		if err != nil { fmt.Println("  emit:", err); continue }
		oCip, oExt, oSNI := dissect(out)
		fmt.Printf("  ours=%d bytes  chrome-to-B=%d bytes  delta=%+d   sni=%q\n",
			len(out), len(B), len(out)-len(B), oSNI)
		fmt.Printf("  cipher order == chrome-to-B: %v\n", eq(mask(oCip), mask(bCip)))
		fmt.Printf("  ext order    == chrome-to-B: %v\n", eq(mask(oExt), mask(bExt)))
		if !eq(mask(oExt), mask(bExt)) {
			fmt.Printf("    chrome: %s\n    ours  : %s\n", hx(mask(bExt)), hx(mask(oExt)))
			fmt.Printf("    (A's order was: %s)\n", hx(mask(aExt)))
		}
		// self-variance over N, then structural divergence vs chrome-to-B
		const N = 16
		vary := make([]bool, len(out))
		lenStable := true
		for k := 0; k < N; k++ {
			o2, err := emit(specA, bSNI, auth, carrier)
			if err != nil || len(o2) != len(out) { lenStable = false; continue }
			for i := range out { if out[i] != o2[i] { vary[i] = true } }
		}
		fmt.Printf("  emission length stable over %d runs: %v\n", N, lenStable)
		if carrier != "" {
			// where did the auth land, and is it stable?
			idx := -1
			for i := 0; i+32 <= len(out); i++ {
				m := true
				for j := 0; j < 32; j++ { if out[i+j] != auth[j] { m = false; break } }
				if m { idx = i; break }
			}
			fmt.Printf("  auth 32B found at offset %d (expected random=11, session_id=44): %v\n",
				idx, idx == 11 || idx == 44)
			stable := idx >= 0
			for j := 0; j < 32 && stable; j++ { if vary[idx+j] { stable = false } }
			fmt.Printf("  auth bytes constant across emissions (not re-randomised): %v\n", stable)
		}
		if len(out) == len(B) {
			st := 0
			for i := range out { if out[i] != B[i] && !vary[i] { st++ } }
			fmt.Printf("  structural divergence vs chrome-to-B: %d bytes\n", st)
		}
	}
}
