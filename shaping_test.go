package twiddle

import (
	"net"
	"testing"
)

// TestPadderLandsOnMeasuredModes: every padded record must have a wire length
// that actually occurs in real browsing traffic.
func TestPadderLandsOnMeasuredModes(t *testing.T) {
	for _, isServer := range []bool{false, true} {
		modes := clientModes
		if isServer {
			modes = serverModes
		}
		allowed := map[int]bool{}
		for _, m := range modes {
			allowed[m] = true
		}
		p := BrowsingPadder(isServer)
		for payload := 0; payload <= 2000; payload++ {
			inner := p(payload)
			if inner < payload+1 {
				t.Fatalf("padder shrank payload %d to %d", payload, inner)
			}
			wire := inner + recordOverhead
			if wire > modes[len(modes)-1] {
				continue // beyond the largest mode; left alone by design
			}
			if !allowed[wire] {
				t.Fatalf("isServer=%v payload %d -> wire %d, not a measured mode", isServer, payload, wire)
			}
		}
	}
}

func TestPadderNeverShrinks(t *testing.T) {
	for _, p := range []Padder{BrowsingPadder(false), BrowsingPadder(true), JitteredPadder(true, 8)} {
		for payload := 0; payload < 20000; payload += 7 {
			if got := p(payload); got < payload+1 {
				t.Fatalf("payload %d padded to %d", payload, got)
			}
		}
	}
}

// TestShapedRecordsOnTheWire checks the actual bytes: a small write must produce
// a record whose length is a measured mode, not a length that tracks the payload.
func TestShapedRecordsOnTheWire(t *testing.T) {
	k := ticketKey(t)
	cred, _ := k.Issue(1, DefaultTicketLen)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	srv := make(chan *Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srv <- nil
			return
		}
		sc, err := Server(c, ServerConfig{TicketKey: k, Padder: BrowsingPadder(true)})
		if err != nil {
			srv <- nil
			return
		}
		srv <- sc
	}()
	raw, _ := net.Dial("tcp", ln.Addr().String())
	cc, _, err := Client(raw, ClientConfig{Pool: pool(t), Credential: cred, Padder: BrowsingPadder(false)})
	if err != nil {
		t.Fatal(err)
	}
	sc := <-srv
	if sc == nil {
		t.Fatal("server side failed")
	}

	// tap the raw stream to see record lengths as a censor would
	seen := make(chan int, 4)
	go func() {
		hdr := make([]byte, 5)
		for {
			if _, err := readFull(raw, hdr); err != nil {
				return
			}
			n := int(hdr[3])<<8 | int(hdr[4])
			body := make([]byte, n)
			if _, err := readFull(raw, body); err != nil {
				return
			}
			seen <- n
		}
	}()
	_ = cc
	if _, err := sc.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	got := <-seen
	allowed := map[int]bool{}
	for _, m := range serverModes {
		allowed[m] = true
	}
	if !allowed[got] {
		t.Errorf("2-byte write produced a %d-byte record, not a measured mode", got)
	}
	t.Logf("a 2-byte payload went out as a %d-byte record (measured server mode)", got)
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
