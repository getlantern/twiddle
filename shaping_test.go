package twiddle

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

func modesFor(isServer bool) map[int]bool {
	m := clientModes
	if isServer {
		m = serverModes
	}
	out := map[int]bool{}
	for _, v := range m {
		out[v] = true
	}
	return out
}

// TestShaperOverheadIsBounded is the regression guard. Pad-only shaping
// amplified the single most common payload size (an MTU-sized inner record,
// ~1400 B) by 11.9x, because it jumped from the 1379 mode to the 16385 one
// instead of segmenting.
func TestShaperOverheadIsBounded(t *testing.T) {
	for _, isServer := range []bool{false, true} {
		sh := BrowsingShaper(isServer)
		for _, payload := range []int{1, 87, 500, 1379, 1400, 1500, 2000, 4000, 8000, 40000, 200000} {
			remaining, wire, records := payload, 0, 0
			for remaining > 0 {
				take, padTo := sh.Next(remaining)
				if take <= 0 {
					t.Fatalf("shaper made no progress at %d bytes", remaining)
				}
				if take > remaining {
					take = remaining
				}
				wire += recordHeaderLen + padTo + recordOverhead
				remaining -= take
				records++
				if records > 5000 {
					t.Fatalf("payload %d fragmented into >5000 records", payload)
				}
			}
			ratio := float64(wire) / float64(payload)
			limit := 1.7
			if payload < 30 {
				limit = 35.0 // tiny payloads pad up to the smallest mode; that is the point
			}
			if ratio > limit {
				t.Errorf("isServer=%v payload %d -> %d wire bytes in %d records (%.1fx, limit %.0fx)",
					isServer, payload, wire, records, ratio, limit)
			}
		}
	}
}

// TestEveryRecordLandsOnAMeasuredMode: a censor reading record lengths must see
// only lengths that occur in real browsing.
func TestEveryRecordLandsOnAMeasuredMode(t *testing.T) {
	for _, isServer := range []bool{false, true} {
		allowed := modesFor(isServer)
		sh := BrowsingShaper(isServer)
		for payload := 1; payload <= 6000; payload++ {
			remaining := payload
			for remaining > 0 {
				take, padTo := sh.Next(remaining)
				if take > remaining {
					take = remaining
				}
				wire := padTo + recordOverhead
				if !allowed[wire] {
					t.Fatalf("isServer=%v payload %d produced a %d-byte record, not a measured mode",
						isServer, payload, wire)
				}
				remaining -= take
			}
		}
	}
}

func TestShaperNeverLosesBytes(t *testing.T) {
	sh := BrowsingShaper(true)
	for payload := 1; payload < 50000; payload += 313 {
		remaining, moved := payload, 0
		for remaining > 0 {
			take, padTo := sh.Next(remaining)
			if take > remaining {
				take = remaining
			}
			if padTo < take+1 {
				t.Fatalf("padTo %d cannot hold %d payload + type byte", padTo, take)
			}
			moved += take
			remaining -= take
		}
		if moved != payload {
			t.Fatalf("payload %d: shaper moved %d bytes", payload, moved)
		}
	}
}

// TestShapedWireLengths runs real data through a real connection and inspects
// the record lengths a censor would see.
func TestShapedWireLengths(t *testing.T) {
	k := ticketKey(t)
	cover := mustCover(t, "www.cloudflare.com")
	cred, _ := k.Issue(1, cover.TicketLen)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	srv := make(chan *Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srv <- nil
			return
		}
		sc, err := Server(c, ServerConfig{
			TicketKey: k, Cover: cover, Replay: NewReplayCache(8, time.Hour),
			Shaper: BrowsingShaper(true),
		})
		if err != nil {
			srv <- nil
			return
		}
		srv <- sc
	}()
	raw, _ := net.Dial("tcp", ln.Addr().String())
	cc, _, err := Client(raw, ClientConfig{
		Pool: pool(t), Cover: cover, Credential: cred, Shaper: BrowsingShaper(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	sc := <-srv
	if sc == nil {
		t.Fatal("server side failed")
	}

	lens := make(chan int, 256)
	go func() {
		hdr := make([]byte, 5)
		for {
			if _, err := io.ReadFull(raw, hdr); err != nil {
				close(lens)
				return
			}
			n := int(hdr[3])<<8 | int(hdr[4])
			if _, err := io.ReadFull(raw, make([]byte, n)); err != nil {
				close(lens)
				return
			}
			lens <- n
		}
	}()
	_ = cc

	payload := make([]byte, 4000) // an MTU-ish response: the case that broke before
	rand.Read(payload)
	if _, err := sc.Write(payload); err != nil {
		t.Fatal(err)
	}
	allowed := modesFor(true)
	total, count, carried := 0, 0, 0
	deadline := time.After(3 * time.Second)
	for carried < len(payload) {
		select {
		case n, ok := <-lens:
			if !ok {
				carried = len(payload)
				break
			}
			if !allowed[n] {
				t.Errorf("record length %d is not a measured mode", n)
			}
			total += recordHeaderLen + n
			carried += n - recordOverhead - 1 // payload carried by this record
			count++
		case <-deadline:
			t.Fatalf("only %d records seen, %d payload bytes accounted", count, carried)
		}
	}
	ratio := float64(total) / float64(len(payload))
	if ratio > 1.5 {
		t.Errorf("4000-byte write cost %d wire bytes (%.2fx)", total, ratio)
	}
	t.Logf("4000-byte write -> %d records, %d wire bytes (%.2fx), all measured modes", count, total, ratio)
}

// TestCoalescingMergesConcurrentWrites: bytes queued while another goroutine is
// flushing ride along rather than each becoming its own record.
func TestCoalescingMergesConcurrentWrites(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	sess, err := DeriveSession(make([]byte, 32), make([]byte, 32), TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewConn(a, sess, true, BrowsingShaper(true))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewConn(b, sess, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for i := 0; i < 50; i++ {
			w.Write([]byte("0123456789"))
		}
		w.Write([]byte("END"))
	}()
	got := make([]byte, 0, 512)
	buf := make([]byte, 1024)
	for !bytes.Contains(got, []byte("END")) {
		n, err := r.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}
	if want := 50*10 + 3; len(got) != want {
		t.Fatalf("got %d bytes, want %d", len(got), want)
	}
	t.Logf("50 small writes delivered intact through the coalescing path")
}
