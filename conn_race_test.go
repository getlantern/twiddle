package twiddle

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// gateConn records every record handed to the socket and holds the FIRST one
// until the test releases it. Blocking there is what forces the overlap between
// a data flush and close_notify, rather than leaving it to chance.
type gateConn struct {
	net.Conn

	entered chan struct{}
	release chan struct{}

	mu      sync.Mutex
	gated   bool
	records [][]byte
}

func newGateConn() *gateConn {
	return &gateConn{entered: make(chan struct{}), release: make(chan struct{})}
}

func (c *gateConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	first := !c.gated
	c.gated = true
	c.mu.Unlock()
	if first {
		close(c.entered)
		<-c.release
	}
	c.mu.Lock()
	c.records = append(c.records, append([]byte(nil), b...))
	c.mu.Unlock()
	return len(b), nil
}

func (c *gateConn) Close() error { return nil }

func (c *gateConn) wire() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Join(c.records, nil)
}

func (c *gateConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.records)
}

// replayConn serves a fixed byte stream to a peer Conn, so the recorded wire
// can be decrypted exactly as the far end would decrypt it.
type replayConn struct {
	net.Conn
	r *bytes.Reader
}

func (c *replayConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *replayConn) Close() error               { return nil }

func testSession(t *testing.T) *Session {
	t.Helper()
	s, err := DeriveSession(make([]byte, 32), make([]byte, 32), TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A close_notify concurrent with a data flush must not overtake it on the wire.
//
// Write releases wmu around writeRecord so a slow socket cannot block other
// writers; Close reaches writeRecord through writeSized, which takes that freed
// wmu. Before wireMu the two ran concurrently, and because the sequence number
// is the AEAD nonce the peer could not decrypt what came out: it counts
// monotonically, so a record that arrives before the one it was sealed after is
// authenticated against the wrong nonce.
//
// This pins the ordering half deterministically. The other half -- two sealers
// reading the same sendSeq, which is nonce reuse under one key -- is the
// unsynchronised increment, and is what -race reports on the same overlap.
func TestCloseNotifyCannotOvertakeAFlush(t *testing.T) {
	sess := testSession(t)
	gate := newGateConn()
	w, err := NewConn(gate, sess, true, nil)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("application data that must arrive first")
	wrote := make(chan error, 1)
	go func() {
		_, err := w.Write(payload)
		wrote <- err
	}()

	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the data record never reached the socket")
	}

	started := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		close(started)
		_ = w.Close()
		close(closed)
	}()
	<-started

	// The data record is still parked in the socket write, so close_notify must
	// be waiting behind it rather than already on the wire.
	//
	// Proving that it did NOT happen needs a bound, and the bound has to outlast
	// scheduling delay on a loaded machine: too short and a Close that never got
	// to run reads as a Close that correctly waited, which passes for the wrong
	// reason. started only proves the goroutine exists, so the loop also watches
	// the wire itself -- without wireMu, Close's record is not blocked by the
	// gate (only the first write is) and appears there directly, which is the
	// symptom rather than a proxy for it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n := gate.count(); n != 0 {
			t.Fatalf("%d records reached the wire while a flush held it", n)
		}
		select {
		case <-closed:
			t.Fatal("close_notify was emitted while a flush held the wire")
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}

	close(gate.release)
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close never returned")
	}

	// The real assertion: the peer decrypts the recorded wire with its own
	// monotonic counter. Any reordering or nonce reuse fails to authenticate.
	peer, err := NewConn(&replayConn{r: bytes.NewReader(gate.wire())}, sess, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 0, len(payload))
	buf := make([]byte, 512)
	for {
		n, err := peer.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			if err != io.EOF {
				t.Fatalf("peer could not decrypt the recorded wire: %v", err)
			}
			break
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("peer decrypted %q, want %q", got, payload)
	}
	if n := gate.count(); n != 2 {
		t.Fatalf("wire carries %d records, want the data record and close_notify", n)
	}
}

// The same overlap without the gate, so -race sees the unsynchronised sendSeq
// if wireMu is ever removed.
func TestConcurrentWritesAndCloseAreRaceFree(t *testing.T) {
	sess := testSession(t)
	server, client := net.Pipe()
	defer server.Close()
	go func() {
		_, _ = io.Copy(io.Discard, server)
	}()

	w, err := NewConn(client, sess, true, nil)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 32; j++ {
				_, _ = w.Write([]byte("0123456789abcdef"))
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = w.Close()
	}()
	wg.Wait()
}
