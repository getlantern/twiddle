// records measures the steady-state TLS record profile of real browsing: the
// size, type, direction and timing of every record on every connection.
//
// This is the input the shaping layer needs. Record sizes and inter-record
// timing are the entire observable of an encrypted tunnel, so a Padder that is
// not fitted to real traffic is guesswork. No decryption is involved -- a TLS
// record header (type, version, length) is cleartext.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type rec struct {
	Dir  string `json:"d"` // "c" client->server, "s" server->client
	Type int    `json:"t"`
	Len  int    `json:"n"`
	Us   int64  `json:"us"`
}

type flow struct {
	Host    string `json:"host"`
	Records []rec  `json:"records"`
}

var (
	mu  sync.Mutex
	out *os.File
)

func emit(f *flow) {
	if len(f.Records) == 0 {
		return
	}
	b, _ := json.Marshal(f)
	mu.Lock()
	fmt.Fprintln(out, string(b))
	out.Sync()
	mu.Unlock()
}

// splitter accumulates a byte stream and emits one entry per complete TLS record.
type splitter struct {
	dir  string
	buf  []byte
	t0   time.Time
	f    *flow
	lock *sync.Mutex
}

func (s *splitter) feed(b []byte) {
	s.buf = append(s.buf, b...)
	for len(s.buf) >= 5 {
		n := int(binary.BigEndian.Uint16(s.buf[3:5]))
		if n > 1<<14+2048 {
			s.buf = nil // not TLS framing; stop tracking this direction
			return
		}
		if len(s.buf) < 5+n {
			return
		}
		s.lock.Lock()
		if len(s.f.Records) < 400 {
			s.f.Records = append(s.f.Records, rec{s.dir, int(s.buf[0]), n, time.Since(s.t0).Microseconds()})
		}
		s.lock.Unlock()
		s.buf = s.buf[5+n:]
	}
}

func pipe(dst io.Writer, src io.Reader, sp *splitter) {
	b := make([]byte, 32*1024)
	for {
		n, err := src.Read(b)
		if n > 0 {
			sp.feed(b[:n])
			if _, werr := dst.Write(b[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func handle(cw net.Conn, host string) {
	defer cw.Close()
	up, err := net.DialTimeout("tcp", host, 8*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	cw.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	f := &flow{Host: strings.Split(host, ":")[0]}
	var lock sync.Mutex
	t0 := time.Now()
	done := make(chan struct{}, 2)
	go func() { pipe(cw, up, &splitter{dir: "s", t0: t0, f: f, lock: &lock}); done <- struct{}{} }()
	go func() { pipe(up, cw, &splitter{dir: "c", t0: t0, f: f, lock: &lock}); done <- struct{}{} }()
	<-done
	cw.Close()
	up.Close()
	<-done
	lock.Lock()
	emit(f)
	lock.Unlock()
}

func main() {
	addr, path := "127.0.0.1:18600", "testdata/records.jsonl"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	if len(os.Args) > 2 {
		path = os.Args[2]
	}
	var err error
	if out, err = os.Create(path); err != nil {
		panic(err)
	}
	defer out.Close()

	go func() { bufio.NewReader(os.Stdin).ReadString('\n'); out.Close(); os.Exit(0) }()
	go func() { time.Sleep(20 * time.Minute); out.Close(); os.Exit(0) }()

	fmt.Printf("CONNECT proxy on %s -> %s\n", addr, path)
	http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		go handle(conn, r.Host)
	}))
}
