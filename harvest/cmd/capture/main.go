// A locally-trusted TLS 1.3 server that records the raw ClientHello of every
// connection it accepts, so a real browser's full-handshake hello and its
// resumption hello can be compared byte for byte.
//
// Keep-alives are disabled and ALPN is restricted to http/1.1 so that each
// fetch from the page below opens a fresh TCP connection -- and therefore a
// fresh handshake, which is what makes the resumption hello observable.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type ctxKey struct{}

var (
	mu  sync.Mutex
	out *os.File
)

func save(id int, rec []byte) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Fprintf(out, "%d %s\n", id, hex.EncodeToString(rec))
	out.Sync()
	fmt.Printf("  captured hello #%d: %d bytes\n", id, len(rec))
}

type tapConn struct {
	net.Conn
	id       int
	buf      []byte
	captured bool
}

func (c *tapConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if !c.captured && n > 0 {
		c.buf = append(c.buf, b[:n]...)
		if len(c.buf) >= 5 && c.buf[0] == 0x16 {
			if rl := int(binary.BigEndian.Uint16(c.buf[3:5])); len(c.buf) >= 5+rl {
				c.captured = true
				save(c.id, c.buf[:5+rl])
			}
		}
	}
	return n, err
}

type tapListener struct {
	net.Listener
	n int32
}

func (l *tapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tapConn{Conn: c, id: int(atomic.AddInt32(&l.n, 1))}, nil
}

const page = `<!doctype html><meta charset=utf-8><title>hello capture</title>
<style>body{font:14px ui-monospace,monospace;padding:2rem;background:#111;color:#ddd}</style>
<h3>capturing</h3>
<img src=/p1><img src=/p2><img src=/p3><img src=/p4>
<img src=/p5><img src=/p6><img src=/p7><img src=/p8>
<p>done - return to the terminal</p>
`

func main() {
	port := "18443"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}
	var err error
	outPath := "testdata/chrome-hellos.hex"
	if len(os.Args) > 2 {
		outPath = os.Args[2]
	}
	out, err = os.Create(outPath)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	cert, err := tls.LoadX509KeyPair("testdata/localhost+2.pem", "testdata/localhost+2-key.pem")
	if err != nil {
		panic(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		panic(err)
	}
	tl := tls.NewListener(&tapListener{Listener: ln}, cfg)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		id, _ := r.Context().Value(ctxKey{}).(int)
		if r.TLS != nil {
			fmt.Printf("  conn #%d  %s  DidResume=%v\n", id, r.URL.Path, r.TLS.DidResume)
			mu.Lock()
			fmt.Fprintf(out, "# conn %d resumed=%v path=%s\n", id, r.TLS.DidResume, r.URL.Path)
			out.Sync()
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/" {
			fmt.Fprint(w, page)
			return
		}
		fmt.Fprint(w, "ok")
	})

	srv := &http.Server{
		Handler: mux,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				if tp, ok := tc.NetConn().(*tapConn); ok {
					return context.WithValue(ctx, ctxKey{}, tp.id)
				}
			}
			return ctx
		},
	}
	srv.SetKeepAlivesEnabled(false)

	fmt.Printf("listening on https://localhost:%s/  — open it in Chrome\n", port)
	go func() { time.Sleep(90 * time.Second); fmt.Println("\n(90s elapsed)"); os.Exit(0) }()
	srv.Serve(tl)
}
