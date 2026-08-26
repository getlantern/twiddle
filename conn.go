package twiddle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// The record layer mirrors TLS 1.3's own construction rather than inventing
// framing, because the overhead IS the observable. A real TLS 1.3 record costs
// one content-type byte plus a 16-byte tag and nothing else, so matching it
// exactly means our record lengths are natively TLS-shaped. Any inner header we
// added would offset every record by a fixed amount -- a free structural
// signature. See docs/framing.md.
//
//	record = 0x17 0x03 0x03 ‖ len:u16 ‖ AEAD(key, nonce, aad, inner)
//	nonce  = static_iv XOR seq64          -- never on the wire
//	aad    = the 5-byte record header      -- binds the length
//	inner  = payload ‖ content_type:1 ‖ zeros(padding)

const (
	recordHeaderLen = 5
	// maxPlaintext is the largest content a record may carry. TLSInnerPlaintext
	// adds the content-type byte on top, so inner tops out at maxPlaintext+1 and
	// the wire record at maxPlaintext+1+16 = 16401 -- which is exactly the
	// max-size mode observed in real traffic.
	maxPlaintext  = 1 << 14
	maxInner      = maxPlaintext + 1
	maxCiphertext = maxPlaintext + 256
	contentAppData   = 0x17
	contentAlert     = 0x15
	contentHandshake = 0x16
)

// Keys is one direction's traffic secret material.
type Keys struct {
	Key []byte
	IV  [12]byte
}

// Session holds both directions' keys.
type Session struct {
	Client, Server Keys
	Suite          uint16
}

// DeriveSession builds traffic keys from the pre-shared key and the ECDH shared
// secret. Authentication comes from the psk and forward secrecy from the DH --
// the same division of labour as TLS 1.3 psk_dhe_ke.
func DeriveSession(psk, shared []byte, suite uint16) (*Session, error) {
	var newHash func() hash.Hash
	var keyLen int
	switch suite {
	case TLS_AES_128_GCM_SHA256:
		newHash, keyLen = sha256.New, 16
	case TLS_AES_256_GCM_SHA384:
		newHash, keyLen = sha512.New384, 32
	default:
		return nil, fmt.Errorf("twiddle: unsupported cipher suite %#04x", suite)
	}
	s := &Session{Suite: suite}
	for _, d := range []struct {
		label string
		out   *Keys
	}{
		{"twiddle c ap traffic", &s.Client},
		{"twiddle s ap traffic", &s.Server},
	} {
		d.out.Key = make([]byte, keyLen)
		r := hkdf.New(newHash, shared, psk, []byte(d.label))
		if _, err := io.ReadFull(r, d.out.Key); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(r, d.out.IV[:]); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (k Keys) aead() (cipher.AEAD, error) {
	b, err := aes.NewCipher(k.Key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Padder chooses the padded inner length for a record carrying n payload bytes.
// It is the shaping layer's hook: record sizes and timing are the entire
// observable, so this is where traffic-analysis resistance lives or dies.
// The default adds nothing.
type Padder func(payload int) int

// Conn is an authenticated, encrypted stream framed as TLS application_data.
type Conn struct {
	raw net.Conn

	wmu     sync.Mutex
	send    cipher.AEAD
	sendIV  [12]byte
	sendSeq uint64
	pad     Padder

	rmu     sync.Mutex
	recv    cipher.AEAD
	recvIV  [12]byte
	recvSeq uint64
	pending []byte
	rerr    error
}

// NewConn wraps raw. isClient selects which direction's keys are used to send.
func NewConn(raw net.Conn, s *Session, isClient bool, pad Padder) (*Conn, error) {
	sendKeys, recvKeys := s.Client, s.Server
	if !isClient {
		sendKeys, recvKeys = s.Server, s.Client
	}
	sa, err := sendKeys.aead()
	if err != nil {
		return nil, err
	}
	ra, err := recvKeys.aead()
	if err != nil {
		return nil, err
	}
	return &Conn{
		raw: raw, send: sa, sendIV: sendKeys.IV,
		recv: ra, recvIV: recvKeys.IV, pad: pad,
	}, nil
}

func nonceFor(iv [12]byte, seq uint64) []byte {
	n := make([]byte, 12)
	copy(n, iv[:])
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	for i := 0; i < 8; i++ {
		n[4+i] ^= s[i]
	}
	return n
}

func (c *Conn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(b) > 0 {
		n := len(b)
		if n > maxPlaintext {
			n = maxPlaintext
		}
		if err := c.writeRecord(contentAppData, b[:n]); err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}

func (c *Conn) writeRecord(typ byte, payload []byte) error {
	inner := make([]byte, 0, len(payload)+1)
	inner = append(inner, payload...)
	inner = append(inner, typ)
	if c.pad != nil {
		if target := c.pad(len(payload)); target > len(inner) && target <= maxInner {
			inner = append(inner, make([]byte, target-len(inner))...)
		}
	}

	hdr := []byte{contentAppData, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(inner)+c.send.Overhead()))
	out := make([]byte, 0, recordHeaderLen+len(inner)+c.send.Overhead())
	out = append(out, hdr...)
	out = c.send.Seal(out, nonceFor(c.sendIV, c.sendSeq), inner, hdr)
	c.sendSeq++
	_, err := c.raw.Write(out)
	return err
}

func (c *Conn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		if err := c.readRecord(); err != nil {
			c.rerr = err
			if len(c.pending) == 0 {
				return 0, err
			}
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *Conn) readRecord() error {
	var hdr [recordHeaderLen]byte
	if _, err := io.ReadFull(c.raw, hdr[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n > maxCiphertext || n < c.recv.Overhead() {
		return fmt.Errorf("twiddle: implausible record length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.raw, buf); err != nil {
		return err
	}
	inner, err := c.recv.Open(buf[:0], nonceFor(c.recvIV, c.recvSeq), buf, hdr[:])
	if err != nil {
		return errors.New("twiddle: record failed to decrypt")
	}
	c.recvSeq++

	// strip zero padding, then the content type -- TLS 1.3's own layout
	i := len(inner) - 1
	for i >= 0 && inner[i] == 0 {
		i--
	}
	if i < 0 {
		return errors.New("twiddle: record has no content type")
	}
	switch inner[i] {
	case contentAppData:
		c.pending = append(c.pending, inner[:i]...)
	case contentAlert:
		return io.EOF
	default:
		// handshake or unknown inner types are not carried post-opening
	}
	return nil
}

func (c *Conn) Close() error                       { return c.raw.Close() }
func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
