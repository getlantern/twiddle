package twiddle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
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
	maxPlaintext     = 1 << 14
	maxInner         = maxPlaintext + 1
	maxCiphertext    = maxPlaintext + 256
	contentAppData   = 0x17
	contentAlert     = 0x15
	contentHandshake = 0x16

	alertWarning     = 0x01
	alertCloseNotify = 0x00

	// closeNotifyWire is what a real endpoint puts on the wire at teardown:
	// 5-byte header + 2-byte alert + 1 inner content type + 16-byte AEAD tag.
	// Measured at exactly 24 B from all three covers, in both AES-128-GCM and
	// AES-256-GCM (harvest/testdata/postflight-resumed.log).
	closeNotifyWire = 24
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

// Transcript is the opening as it went on the wire, in order, and binding it to
// the traffic keys is what makes a tampered ServerHello detectable at all --
// exactly as TLS 1.3's transcript hash does.
//
// Without it the client checked almost nothing about the ServerHello: it pulled
// the X25519 half out of the key_share, did the ECDH, and derived keys from the
// psk and its OWN configured cipher suite. So an on-path attacker could flip a
// byte in legacy_session_id_echo, cipher_suite, legacy_version,
// compression_method, ServerHello.random or the ML-KEM half of the share and
// the client completed the handshake regardless -- while a genuine TLS 1.3
// client aborts, because RFC 8446 4.1.3 requires the session_id echo to match
// and the server Finished MACs the whole transcript.
//
// That gap was an ACTIVE DISTINGUISHER, and a cheap one: flip one byte in a
// ServerHello and watch whether the connection survives. Real TLS dies, we did
// not. It needs no traffic analysis, works on the first connection, and the
// only cost to a censor is breaking the connection it probes. Six of seven
// mutated fields were accepted before this; only the X25519 half was caught,
// and only incidentally, because it breaks the ECDH.
//
// Feeding the transcript into the derivation closes it the way TLS does rather
// than by adding field-by-field checks: ANY difference between what the server
// sent and what the client received produces different keys, so the first
// encrypted record fails to decrypt. Under theater that is the right analogue
// of an alert, since this transport never sends one.
// The arity is FIXED at the three opening records rather than variadic. The
// first version was variadic, reasoning that a record joining the opening later
// could then be added without widening a signature -- which had it backwards. A
// variadic call site can silently drop a record and still compile, weakening the
// binding with nothing to notice, and silent weakening is the exact class of bug
// this change exists to remove. Widening a signature is a compile error at every
// call site, which is the direction that gets looked at.
func Transcript(clientHello, serverHello, changeCipherSpec []byte) []byte {
	t := make([]byte, 0, len(clientHello)+len(serverHello)+len(changeCipherSpec))
	t = append(t, clientHello...)
	t = append(t, serverHello...)
	return append(t, changeCipherSpec...)
}

// DeriveSession builds traffic keys from the pre-shared key, the ECDH shared
// secret, and the opening transcript. Authentication comes from the psk and
// forward secrecy from the DH -- the same division of labour as TLS 1.3
// psk_dhe_ke -- while the transcript is what binds those keys to the opening
// that produced them.
//
// transcript must be Transcript(ClientHello, ServerHello, ChangeCipherSpec)
// over the records as they went on the wire, and an empty one is REFUSED.
//
// Refusing it matters for the same reason Transcript has fixed arity: an
// unbound derivation still compiles and still produces working keys, so a call
// site that lost its transcript would keep passing tests while silently
// reinstating the tampering this exists to stop. There is no legitimate unbound
// caller -- tests that only need a matched key pair supply a fixed transcript
// of their own -- so the case is removed rather than documented.
func DeriveSession(psk, shared []byte, suite uint16, transcript []byte) (*Session, error) {
	if len(transcript) == 0 {
		return nil, errors.New("twiddle: empty transcript; keys must be bound to the opening")
	}
	var keyLen int
	switch suite {
	case TLS_AES_128_GCM_SHA256:
		keyLen = 16
	case TLS_AES_256_GCM_SHA384:
		keyLen = 32
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
		// psk is the salt and the ECDH secret the input keying material, so both
		// must be present to derive traffic keys: authentication from the
		// pre-shared key, forward secrecy from the Diffie-Hellman.
		// The transcript hash rides in the HKDF info alongside the label,
		// which is where TLS 1.3 puts it too: Derive-Secret binds each secret
		// to the handshake messages that produced it.
		var out []byte
		var err error
		if suite == TLS_AES_256_GCM_SHA384 {
			sum := sha512.Sum384(transcript)
			out, err = hkdf.Key(sha512.New384, shared, psk, d.label+string(sum[:]), keyLen+12)
		} else {
			sum := sha256.Sum256(transcript)
			out, err = hkdf.Key(sha256.New, shared, psk, d.label+string(sum[:]), keyLen+12)
		}
		if err != nil {
			return nil, err
		}
		d.out.Key = out[:keyLen]
		copy(d.out.IV[:], out[keyLen:])
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

// Conn is an authenticated, encrypted stream framed as TLS application_data.
type Conn struct {
	raw net.Conn

	wmu      sync.Mutex
	send     cipher.AEAD
	sendIV   [12]byte
	sendSeq  uint64
	shaper   Shaper
	wbuf     []byte
	flushing bool
	werr     error

	// wireMu serializes record emission, covering the seal and the socket write
	// as one step.
	//
	// It cannot be folded into wmu. Write deliberately RELEASES wmu around each
	// writeRecord so a slow socket does not block other writers, and guards
	// re-entry with the flushing flag -- but that flag only excludes Write from
	// Write. Close takes the freed wmu and reaches writeRecord through
	// writeSized, so a close_notify could seal concurrently with a data flush.
	//
	// Both halves of writeRecord need the same lock, and for different reasons.
	// The sequence number IS the AEAD nonce, so two sealers taking the same
	// sendSeq is nonce reuse under one key -- for AES-GCM that is authentication
	// key recovery, not a decrypt failure. And even with distinct numbers the
	// records must reach the wire in that order, because the peer decrypts
	// against its own monotonic counter.
	wireMu sync.Mutex

	// closeOnce guards the close_notify alert: Close may be called more than
	// once, and a second alert would itself be the anomaly.
	closeOnce sync.Once

	rmu     sync.Mutex
	recv    cipher.AEAD
	recvIV  [12]byte
	recvSeq uint64
	pending []byte
	rerr    error

	// fullHandshake records which opening shape this connection used. Set once
	// by Client or Server before the connection is handed out, and read-only
	// after, so it needs no lock.
	fullHandshake bool
}

// FullHandshake reports whether this connection opened with a full handshake
// rather than a resumption.
//
// Exposed for measurement. The point of the full-handshake carrier is to stop
// emitting 100% resumptions (see docs/full-handshake-carrier.md), and the only
// way to know the deployed mix is to count it -- a ContactMemory that silently
// degraded on every connection, because no cover was ever probed, would
// otherwise look exactly like one that was working.
func (c *Conn) FullHandshake() bool { return c.fullHandshake }

// NewConn wraps raw. isClient selects which direction's keys are used to send.
func NewConn(raw net.Conn, s *Session, isClient bool, sh Shaper) (*Conn, error) {
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
	if sh == nil {
		sh = PlainShaper()
	}
	return &Conn{
		raw: raw, send: sa, sendIV: sendKeys.IV,
		recv: ra, recvIV: recvKeys.IV, shaper: sh,
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

// Write queues b and drains the pending buffer through the shaper.
//
// Coalescing is opportunistic and adds NO delay: a caller whose bytes arrive
// while another goroutine is mid-flush simply appends and returns, and the
// in-flight flush carries them. So merging happens under real write pressure and
// not on a clock. That distinction matters -- a fixed flush interval would be
// exactly the "synchronized batching" that flow-physics classifiers key on, and
// the human timing already in the stream is a better defence than any we could
// synthesise (docs/traffic-analysis.md).
//
// A consequence: an error caused by bytes merged into someone else's flush is
// reported to a later Write, as with any buffered writer.
func (c *Conn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	if c.werr != nil {
		err := c.werr
		c.wmu.Unlock()
		return 0, err
	}
	c.wbuf = append(c.wbuf, b...)
	if c.flushing {
		c.wmu.Unlock()
		return len(b), nil
	}
	c.flushing = true
	for len(c.wbuf) > 0 {
		take, padTo := c.shaper.Next(len(c.wbuf))
		if take <= 0 || take > len(c.wbuf) {
			take = len(c.wbuf)
		}
		chunk := append([]byte(nil), c.wbuf[:take]...)
		c.wbuf = c.wbuf[take:]
		c.wmu.Unlock()
		err := c.writeRecord(contentAppData, chunk, padTo)
		c.wmu.Lock()
		if err != nil {
			c.flushing = false
			c.werr = err
			c.wmu.Unlock()
			return 0, err
		}
	}
	c.flushing = false
	c.wmu.Unlock()
	return len(b), nil
}

func (c *Conn) writeRecord(typ byte, payload []byte, padTo int) error {
	c.wireMu.Lock()
	defer c.wireMu.Unlock()

	inner := make([]byte, 0, len(payload)+1)
	inner = append(inner, payload...)
	inner = append(inner, typ)
	if padTo > len(inner) && padTo <= maxInner {
		inner = append(inner, make([]byte, padTo-len(inner))...)
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

// writeSized emits one application_data record of exactly wireLen bytes,
// bypassing the browsing shaper. The opening EncryptedExtensions/Finished
// stand-ins have to hit the measured remainder (64 or 106 B), not a 1395-byte
// browsing mode.
func (c *Conn) writeSized(typ byte, payload []byte, wireLen int) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	padTo := wireLen - recordHeaderLen - c.send.Overhead()
	if padTo < len(payload)+1 {
		return fmt.Errorf("twiddle: wire length %d too small for %d-byte payload", wireLen, len(payload))
	}
	if padTo > maxInner {
		return fmt.Errorf("twiddle: wire length %d exceeds max inner", wireLen)
	}
	return c.writeRecord(typ, payload, padTo)
}

// consumeRecord decrypts the next record and returns its inner content type
// and payload, without queuing application data. Handshake-shaped opening
// records are consumed this way so they never mix with tunnel bytes.
func (c *Conn) consumeRecord() (typ byte, payload []byte, err error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return c.decryptRecord()
}

func (c *Conn) decryptRecord() (byte, []byte, error) {
	var hdr [recordHeaderLen]byte
	if _, err := io.ReadFull(c.raw, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n > maxCiphertext || n < c.recv.Overhead() {
		return 0, nil, fmt.Errorf("twiddle: implausible record length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.raw, buf); err != nil {
		return 0, nil, err
	}
	inner, err := c.recv.Open(buf[:0], nonceFor(c.recvIV, c.recvSeq), buf, hdr[:])
	if err != nil {
		return 0, nil, errors.New("twiddle: record failed to decrypt")
	}
	c.recvSeq++

	i := len(inner) - 1
	for i >= 0 && inner[i] == 0 {
		i--
	}
	if i < 0 {
		return 0, nil, errors.New("twiddle: record has no content type")
	}
	return inner[i], inner[:i], nil
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
	typ, payload, err := c.decryptRecord()
	if err != nil {
		return err
	}
	switch typ {
	case contentAppData:
		c.pending = append(c.pending, payload...)
	case contentAlert:
		return io.EOF
	default:
		// handshake or unknown inner types are not carried post-opening
	}
	return nil
}

// Close sends close_notify, then closes the socket.
//
// Every real TLS 1.3 endpoint measured emits exactly one 24-byte alert record
// at teardown. Closing bare put a sequence on the wire that no TLS endpoint
// produces, on the LAST record of the connection -- which is as cheap for an
// observer to watch as the first, and was the only record of ours that was
// unconditionally wrong.
//
// Best-effort: if the peer is already gone the write fails, and that is not a
// reason to fail Close. Once only, because Close may be called twice and a
// second alert would itself be the anomaly.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.writeSized(contentAlert, []byte{alertWarning, alertCloseNotify}, closeNotifyWire)
	})
	return c.raw.Close()
}

func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
