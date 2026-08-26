package twiddle

import (
	"crypto/ecdh"
	"math/big"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ErrNotOurs reports that a connection did not authenticate. The sing-box
// adapter forwards these verbatim to the cover site rather than answering --
// under theater we cannot complete a real handshake, so the splitting egress is
// load-bearing rather than optional.
var ErrNotOurs = errors.New("twiddle: connection did not authenticate")

// ClientConfig is what a client needs to open a connection.
type ClientConfig struct {
	// Pool holds harvested ClientHello records. One is chosen per connection.
	Pool [][]byte
	// CoverSNI is the domain this egress masquerades as.
	CoverSNI string
	// Credential is the ticket and psk to present. Replaced after each
	// connection with the one the server issues in its flight.
	Credential *Credential
	BinderLen  int
	Shaper     Shaper
}

// ServerConfig is what an egress needs to accept one.
type ServerConfig struct {
	TicketKey *TicketKey
	MaxAge    time.Duration
	// TicketLen must be stable: a real server's ticket format does not vary.
	TicketLen int
	Shaper    Shaper
}

// Client opens a twiddle connection over raw.
//
// The opening is a harvested Chrome ClientHello with the cover SNI, a fresh
// key_share ephemeral and the ticket authenticator, answered by a synthesised
// ServerHello and an opaque flight. Everything after is the record layer.
func Client(raw net.Conn, cfg ClientConfig) (*Conn, *Credential, error) {
	if len(cfg.Pool) == 0 {
		return nil, nil, errors.New("twiddle: empty hello pool")
	}
	pick, err := rand.Int(rand.Reader, bigLen(len(cfg.Pool)))
	if err != nil {
		return nil, nil, err
	}
	binderLen := cfg.BinderLen
	if binderLen == 0 {
		binderLen = 32
	}

	wire, eph, err := Twiddle(cfg.Pool[pick.Int64()], Options{
		CoverSNI:   cfg.CoverSNI,
		Credential: cfg.Credential,
		BinderLen:  binderLen,
	})
	if err != nil {
		return nil, nil, err
	}
	if _, err := raw.Write(wire); err != nil {
		return nil, nil, err
	}

	sh, err := readRecord(raw)
	if err != nil {
		return nil, nil, err
	}
	serverEph, err := ServerEphemeralFromShare(sh)
	if err != nil {
		return nil, nil, err
	}
	if _, err := readRecord(raw); err != nil { // ChangeCipherSpec
		return nil, nil, err
	}

	shared, err := eph.ECDH(serverEph)
	if err != nil {
		return nil, nil, err
	}
	sess, err := DeriveSession(cfg.Credential.PSK[:], shared, TLS_AES_128_GCM_SHA256)
	if err != nil {
		return nil, nil, err
	}
	conn, err := NewConn(raw, sess, true, cfg.Shaper)
	if err != nil {
		return nil, nil, err
	}

	// The flight carries the next credential, exactly as NewSessionTicket does.
	next, err := readFlight(conn)
	if err != nil {
		return nil, nil, err
	}
	if _, err := raw.Write(ChangeCipherSpec()); err != nil {
		return nil, nil, err
	}
	return conn, next, nil
}

// Server accepts a twiddle connection, or returns ErrNotOurs.
func Server(raw net.Conn, cfg ServerConfig) (*Conn, error) {
	rec, err := readRecord(raw)
	if err != nil {
		return nil, ErrNotOurs
	}
	h, err := ParseClientHello(rec)
	if err != nil {
		return nil, ErrNotOurs
	}
	res, err := VerifyTicketAuth(h, cfg.TicketKey, cfg.MaxAge)
	if err != nil {
		return nil, ErrNotOurs
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sh, err := SynthesizeServerHello(ServerHelloParams{
		SessionIDEcho:   h.SessionID,
		CipherSuite:     TLS_AES_128_GCM_SHA256,
		ServerEphemeral: priv.PublicKey(),
	})
	if err != nil {
		return nil, err
	}
	if _, err := raw.Write(sh); err != nil {
		return nil, err
	}
	if _, err := raw.Write(ChangeCipherSpec()); err != nil {
		return nil, err
	}

	shared, err := priv.ECDH(res.ClientEphemeral)
	if err != nil {
		return nil, err
	}
	sess, err := DeriveSession(res.PSK[:], shared, TLS_AES_128_GCM_SHA256)
	if err != nil {
		return nil, err
	}
	conn, err := NewConn(raw, sess, false, cfg.Shaper)
	if err != nil {
		return nil, err
	}

	ticketLen := cfg.TicketLen
	if ticketLen == 0 {
		ticketLen = DefaultTicketLen
	}
	next, err := cfg.TicketKey.Issue(res.ClientID, ticketLen)
	if err != nil {
		return nil, err
	}
	if err := writeFlight(conn, next); err != nil {
		return nil, err
	}
	if _, err := readRecord(raw); err != nil { // client ChangeCipherSpec
		return nil, err
	}
	return conn, nil
}

// writeFlight sends the encrypted records standing in for the certificate
// flight. A resumed handshake's flight was measured at a near-constant
// 1291-1333 bytes across five real servers, so that is the shape to hit -- and
// the next credential rides inside it for free.
func writeFlight(c *Conn, next *Credential) error {
	body := make([]byte, 0, 2+len(next.Ticket)+32)
	body = appendU16(body, uint16(len(next.Ticket)))
	body = append(body, next.Ticket...)
	body = append(body, next.PSK[:]...)

	target := 1291 + mrand(43)
	if len(body) < target {
		pad := make([]byte, target-len(body))
		if _, err := rand.Read(pad); err != nil {
			return err
		}
		body = append(body, pad...)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(body)))
	_, err := c.Write(append(hdr[:], body...))
	return err
}

func readFlight(c *Conn) (*Credential, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(c, body); err != nil {
		return nil, err
	}
	if len(body) < 2 {
		return nil, errMalformed
	}
	tl := int(binary.BigEndian.Uint16(body[0:2]))
	if 2+tl+32 > len(body) {
		return nil, errMalformed
	}
	cred := &Credential{Ticket: append([]byte(nil), body[2:2+tl]...)}
	copy(cred.PSK[:], body[2+tl:2+tl+32])
	return cred, nil
}

// readRecord reads one complete TLS record, header included.
func readRecord(r io.Reader) ([]byte, error) {
	var hdr [recordHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n > maxCiphertext {
		return nil, fmt.Errorf("twiddle: record length %d out of range", n)
	}
	out := make([]byte, recordHeaderLen+n)
	copy(out, hdr[:])
	if _, err := io.ReadFull(r, out[recordHeaderLen:]); err != nil {
		return nil, err
	}
	return out, nil
}

func bigLen(n int) *big.Int { return big.NewInt(int64(n)) }

// mrand returns a uniform int in [0,n) for shaping jitter.
func mrand(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}
