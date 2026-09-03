package twiddle

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
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
	// Cover is the impersonated identity. Unknown or partial profiles are
	// rejected: a microsoft SNI with a 32-byte binder is a different identity.
	Cover CoverProfile
	// Credential is the ticket and psk to present. Replaced after each
	// connection with the one the server issues as a post-handshake ticket.
	Credential *Credential
	Shaper     Shaper
}

// ServerConfig is what an egress needs to accept one.
type ServerConfig struct {
	TicketKey *TicketKey
	Cover     CoverProfile
	// MaxAge bounds ticket lifetime. Zero means DefaultTicketMaxAge; the check
	// is never skipped on this path.
	MaxAge time.Duration
	// Replay spends tickets atomically. Duplicate tickets take the cover path.
	// It must be shared by every Server call using this TicketKey.
	Replay *ReplayCache
	Shaper Shaper
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
	if err := cfg.Cover.Valid(); err != nil {
		return nil, nil, err
	}
	if cfg.Credential == nil {
		return nil, nil, errors.New("twiddle: missing credential")
	}
	if len(cfg.Credential.Ticket) != cfg.Cover.TicketLen {
		return nil, nil, fmt.Errorf("twiddle: credential ticket length %d does not match cover %d", len(cfg.Credential.Ticket), cfg.Cover.TicketLen)
	}
	pick, err := rand.Int(rand.Reader, bigLen(len(cfg.Pool)))
	if err != nil {
		return nil, nil, err
	}

	wire, eph, err := Twiddle(cfg.Pool[pick.Int64()], Options{
		CoverSNI:   cfg.Cover.Host,
		Credential: cfg.Credential,
		BinderLen:  cfg.Cover.BinderLen,
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
	sess, err := DeriveSession(cfg.Credential.PSK[:], shared, cfg.Cover.CipherSuite)
	if err != nil {
		return nil, nil, err
	}
	conn, err := NewConn(raw, sess, true, cfg.Shaper)
	if err != nil {
		return nil, nil, err
	}

	// Server EncryptedExtensions+Finished stand-in, sized to the measured
	// remainder of the first server burst — not the burst total.
	if _, _, err := conn.consumeRecord(); err != nil {
		return nil, nil, err
	}
	if _, err := raw.Write(ChangeCipherSpec()); err != nil {
		return nil, nil, err
	}
	if err := conn.writeSized(contentHandshake, nil, cfg.Cover.ClientEncryptedWire()); err != nil {
		return nil, nil, err
	}

	// NewSessionTicket arrives after both Finisheds, matching real TLS 1.3
	// timing. Rotating inside the opening burst was how the credential padded
	// that burst to the wrong size.
	next, err := readTickets(conn)
	if err != nil {
		return nil, nil, err
	}
	return conn, next, nil
}

// Server accepts a twiddle connection, or returns ErrNotOurs.
func Server(raw net.Conn, cfg ServerConfig) (*Conn, error) {
	if err := cfg.Cover.Valid(); err != nil {
		return nil, err
	}
	if cfg.Replay == nil {
		return nil, errors.New("twiddle: shared replay cache is required")
	}
	rec, err := readRecord(raw)
	if err != nil {
		return nil, ErrNotOurs
	}
	h, err := ParseClientHello(rec)
	if err != nil {
		return nil, ErrNotOurs
	}
	ticket, err := cfg.Cover.validateClientHello(h)
	if err != nil {
		return nil, ErrNotOurs
	}
	maxAge := cfg.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultTicketMaxAge
	}
	res, err := VerifyTicketAuth(h, cfg.TicketKey, maxAge)
	if err != nil {
		return nil, ErrNotOurs
	}
	if !cfg.Replay.Consume(ticket) {
		return nil, ErrNotOurs
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sh, err := SynthesizeServerHello(ServerHelloParams{
		SessionIDEcho:   h.SessionID,
		CipherSuite:     cfg.Cover.CipherSuite,
		ServerEphemeral: priv.PublicKey(),
		PSKFirst:        cfg.Cover.PSKFirst,
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
	sess, err := DeriveSession(res.PSK[:], shared, cfg.Cover.CipherSuite)
	if err != nil {
		return nil, err
	}
	conn, err := NewConn(raw, sess, false, cfg.Shaper)
	if err != nil {
		return nil, err
	}

	if err := conn.writeSized(contentHandshake, nil, cfg.Cover.ServerEncryptedWire()); err != nil {
		return nil, err
	}
	if _, err := readRecord(raw); err != nil { // client ChangeCipherSpec
		return nil, err
	}
	if _, _, err := conn.consumeRecord(); err != nil { // client Finished stand-in
		return nil, err
	}

	next, err := cfg.TicketKey.Issue(res.ClientID, cfg.Cover.TicketLen)
	if err != nil {
		return nil, err
	}
	if err := writeTickets(conn, next); err != nil {
		return nil, err
	}
	return conn, nil
}

// sessionTicketWire is a plausible NewSessionTicket record. It is sent after
// both Finisheds, so it is outside the Wb=3 opening window the size bug was
// about. Real later bursts also carry application data; matching that volume
// is a later shaping concern.
const sessionTicketWire = 370

func writeTickets(c *Conn, next *Credential) error {
	body := make([]byte, 0, 2+len(next.Ticket)+32)
	body = appendU16(body, uint16(len(next.Ticket)))
	body = append(body, next.Ticket...)
	body = append(body, next.PSK[:]...)
	return c.writeSized(contentHandshake, body, sessionTicketWire)
}

func readTickets(c *Conn) (*Credential, error) {
	typ, body, err := c.consumeRecord()
	if err != nil {
		return nil, err
	}
	if typ != contentHandshake && typ != contentAppData {
		return nil, errMalformed
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
