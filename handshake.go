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
	// FullHandshake FORCES a full-handshake opening: no pre_shared_key, the
	// ticket in the ECH payload, and a server flight carrying a
	// certificate-sized remainder.
	//
	// It exists because emitting only resumption hellos is itself a
	// distinguisher -- measured at 4.1% of real browsing -- and because a
	// resumption to an address the client was never seen completing a full
	// handshake with is structurally impossible in real TLS. See
	// docs/full-handshake-carrier.md.
	//
	// Prefer Contacts, which decides per connection. Setting this is a hard
	// request: a cover with no measured full profile fails rather than
	// degrading, because a caller who asked for the shape explicitly wants to
	// know it is unavailable.
	FullHandshake bool
	// Contacts, when set, chooses the shape per connection: full on first
	// contact with an egress, resumed afterwards, full again once the censor
	// can no longer be assumed to remember. See ContactMemory.
	//
	// It lives here rather than in the caller so the decision cannot be
	// forgotten, and so recording a completed handshake cannot be missed --
	// both of which fail toward emitting resumptions, the direction that hurts.
	//
	// Nil means today's behaviour: resumption unless FullHandshake is set. That
	// is the only workable default, since the cover table ships no full profile
	// until one has been probed.
	Contacts *ContactMemory
	Shaper   Shaper
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
	// An EXPLICIT request is validated here rather than on the wire, and it
	// fails where a Contacts-driven choice degrades. A client that opened a full
	// handshake against a cover with no measured full profile would get a
	// guessed certificate flight back, which is worse than not offering the
	// shape at all.
	if cfg.FullHandshake {
		if !cfg.Cover.CanEmitFullHandshake() {
			return nil, nil, fmt.Errorf("twiddle: cover %s has no measured full-handshake profile", cfg.Cover.Host)
		}
		if len(FullHandshakeCarriers(cfg.Pool)) == 0 {
			return nil, nil, errors.New("twiddle: no hello in the pool has an ECH payload large enough to carry a full-handshake ticket")
		}
	}

	// raw is dereferenced from here on, so a nil one becomes an error rather
	// than a panic. Deliberately AFTER every config check: Client(nil, cfg) is
	// how several tests exercise config validation without a socket, and that
	// ordering keeps a config error reported as a config error. It matters
	// because the Contacts decision below reads raw.LocalAddr().
	if raw == nil {
		return nil, nil, errors.New("twiddle: nil connection")
	}

	// An explicit request is honoured; otherwise the contact memory decides.
	// A Contacts-driven choice DEGRADES to resumption when the cover or the
	// pool cannot back a full handshake, where an explicit one fails: the
	// caller asked for the right shape, not for the connection to be refused,
	// and refusing would make enabling Contacts depend on every cover having
	// been probed first. The degradation is not recorded, so it keeps trying
	// rather than latching.
	full := cfg.FullHandshake
	// contactGen is the generation the shape was decided under. record refuses a
	// write from a different one, so a Reset during the handshake cannot be
	// undone by the recording that follows it.
	var contactGen uint64
	if cfg.Contacts != nil {
		wantFull, gen := cfg.Contacts.needsFull(raw.LocalAddr(), raw.RemoteAddr(), time.Now())
		contactGen = gen
		if !full && wantFull {
			// All three have to be able to back the shape, and the CREDENTIAL
			// is the one that will be missing in practice: CredentialFromWire
			// leaves the companion nil, so every client provisioned before
			// lantern-cloud emits full_ticket is resumption-only. Omitting this
			// check made Contacts flip full to true and then fail in Twiddle,
			// refusing the connection instead of degrading -- which would have
			// broken every connection the moment Contacts was enabled ahead of
			// provisioning.
			full = cfg.Cover.CanEmitFullHandshake() &&
				len(FullHandshakeCarriers(cfg.Pool)) > 0 &&
				len(cfg.Credential.FullTicket) == FullTicketLen
		}
	}

	// The remainder record COUNT is what the client reads, so the two shapes
	// are read differently and picking the wrong sequence misaligns every
	// later read.
	remainder := cfg.Cover.ResumedRemainder
	if full {
		remainder = cfg.Cover.FullRemainder
	}
	// The full path can only use hellos whose ECH payload holds a ticket, and a
	// pool is not uniform -- a device tap copies whatever the browser emitted.
	// Drawing from the whole pool would fail on some connections and succeed on
	// others, depending on the draw.
	candidates := cfg.Pool
	if full {
		// Non-empty either way by now: an explicit request was checked above,
		// and a Contacts-driven one only set full when carriers exist.
		if candidates = FullHandshakeCarriers(cfg.Pool); len(candidates) == 0 {
			return nil, nil, errors.New("twiddle: no hello in the pool has an ECH payload large enough to carry a full-handshake ticket")
		}
	}
	pick, err := rand.Int(rand.Reader, bigLen(len(candidates)))
	if err != nil {
		return nil, nil, err
	}

	wire, eph, err := Twiddle(candidates[pick.Int64()], Options{
		CoverSNI:      cfg.Cover.Host,
		Credential:    cfg.Credential,
		BinderLen:     cfg.Cover.BinderLen,
		FullHandshake: full,
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
	conn.fullHandshake = full

	// Server EncryptedExtensions+Finished stand-in. One read per record the
	// cover sends, because the count varies by identity: microsoft splits the
	// remainder 32/74 where cloudflare and google coalesce it into one 64.
	// Reading a fixed one record left microsoft's second record in the stream
	// and every later read misaligned.
	for range remainder {
		if _, _, err := conn.consumeRecord(); err != nil {
			return nil, nil, err
		}
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
	// Recorded only now, with the opening complete. A full handshake that
	// failed established no relationship for a later resumption to continue, so
	// recording it would be the one direction that hurts.
	if full && cfg.Contacts != nil {
		cfg.Contacts.record(raw.LocalAddr(), raw.RemoteAddr(), time.Now(), contactGen)
	}
	return conn, next, nil
}

// Server accepts a twiddle connection, or returns ErrNotOurs.
func Server(raw net.Conn, cfg ServerConfig) (*Conn, error) {
	if err := cfg.Cover.Valid(); err != nil {
		return nil, err
	}
	if cfg.TicketKey == nil {
		return nil, errors.New("twiddle: ticket key is required")
	}
	if cfg.Replay == nil {
		return nil, errors.New("twiddle: shared replay cache is required")
	}
	maxAge := cfg.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultTicketMaxAge
	}
	// The replay gate forgets a client once its newest ticket ages past the
	// horizon, and that is only sound if MaxAge refuses such a ticket first.
	// Checked rather than documented, and checked here rather than after the
	// first read: a horizon shorter than MaxAge silently reopens the window the
	// gate exists to close, so it should not take a peer connecting to surface.
	if hz := cfg.Replay.Horizon(); hz < maxAge {
		return nil, fmt.Errorf("twiddle: replay horizon %v is shorter than ticket MaxAge %v", hz, maxAge)
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
	// The same signal that selected the validator selects the authenticator,
	// and the two must not disagree: a hello with pre_shared_key is a
	// resumption and its ticket came out of that extension, a hello without one
	// is a full handshake and its ticket came out of the ECH payload.
	full := h.Find(ExtPreSharedKey) == nil
	var res *AuthResult
	if full {
		res, err = VerifyECHTicketAuth(h, cfg.TicketKey, maxAge)
	} else {
		res, err = VerifyTicketAuth(h, cfg.TicketKey, maxAge)
	}
	if err != nil {
		return nil, ErrNotOurs
	}
	if !cfg.Replay.Consume(res.ClientID, res.Issued, ticket) {
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
		FullHandshake:   full,
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
	conn.fullHandshake = full

	// One write per record the cover actually sends: microsoft splits the
	// resumed remainder 32/74 where cloudflare and google coalesce it into one
	// 64. The full remainder is the certificate flight -- one to two orders of
	// magnitude larger -- and is drawn fresh each connection, because a
	// certificate flight that is byte-identical every time is a distinguisher
	// no real server produces.
	remainder := cfg.Cover.ResumedRemainder
	if full {
		if remainder, err = cfg.Cover.DrawFullRemainder(); err != nil {
			return nil, err
		}
	}
	for _, n := range remainder {
		if err := conn.writeSized(contentHandshake, nil, n); err != nil {
			return nil, err
		}
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
//
// The size is a KNOWN-WRONG constant for all three covers -- microsoft was
// measured issuing 303-byte tickets and cloudflare and google issue none
// unprompted at all. Tracked in docs/full-handshake-carrier.md; not made worse
// here.
const sessionTicketWire = 370

// Rotation is TWO records, one per ticket, rather than one carrying both.
//
// Not a stylistic choice: a single record would have to hold both tickets and
// the psk, which for a microsoft cover is 2+256+2+144+32 = 436 bytes against
// the 349 that fit inside sessionTicketWire, and writeSized would refuse it.
// Two records is also the more faithful shape -- microsoft was measured
// sending two unprompted NewSessionTickets after a full handshake -- and it
// leaves the first record's layout byte-for-byte what it was.
func writeTickets(c *Conn, next *Credential) error {
	body := make([]byte, 0, 2+len(next.Ticket)+32)
	body = appendU16(body, uint16(len(next.Ticket)))
	body = append(body, next.Ticket...)
	body = append(body, next.PSK[:]...)
	if err := c.writeSized(contentHandshake, body, sessionTicketWire); err != nil {
		return err
	}
	full := make([]byte, 0, 2+len(next.FullTicket))
	full = appendU16(full, uint16(len(next.FullTicket)))
	full = append(full, next.FullTicket...)
	return c.writeSized(contentHandshake, full, sessionTicketWire)
}

func readTickets(c *Conn) (*Credential, error) {
	typ, body, err := c.consumeRecord()
	if err != nil {
		return nil, err
	}
	// writeTickets emits contentHandshake and nothing else, so accepting
	// application_data here only widens what can be mistaken for a credential.
	// After the opening the tunnel carries app-data records; if the ordering
	// ever shifts, a lenient check would parse the first of them as a rotated
	// ticket instead of failing loudly.
	if typ != contentHandshake {
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

	typ, body, err = c.consumeRecord()
	if err != nil {
		return nil, err
	}
	if typ != contentHandshake {
		return nil, errMalformed
	}
	if len(body) < 2 {
		return nil, errMalformed
	}
	fl := int(binary.BigEndian.Uint16(body[0:2]))
	if fl != FullTicketLen || 2+fl > len(body) {
		return nil, errMalformed
	}
	cred.FullTicket = append([]byte(nil), body[2:2+fl]...)
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
