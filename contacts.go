package twiddle

import (
	"net"
	"sync"
	"time"
)

// ContactMemory decides, per connection, whether the opening should be a full
// handshake or a resumption.
//
// The rule it implements is not "match the 4% resumption share measured in real
// browsing" -- see docs/full-handshake-carrier.md. It is narrower and much
// cheaper to satisfy: a censor watching this client and this egress must have
// already seen the FULL HANDSHAKE that a resumption continues. A client with a
// long relationship to one host and a stack of its tickets is an ordinary
// pattern. What no real client does is reach a host for the first time already
// holding a ticket, and never once complete a full handshake with it.
//
// So: full on first contact with an egress, resumed afterwards, and full again
// once the censor can no longer be assumed to remember.
//
// EVERY UNCERTAINTY RESOLVES TOWARD FULL. A forgotten entry, an evicted one, a
// restarted process, a changed local address, an expired horizon -- each
// produces an extra full handshake, which costs 5-10 KB and looks MORE normal
// rather than less, because 95%+ of real connections are full handshakes. The
// opposite mistake, a resumption with no observable predecessor, is the
// distinguisher this exists to remove. That asymmetry is why the eviction below
// is sound, and it is the reverse of ReplayCache's situation, where evicting a
// live entry reopens the window the gate exists to close.
type ContactMemory struct {
	mu      sync.Mutex
	horizon time.Duration
	max     int
	seen    map[contactKey]time.Time
}

// contactKey pairs the egress address with the local one.
//
// The local address is included because a censor's history is tied to a vantage
// point: a client that moves from one network to another is being watched by
// somebody who never saw the earlier full handshake, so the relationship has to
// be re-established. It is a WEAK proxy -- behind NAT it is a private address,
// and two different networks can both hand out 192.168.1.5, in which case the
// move goes unnoticed. Callers that can detect a network change should call
// Reset, which is the reliable signal; this catches the cheap cases on its own.
type contactKey struct {
	local  string
	remote string
}

const (
	// DefaultContactHorizon is how long a full handshake is assumed to still be
	// in a censor's flow history.
	//
	// The true value is unknowable, so this errs short. Flow-record retention
	// is commonly days, so six hours sits well inside it, and the cost of being
	// wrong in this direction is one extra full handshake per egress per six
	// hours -- tens of kilobytes a day. Erring long risks emitting exactly the
	// resumption-without-predecessor this is meant to prevent.
	DefaultContactHorizon = 6 * time.Hour

	// defaultContactMax bounds the map. A client contacts tens of egresses, not
	// thousands, so this is a backstop against a leak rather than a working
	// limit.
	defaultContactMax = 1024
)

// NewContactMemory returns a memory with the given horizon and entry bound.
// Zero or negative selects the defaults.
func NewContactMemory(horizon time.Duration, max int) *ContactMemory {
	if horizon <= 0 {
		horizon = DefaultContactHorizon
	}
	if max <= 0 {
		max = defaultContactMax
	}
	return &ContactMemory{
		horizon: horizon,
		max:     max,
		seen:    make(map[contactKey]time.Time),
	}
}

// Horizon reports how long a recorded full handshake is trusted for.
func (m *ContactMemory) Horizon() time.Duration {
	if m == nil {
		return 0
	}
	return m.horizon
}

// Reset forgets every contact, so the next connection to each egress opens with
// a full handshake.
//
// Callers should call this when the platform reports a network change -- a new
// interface, a new default route, a VPN coming up or down. That is the reliable
// version of what contactKey's local address approximates: after such a change
// the observer is potentially a different one, with no history of anything this
// client did before.
func (m *ContactMemory) Reset() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen = make(map[contactKey]time.Time)
}

// Tracked reports how many contacts are remembered.
func (m *ContactMemory) Tracked() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.seen)
}

func addrKey(a net.Addr) string {
	if a == nil {
		return ""
	}
	// Ports are deliberately dropped. A censor correlating a resumption with
	// the full handshake it continues does so by address pair; the source port
	// changes on every connection and cannot be part of the relationship.
	if host, _, err := net.SplitHostPort(a.String()); err == nil {
		return host
	}
	return a.String()
}

// needsFull reports whether this connection should open with a full handshake.
//
// Two concurrent connections to the same new egress will both be told yes, and
// both will do a full handshake. That is not a race worth closing: it is what a
// browser does on every page load, where a parallel burst opens several
// connections to one origin before any of them has a ticket to resume with.
func (m *ContactMemory) needsFull(local, remote net.Addr, now time.Time) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictLocked(now)
	last, ok := m.seen[contactKey{addrKey(local), addrKey(remote)}]
	// The horizon is enforced TWICE, here and in evictLocked, and neither is
	// load-bearing alone -- a mutation removing either one keeps every test
	// green. That is deliberate: eviction bounds the state and this comparison
	// bounds the answer, so making eviction periodic or lazy later cannot
	// silently extend how long a relationship is trusted for.
	return !ok || now.Sub(last) >= m.horizon
}

// record notes a COMPLETED full handshake. Only completed ones count: a
// handshake that failed established no relationship for a later resumption to
// continue.
func (m *ContactMemory) record(local, remote net.Addr, now time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen[contactKey{addrKey(local), addrKey(remote)}] = now
	m.evictLocked(now)
}

// evictLocked drops what is past the horizon, then enforces the entry bound by
// dropping the oldest.
//
// Dropping a live entry is safe here, unlike in ReplayCache, because the only
// consequence is one extra full handshake -- the safe direction. That is what
// lets this use a simple bound where the replay gate needed a redesign.
func (m *ContactMemory) evictLocked(now time.Time) {
	for k, t := range m.seen {
		if now.Sub(t) >= m.horizon {
			delete(m.seen, k)
		}
	}
	for len(m.seen) > m.max {
		var oldestKey contactKey
		var oldest time.Time
		first := true
		for k, t := range m.seen {
			if first || t.Before(oldest) {
				oldestKey, oldest, first = k, t, false
			}
		}
		delete(m.seen, oldestKey)
	}
}
