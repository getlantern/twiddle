package twiddle

import (
	"crypto/sha256"
	"sync"
	"time"
)

// DefaultTicketMaxAge is applied when ServerConfig.MaxAge is unset. A ticket
// older than this takes the cover path, same as a bad binder. VerifyTicketAuth
// still treats maxAge==0 as "do not check" so unit tests can isolate the
// binder; Server never passes 0.
const DefaultTicketMaxAge = 24 * time.Hour

// defaultReplayMax bounds tracked CLIENTS, not tickets. It is a memory
// backstop, not the mechanism: see ReplayCache.
const defaultReplayMax = 65536

// ReplayCache is the single-use gate on tickets. Without it a twiddle ticket is
// a replayable identification token: VerifyTicketAuth is stateless, so a
// captured hello authenticates twice, and a censor who replays one to both the
// suspected proxy and the claimed cover sees a resumed flight from us and a
// full handshake from them.
//
// It keys on the CLIENT, not on the ticket. Credentials rotate every
// connection, so the newest ticket a client has presented dominates all its
// earlier ones: anything older is either spent or forged, and both take the
// cover path. That makes the state O(clients active within the horizon) rather
// than O(connections), and — the part that matters — it makes forgetting SAFE.
//
// A per-ticket set could not manage that. Bounded by entry count, it evicted
// the oldest tickets while they were still inside MaxAge, so a hello captured
// hours earlier replayed successfully once ordinary traffic had pushed it out.
// At 8192 entries an egress serving a hundred clients crossed that in under a
// day of normal use, with no adversary action and no signal that the window had
// reopened. Eviction here is by horizon instead, which is sound for a reason
// rather than by luck: a ticket older than the horizon is already refused by
// VerifyTicketAuth's MaxAge check, so dropping the client's record cannot admit
// anything. Server enforces horizon >= MaxAge so that argument holds.
//
// Consume is the gate. A duplicate returns false and the caller must take the
// cover path (ErrNotOurs), not answer.
type ReplayCache struct {
	mu      sync.Mutex
	horizon time.Duration
	max     int
	clients map[uint64]*clientSeen
}

// clientSeen is one client's freshness record.
//
// ties exists because Issued has one-second resolution (auth.go stores
// unix seconds), and the client holds a pool of credentials so it may spend
// several tickets minted in the same second, in any order. Ordering alone
// therefore cannot separate a legitimate sibling from a replay, so tickets at
// the newest second are tracked individually. That set is bounded by one
// client's per-second concurrency — single digits — not by traffic volume.
type clientSeen struct {
	newest time.Time
	ties   map[string]struct{}
	seenAt time.Time
}

// NewReplayCache returns a gate that forgets a client once its newest ticket is
// older than horizon. max bounds tracked clients as a memory backstop; both
// arguments fall back to defaults (65536 clients, 24h) when <= 0.
//
// horizon MUST be at least the Server's MaxAge. Server checks it.
func NewReplayCache(max int, horizon time.Duration) *ReplayCache {
	if max <= 0 {
		max = defaultReplayMax
	}
	if horizon <= 0 {
		horizon = DefaultTicketMaxAge
	}
	return &ReplayCache{
		horizon: horizon,
		max:     max,
		clients: make(map[uint64]*clientSeen),
	}
}

// Horizon reports how far back the gate remembers. Server requires it to be at
// least MaxAge, because that is what makes eviction safe.
func (c *ReplayCache) Horizon() time.Duration {
	if c == nil {
		return 0
	}
	return c.horizon
}

// Consume spends one ticket. It returns true the first time this ticket is
// presented, and false for a replay or anything staler than the client's newest
// accepted ticket.
//
// clientID and issued come from the ticket's authenticated plaintext, so
// neither is attacker-chosen: a forged clientID cannot be produced without the
// server's ticket key, which is why the tracked client population is the
// provisioned one rather than anything a censor can inflate.
func (c *ReplayCache) Consume(clientID uint64, issued time.Time, ticket []byte) bool {
	if c == nil {
		return true
	}
	sum := sha256.Sum256(ticket)
	key := string(sum[:])
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictLocked(now)

	seen, ok := c.clients[clientID]
	if !ok {
		c.admitLocked(clientID, issued, key, now)
		return true
	}
	switch {
	case issued.After(seen.newest):
		// A newer ticket retires every earlier one, ties included.
		seen.newest = issued
		seen.ties = map[string]struct{}{key: {}}
		seen.seenAt = now
		return true
	case issued.Equal(seen.newest):
		if _, dup := seen.ties[key]; dup {
			return false
		}
		seen.ties[key] = struct{}{}
		seen.seenAt = now
		return true
	default:
		// Older than the newest this client has presented: spent or forged.
		return false
	}
}

func (c *ReplayCache) admitLocked(clientID uint64, issued time.Time, key string, now time.Time) {
	if len(c.clients) >= c.max {
		c.dropOldestLocked()
	}
	c.clients[clientID] = &clientSeen{
		newest: issued,
		ties:   map[string]struct{}{key: {}},
		seenAt: now,
	}
}

// evictLocked forgets clients whose newest ticket has aged past the horizon.
// Safe by construction: such a ticket no longer passes MaxAge.
func (c *ReplayCache) evictLocked(now time.Time) {
	for id, seen := range c.clients {
		if now.Sub(seen.newest) >= c.horizon {
			delete(c.clients, id)
		}
	}
}

// dropOldestLocked is the memory backstop, and it is the one path that can
// reopen a replay window — for the single least-recently-active client, whose
// tickets are also closest to ageing out of MaxAge anyway. It should not
// normally run: reaching it means more distinct provisioned clients than max
// were active inside one horizon, and clientID cannot be forged to inflate
// that.
func (c *ReplayCache) dropOldestLocked() {
	var victim uint64
	var oldest time.Time
	first := true
	for id, seen := range c.clients {
		if first || seen.seenAt.Before(oldest) {
			victim, oldest, first = id, seen.seenAt, false
		}
	}
	if !first {
		delete(c.clients, victim)
	}
}

// TrackedClients reports how many clients the gate is holding. Diagnostic: a
// count pinned at max means dropOldestLocked is running and the backstop needs
// raising.
func (c *ReplayCache) TrackedClients() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.clients)
}
