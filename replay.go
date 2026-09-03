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

const defaultReplayMax = 8192

// ReplayCache is a bounded, TTL'd set of tickets already accepted. Twiddle
// tickets are otherwise a replayable identification token: VerifyTicketAuth is
// stateless, so a captured hello authenticates twice, and a censor who replays
// it to both the suspected proxy and the claimed cover sees a resumed flight
// from us and a full handshake from them.
//
// Consume is the single-use gate. A duplicate returns false and the caller
// must take the cover path (ErrNotOurs), not answer.
type ReplayCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	seen  map[string]time.Time
	order []string
}

// NewReplayCache returns a cache that forgets entries after ttl and drops the
// oldest when max is exceeded. max<=0 or ttl<=0 use the defaults (8192, 24h).
func NewReplayCache(max int, ttl time.Duration) *ReplayCache {
	if max <= 0 {
		max = defaultReplayMax
	}
	if ttl <= 0 {
		ttl = DefaultTicketMaxAge
	}
	return &ReplayCache{
		ttl:  ttl,
		max:  max,
		seen: make(map[string]time.Time, max),
	}
}

// Consume records ticket as spent. It returns true the first time this ticket
// is seen within ttl, and false if it is a replay (or a hash collision, which
// we treat the same: cover path).
func (c *ReplayCache) Consume(ticket []byte) bool {
	if c == nil {
		return true
	}
	sum := sha256.Sum256(ticket)
	key := string(sum[:])
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictLocked(now)
	if t, ok := c.seen[key]; ok && now.Sub(t) < c.ttl {
		return false
	}
	c.seen[key] = now
	c.order = append(c.order, key)
	for len(c.seen) > c.max {
		old := c.order[0]
		c.order = c.order[1:]
		delete(c.seen, old)
	}
	return true
}

func (c *ReplayCache) evictLocked(now time.Time) {
	n := 0
	for _, k := range c.order {
		t, ok := c.seen[k]
		if !ok || now.Sub(t) >= c.ttl {
			delete(c.seen, k)
			continue
		}
		c.order[n] = k
		n++
	}
	c.order = c.order[:n]
}
