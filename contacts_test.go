package twiddle

import (
	"net"
	"sync"
	"testing"
	"time"
)

// addr is a stand-in net.Addr so the unit tests can drive addresses directly.
type addr string

func (a addr) Network() string { return "tcp" }
func (a addr) String() string  { return string(a) }

// mustNeedFull drops the generation, for the tests that only assert the
// decision. The generation itself is covered by
// TestContactMemoryIgnoresARecordFromBeforeAReset.
func mustNeedFull(m *ContactMemory, local, remote net.Addr, now time.Time) bool {
	full, _ := m.needsFull(local, remote, now)
	return full
}

// The rule, in one test: full on first contact, resumed afterwards.
func TestContactMemoryIsFullOnFirstContactAndResumedAfter(t *testing.T) {
	m := NewContactMemory(time.Hour, 0)
	now := time.Now()
	local, remote := addr("10.0.0.2:51000"), addr("203.0.113.9:443")

	if !mustNeedFull(m, local, remote, now) {
		t.Fatal("first contact with an egress did not ask for a full handshake")
	}
	// Asking is not recording: until the handshake completes, the relationship
	// does not exist and the answer must not change.
	if !mustNeedFull(m, local, remote, now) {
		t.Error("the answer changed before any handshake was recorded")
	}

	m.record(local, remote, now, m.generation())
	if mustNeedFull(m, local, remote, now.Add(time.Minute)) {
		t.Error("a second connection to a recorded egress asked for another full handshake")
	}
}

// The source port changes on every connection and cannot be part of a
// relationship a censor correlates by address pair.
func TestContactMemoryIgnoresPorts(t *testing.T) {
	m := NewContactMemory(time.Hour, 0)
	now := time.Now()
	m.record(addr("10.0.0.2:51000"), addr("203.0.113.9:443"), now, m.generation())

	if mustNeedFull(m, addr("10.0.0.2:52222"), addr("203.0.113.9:443"), now) {
		t.Error("a new source port was treated as a new contact")
	}
}

// Past the horizon the censor can no longer be assumed to remember, so the
// relationship has to be re-established.
func TestContactMemoryReFullsPastTheHorizon(t *testing.T) {
	m := NewContactMemory(time.Hour, 0)
	base := time.Now()
	local, remote := addr("10.0.0.2:51000"), addr("203.0.113.9:443")
	m.record(local, remote, base, m.generation())

	if mustNeedFull(m, local, remote, base.Add(59*time.Minute)) {
		t.Error("re-fulled inside the horizon")
	}
	if !mustNeedFull(m, local, remote, base.Add(time.Hour)) {
		t.Error("did not re-full at the horizon")
	}
	if !mustNeedFull(m, local, remote, base.Add(3*time.Hour)) {
		t.Error("did not re-full past the horizon")
	}
}

// The horizon is enforced in two places -- the answer and the eviction -- and
// the test above cannot tell them apart, because removing either one leaves it
// green. This one covers eviction specifically: state past the horizon has to
// be dropped, or a long-running client accumulates one entry per egress it ever
// contacted and the bound becomes the only thing holding the map down.
func TestContactMemoryDropsStatePastTheHorizon(t *testing.T) {
	m := NewContactMemory(time.Hour, 0)
	base := time.Now()
	for i := 1; i <= 20; i++ {
		m.record(addr("10.0.0.2:1"), addr(net.JoinHostPort(
			net.IPv4(203, 0, 113, byte(i)).String(), "443")), base, m.generation())
	}
	if m.Tracked() != 20 {
		t.Fatalf("tracking %d contacts, want 20", m.Tracked())
	}

	// Any later call runs eviction, and every entry is now stale.
	mustNeedFull(m, addr("10.0.0.2:1"), addr("198.51.100.1:443"), base.Add(2*time.Hour))
	if got := m.Tracked(); got != 0 {
		t.Errorf("tracking %d contacts after the horizon passed, want 0", got)
	}
}

// A different egress, and a different local address, are both new contacts. The
// second is the roaming case: a censor at the new vantage point never saw the
// earlier full handshake.
func TestContactMemoryKeysOnBothEnds(t *testing.T) {
	m := NewContactMemory(time.Hour, 0)
	now := time.Now()
	m.record(addr("10.0.0.2:51000"), addr("203.0.113.9:443"), now, m.generation())

	if !mustNeedFull(m, addr("10.0.0.2:51000"), addr("198.51.100.7:443"), now) {
		t.Error("a different egress was treated as already contacted")
	}
	if !mustNeedFull(m, addr("192.168.5.4:51000"), addr("203.0.113.9:443"), now) {
		t.Error("a new local address was treated as already contacted; roaming would emit a bare resumption")
	}
}

// Reset is the reliable version of the local-address heuristic, for callers
// that can see a network change the local address does not reveal -- the same
// private address handed out by two different networks.
func TestContactMemoryResetForcesFullAgain(t *testing.T) {
	m := NewContactMemory(time.Hour, 0)
	now := time.Now()
	local, remote := addr("192.168.1.5:51000"), addr("203.0.113.9:443")
	m.record(local, remote, now, m.generation())
	if mustNeedFull(m, local, remote, now) {
		t.Fatal("recorded contact still asked for a full handshake")
	}

	m.Reset()
	if m.Tracked() != 0 {
		t.Errorf("Reset left %d contacts", m.Tracked())
	}
	if !mustNeedFull(m, local, remote, now) {
		t.Error("after Reset the same address pair did not ask for a full handshake")
	}
}

// The bound exists so the map cannot leak, and evicting a LIVE entry is sound
// here precisely because the consequence is one extra full handshake. That is
// the reverse of ReplayCache, where evicting a live entry reopens the window
// the gate exists to close.
func TestContactMemoryEvictionFailsTowardFull(t *testing.T) {
	const max = 32
	m := NewContactMemory(time.Hour, max)
	base := time.Now()

	first := addr("203.0.113.1:443")
	m.record(addr("10.0.0.2:1"), first, base, m.generation())

	for i := 0; i < max*4; i++ {
		m.record(addr("10.0.0.2:1"), addr(net.JoinHostPort(
			net.IPv4(198, 51, 100, byte(i%250+1)).String(), "443")),
			base.Add(time.Duration(i+1)*time.Second), m.generation())
	}
	if got := m.Tracked(); got > max {
		t.Errorf("tracking %d contacts, above the %d bound", got, max)
	}
	// The oldest entry is gone, and its absence asks for a full handshake --
	// the safe direction, not a reopened hole.
	if !mustNeedFull(m, addr("10.0.0.2:1"), first, base.Add(time.Minute)) {
		t.Error("an evicted contact was still treated as already contacted")
	}
}

// A nil memory is the documented default and must behave as today: never ask
// for a full handshake, and never panic on record.
func TestNilContactMemoryIsInert(t *testing.T) {
	var m *ContactMemory
	if mustNeedFull(m, addr("a:1"), addr("b:2"), time.Now()) {
		t.Error("a nil memory asked for a full handshake")
	}
	m.record(addr("a:1"), addr("b:2"), time.Now(), m.generation()) // must not panic
	m.Reset()
	if m.Tracked() != 0 || m.Horizon() != 0 {
		t.Error("a nil memory reported state")
	}
}

func TestContactMemoryDefaults(t *testing.T) {
	m := NewContactMemory(0, 0)
	if m.Horizon() != DefaultContactHorizon {
		t.Errorf("horizon %v, want the default %v", m.Horizon(), DefaultContactHorizon)
	}
}

// The race the generation guard exists for.
//
// A decision and its recording straddle the entire handshake, so a Reset can
// land between them. Without the guard the recording that follows would undo
// the reset: the entry reappears for an address pair the NEW observer has no
// history of, and the next connection resumes with no predecessor it can see.
//
// The local address usually changes with the network and saves us, but not
// always -- two networks can both hand out 192.168.1.5, which is exactly the
// case Reset exists to cover. So this test holds the address pair fixed.
func TestContactMemoryIgnoresARecordFromBeforeAReset(t *testing.T) {
	m := NewContactMemory(time.Hour, 0)
	now := time.Now()
	local, remote := addr("192.168.1.5:51000"), addr("203.0.113.9:443")

	// The shape is decided, and the generation captured with it.
	full, gen := m.needsFull(local, remote, now)
	if !full {
		t.Fatal("first contact did not ask for a full handshake")
	}

	// The network changes while the handshake is in flight.
	m.Reset()

	// The handshake completes and tries to record what it decided.
	m.record(local, remote, now, gen)

	if m.Tracked() != 0 {
		t.Errorf("a handshake decided before the reset wrote %d contacts after it", m.Tracked())
	}
	if !mustNeedFull(m, local, remote, now) {
		t.Error("the next connection would resume, against an observer with no record of the handshake that preceded it")
	}

	// And the guard is not a permanent block: a handshake decided AFTER the
	// reset records normally.
	full, gen = m.needsFull(local, remote, now)
	if !full {
		t.Fatal("post-reset contact did not ask for a full handshake")
	}
	m.record(local, remote, now, gen)
	if m.Tracked() != 1 {
		t.Errorf("tracking %d contacts after a valid record, want 1", m.Tracked())
	}
	if mustNeedFull(m, local, remote, now.Add(time.Minute)) {
		t.Error("a handshake recorded after the reset was not honoured")
	}
}

// The same interleaving through Client, concurrently, under -race: a Reset
// landing during the handshake I/O must not leave the pair recorded.
func TestContactMemoryResetDuringHandshakeIsNotUndone(t *testing.T) {
	m := NewContactMemory(time.Hour, 0)
	now := time.Now()
	local, remote := addr("192.168.1.5:51000"), addr("203.0.113.9:443")

	full, gen := m.needsFull(local, remote, now)
	if !full {
		t.Fatal("first contact did not ask for a full handshake")
	}

	// Reset and record racing, as they would across two goroutines.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); m.Reset() }()
	go func() { defer wg.Done(); m.record(local, remote, now, gen) }()
	wg.Wait()

	// Either order is acceptable ONLY if the outcome is safe. If Reset ran
	// first the generation stops the write; if record ran first the reset
	// clears it. Both leave nothing behind, which is the point.
	if m.Tracked() != 0 {
		t.Errorf("tracking %d contacts after a reset raced the recording, want 0", m.Tracked())
	}
}
