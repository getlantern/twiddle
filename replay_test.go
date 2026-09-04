package twiddle

import (
	"testing"
	"time"
)

// mintAt issues a ticket carrying a specific Issued time, so freshness ordering
// can be driven directly rather than by sleeping.
func mintAt(t *testing.T, k *TicketKey, clientID uint64, at time.Time) *Credential {
	t.Helper()
	cred, err := k.issueAt(clientID, DefaultTicketLen, at)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// The basic gate: a ticket is spendable once.
func TestReplayRejectsTheSameTicketTwice(t *testing.T) {
	k := ticketKey(t)
	c := NewReplayCache(0, 0)
	now := time.Now()
	cred := mintAt(t, k, 1, now)

	if !c.Consume(1, now, cred.Ticket) {
		t.Fatal("first presentation was rejected")
	}
	if c.Consume(1, now, cred.Ticket) {
		t.Error("a replay of the same ticket was accepted")
	}
}

// The regression this design exists for.
//
// The previous gate was a set of ticket hashes bounded by ENTRY COUNT (8192)
// with FIFO eviction, so any 8192 accepted openings — from any clients, through
// ordinary traffic — pushed an older ticket out while it was still inside
// MaxAge, and it replayed successfully. Keying on the client means another
// client's traffic cannot evict this one's freshness record.
func TestReplayIsNotReopenedByOtherClientsTraffic(t *testing.T) {
	k := ticketKey(t)
	c := NewReplayCache(0, 0)
	now := time.Now()

	// A censor captures and we spend client 1's ticket.
	captured := mintAt(t, k, 1, now)
	if !c.Consume(1, now, captured.Ticket) {
		t.Fatal("first presentation was rejected")
	}

	// Ordinary traffic: far more openings than the old 8192-entry bound, from
	// other clients, each with its own ticket.
	const others = 20000
	for i := 0; i < others; i++ {
		id := uint64(1000 + i)
		cred := mintAt(t, k, id, now)
		if !c.Consume(id, now, cred.Ticket) {
			t.Fatalf("legitimate opening from client %d was rejected", id)
		}
	}
	if got := c.TrackedClients(); got != others+1 {
		t.Fatalf("tracking %d clients, want %d — the backstop evicted and this test no longer proves the point", got, others+1)
	}

	// The captured hello must still be refused.
	if c.Consume(1, now, captured.Ticket) {
		t.Errorf("replay succeeded after %d unrelated openings; the window reopened", others)
	}
}

// Credentials rotate, so a client's newest ticket retires its earlier ones.
// A stale ticket must be refused even though it was never itself presented —
// a censor holding an old capture does not get to spend it.
func TestReplayRejectsTicketOlderThanTheClientsNewest(t *testing.T) {
	k := ticketKey(t)
	c := NewReplayCache(0, 0)
	now := time.Now()

	old := mintAt(t, k, 7, now.Add(-2*time.Hour))
	fresh := mintAt(t, k, 7, now)

	if !c.Consume(7, now, fresh.Ticket) {
		t.Fatal("the fresh ticket was rejected")
	}
	if c.Consume(7, now.Add(-2*time.Hour), old.Ticket) {
		t.Error("a ticket older than the client's newest was accepted")
	}
}

// Issued has one-second resolution and the client holds a credential pool, so
// siblings minted in the same second are spent in arbitrary order. Ordering
// alone cannot tell a sibling from a replay, so both must be accepted — this is
// what stops the gate refusing legitimate concurrent openings.
func TestReplayAcceptsSameSecondSiblings(t *testing.T) {
	k := ticketKey(t)
	c := NewReplayCache(0, 0)
	now := time.Now().Truncate(time.Second)

	a := mintAt(t, k, 3, now)
	b := mintAt(t, k, 3, now)
	if string(a.Ticket) == string(b.Ticket) {
		t.Fatal("two issues produced the same ticket; this test proves nothing")
	}

	if !c.Consume(3, now, a.Ticket) {
		t.Fatal("first sibling rejected")
	}
	if !c.Consume(3, now, b.Ticket) {
		t.Error("second same-second sibling rejected; concurrent openings would fail")
	}
	// Each is still single-use.
	if c.Consume(3, now, a.Ticket) {
		t.Error("replay of the first sibling was accepted")
	}
	if c.Consume(3, now, b.Ticket) {
		t.Error("replay of the second sibling was accepted")
	}
}

// A newer ticket retires the whole tie set, not just the ordering bound.
func TestReplayNewerTicketRetiresSameSecondSiblings(t *testing.T) {
	k := ticketKey(t)
	c := NewReplayCache(0, 0)
	base := time.Now().Truncate(time.Second)

	a := mintAt(t, k, 4, base)
	if !c.Consume(4, base, a.Ticket) {
		t.Fatal("first rejected")
	}
	newer := mintAt(t, k, 4, base.Add(time.Second))
	if !c.Consume(4, base.Add(time.Second), newer.Ticket) {
		t.Fatal("newer ticket rejected")
	}
	// a is now older than the client's newest, so it must be refused even
	// though the tie set that held it was replaced.
	if c.Consume(4, base, a.Ticket) {
		t.Error("a retired same-second ticket was accepted")
	}
}

// Forgetting past the horizon is what keeps the state bounded, and it is only
// sound because MaxAge refuses such a ticket first. Server enforces that
// relationship rather than trusting the caller.
func TestServerRejectsHorizonShorterThanMaxAge(t *testing.T) {
	k := ticketKey(t)
	cover := mustCover(t, "www.microsoft.com")
	_, err := Server(nil, ServerConfig{
		TicketKey: k,
		Cover:     cover,
		MaxAge:    24 * time.Hour,
		Replay:    NewReplayCache(0, time.Hour),
	})
	if err == nil {
		t.Fatal("a replay horizon shorter than MaxAge was accepted; the window silently reopens")
	}
	if got := err.Error(); !contains(got, "horizon") {
		t.Errorf("unhelpful error: %v", got)
	}
}

// Past the horizon the client record goes, which is the bound on state. The
// ticket is unusable by then anyway: VerifyTicketAuth's MaxAge refuses it.
func TestReplayForgetsPastTheHorizon(t *testing.T) {
	k := ticketKey(t)
	c := NewReplayCache(0, time.Hour)
	old := time.Now().Add(-2 * time.Hour)
	cred := mintAt(t, k, 9, old)

	if !c.Consume(9, old, cred.Ticket) {
		t.Fatal("first presentation rejected")
	}
	// Any later Consume runs eviction first, and this client's newest ticket is
	// already beyond the horizon.
	other := mintAt(t, k, 10, time.Now())
	c.Consume(10, time.Now(), other.Ticket)

	if got := c.TrackedClients(); got != 1 {
		t.Errorf("tracking %d clients, want just the fresh one", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// A credential's two tickets must both be spendable.
//
// The gate refuses a ticket older than the client's newest, so if Issue sealed
// the companion even a second apart from the resumption ticket, whichever path
// the client used SECOND would be read as a stale capture and refused. That
// failure would be invisible in unit tests of either path alone: each works,
// and only using both breaks.
func TestBothTicketsOfOneCredentialAreSpendable(t *testing.T) {
	k := ticketKey(t)
	c := NewReplayCache(0, 0)

	cred, err := k.Issue(21, DefaultTicketLen)
	if err != nil {
		t.Fatal(err)
	}
	id, _, issued, err := k.Open(cred.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	fid, _, fullIssued, err := k.Open(cred.FullTicket)
	if err != nil {
		t.Fatal(err)
	}
	if id != fid {
		t.Fatalf("the two tickets carry different clientIDs (%d, %d); they are two clients, not one", id, fid)
	}

	if !c.Consume(id, issued, cred.Ticket) {
		t.Fatal("the resumption ticket was refused")
	}
	if !c.Consume(fid, fullIssued, cred.FullTicket) {
		t.Error("the full-handshake companion was refused after the resumption ticket; their issue times disagree")
	}
	// Each is still single-use.
	if c.Consume(fid, fullIssued, cred.FullTicket) {
		t.Error("a replay of the full ticket was accepted")
	}
}

// IssueFullFor upgrades a resumption-only credential, and must take every
// field from the ticket it companions -- including the issue time, or it
// recreates the bug above.
func TestIssueFullForMatchesTheTicketItCompanions(t *testing.T) {
	k := ticketKey(t)
	old, err := k.issueAt(31, DefaultTicketLen, time.Now().Add(-3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	full, err := k.IssueFullFor(old.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	id, psk, issued, err := k.Open(full)
	if err != nil {
		t.Fatal(err)
	}
	wantID, wantPSK, wantIssued, err := k.Open(old.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	if id != wantID {
		t.Errorf("clientID %d, want %d", id, wantID)
	}
	if psk != wantPSK {
		t.Error("companion carries a different psk")
	}
	if !issued.Equal(wantIssued) {
		t.Errorf("companion issued %v, want %v -- the replay gate would refuse whichever is used second", issued, wantIssued)
	}
}
