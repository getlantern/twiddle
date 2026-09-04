package coverprobe

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	tw "github.com/getlantern/twiddle"
)

// Against the real upstreams. Off by default: it needs the network, and the
// suite must pass on a machine without one.
//
// This is the test that matters for the whole design. A flight-style probe that
// never completes the handshake measured 1215 B ServerHellos and multi-kilobyte
// remainders -- the FULL handshake -- and was rejected by Adopt every time.
// Resuming first is what reaches the opening the transport actually imitates.
func TestProbeReproducesTheMeasuredProfile(t *testing.T) {
	if os.Getenv("TWIDDLE_LIVE_PROBE") == "" {
		t.Skip("set TWIDDLE_LIVE_PROBE=1 to probe the real covers")
	}
	for _, host := range tw.MeasuredCovers() {
		t.Run(host, func(t *testing.T) {
			base, err := tw.CoverFor(host)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			dial := func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
			}

			res, err := Probe(ctx, dial, host)
			// Probe returns only the resumed half, so it inherits ProbeBoth's
			// dependence on the upstream actually resuming -- which cloudflare
			// declines roughly 40% of the time, because a second connection
			// lands on an edge server that cannot decrypt its sibling's ticket.
			// Skipped rather than failed: nothing about the cover or about us is
			// wrong. TestAtLeastOneCoverStillResumes is the floor that stops
			// every cover skipping silently.
			if errors.Is(err, ErrNoResume) {
				t.Skipf("%s declined to resume on this attempt; nothing to compare", host)
			}
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			t.Logf("%s: ServerHello %d, remainder %v, burst %d, %v",
				host, res.ServerHello, res.Remainder, res.OpeningBurst,
				res.Elapsed.Round(time.Millisecond))

			got, err := base.Adopt(res)
			if err != nil {
				t.Fatalf("live probe rejected against the table: %v", err)
			}
			if !slices.Equal(got.ResumedRemainder, base.ResumedRemainder) {
				t.Errorf("live remainder %v differs from the table's %v — the table is stale, or the identity changed",
					got.ResumedRemainder, base.ResumedRemainder)
			}
			if got.ResumedOpeningBurst() != base.ResumedOpeningBurst() {
				t.Errorf("live burst %d, table %d", got.ResumedOpeningBurst(), base.ResumedOpeningBurst())
			}
		})
	}
}

// ProbeBoth against the real upstreams. The full handshake is the shape ~96% of
// real connections take, and its remainder cannot come from a table, so this is
// the path that has to work from a probe or not at all.
func TestProbeBothAgainstLiveUpstreams(t *testing.T) {
	if os.Getenv("TWIDDLE_LIVE_PROBE") == "" {
		t.Skip("set TWIDDLE_LIVE_PROBE=1 to probe the real covers")
	}
	for _, host := range tw.MeasuredCovers() {
		t.Run(host, func(t *testing.T) {
			base, err := tw.CoverFor(host)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			dial := func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
			}

			full, resumed, err := ProbeBoth(ctx, dial, host)
			// A cover that declined to resume on this attempt has told us
			// nothing is wrong -- it landed on an edge server that could not
			// decrypt its own sibling's ticket. Measured at a 40% failure rate
			// against cloudflare, so failing here made this test unusable in
			// CI. Skipped rather than tolerated, so it cannot pass while
			// verifying nothing, and the counter below is what stops EVERY
			// cover skipping silently.
			if errors.Is(err, ErrNoResume) {
				t.Skipf("%s declined to resume on this attempt; nothing to compare", host)
			}
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			t.Logf("full:    ServerHello %d, remainder %v, burst %d",
				full.ServerHello, full.Remainder, full.OpeningBurst)
			t.Logf("resumed: ServerHello %d, remainder %v, burst %d",
				resumed.ServerHello, resumed.Remainder, resumed.OpeningBurst)

			// The resumed half must still match the table exactly.
			withResumed, err := base.Adopt(resumed)
			if err != nil {
				t.Fatalf("resumed probe rejected: %v", err)
			}
			if !slices.Equal(withResumed.ResumedRemainder, base.ResumedRemainder) {
				t.Errorf("resumed remainder %v, table %v", withResumed.ResumedRemainder, base.ResumedRemainder)
			}

			// The full half has no table entry by design; it must be adoptable
			// and must leave the resumed half untouched.
			got, err := withResumed.Adopt(full)
			if err != nil {
				t.Fatalf("full probe rejected: %v", err)
			}
			if !got.CanEmitFullHandshake() {
				t.Error("adopting a full probe did not enable the full carrier")
			}
			if !slices.Equal(got.FullRemainder, full.Remainder) {
				t.Errorf("full remainder %v, probed %v", got.FullRemainder, full.Remainder)
			}
			if !slices.Equal(got.ResumedRemainder, base.ResumedRemainder) {
				t.Error("adopting the full probe disturbed the resumed variant")
			}
			if got.FullOpeningBurst() != full.OpeningBurst {
				t.Errorf("derived full burst %d, probed %d", got.FullOpeningBurst(), full.OpeningBurst)
			}
			if got.FullOpeningBurst() <= got.ResumedOpeningBurst() {
				t.Errorf("full burst %d is not larger than resumed %d; the certificate is missing",
					got.FullOpeningBurst(), got.ResumedOpeningBurst())
			}
		})
	}
}

// The certificate flight is a variable, not a constant. This is the measurement
// that establishes it, and it is the one an emitter needs: sending a single
// observation verbatim would make us the only host whose certificate flight is
// byte-identical on every connection.
// The floor on the skips above: if no cover anywhere
// produced a resumed observation, the test verified nothing and says so.
func TestAtLeastOneCoverStillResumes(t *testing.T) {
	if os.Getenv("TWIDDLE_LIVE_PROBE") == "" {
		t.Skip("set TWIDDLE_LIVE_PROBE=1 to probe the real covers")
	}
	for _, host := range tw.MeasuredCovers() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		dial := func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
		}
		_, resumed, err := ProbeBoth(ctx, dial, host)
		cancel()
		if err == nil {
			t.Logf("%s resumed: ServerHello %d, remainder %v",
				host, resumed.ServerHello, resumed.Remainder)
			return
		}
	}
	t.Error("no measured cover resumed on any attempt; the resumed profile this transport imitates can no longer be observed anywhere")
}

func TestSampleFullObservesTheJitter(t *testing.T) {
	if os.Getenv("TWIDDLE_LIVE_PROBE") == "" {
		t.Skip("set TWIDDLE_LIVE_PROBE=1 to probe the real covers")
	}
	const samples = 5
	movers := 0
	for _, host := range tw.MeasuredCovers() {
		t.Run(host, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			dial := func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
			}
			base, jitter, err := SampleFull(ctx, dial, host, samples)
			if err != nil {
				t.Fatalf("sample: %v", err)
			}
			if len(jitter) != len(base.Remainder) {
				t.Fatalf("jitter %v does not match remainder %v", jitter, base.Remainder)
			}
			total := 0
			for _, j := range jitter {
				if j < 0 {
					t.Errorf("negative jitter %v", jitter)
				}
				total += j
			}
			if total > 0 {
				movers++
			}
			t.Logf("%s over %d samples: baseline %v, jitter %v", host, samples, base.Remainder, jitter)
		})
	}
	if movers == 0 {
		t.Error("no cover's certificate flight moved across samples; the ECDSA jitter measured earlier is not being observed")
	}
}
