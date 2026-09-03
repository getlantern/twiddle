package coverprobe

import (
	"context"
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
