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
			if !slices.Equal(got.ServerRemainder, base.ServerRemainder) {
				t.Errorf("live remainder %v differs from the table's %v — the table is stale, or the identity changed",
					got.ServerRemainder, base.ServerRemainder)
			}
			if got.ServerOpeningBurst() != base.ServerOpeningBurst() {
				t.Errorf("live burst %d, table %d", got.ServerOpeningBurst(), base.ServerOpeningBurst())
			}
		})
	}
}
