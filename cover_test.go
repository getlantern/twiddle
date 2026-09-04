package twiddle

import (
	"slices"
	"strings"
	"testing"
)

// TestCoverProfilesMatchTheMeasurements pins the cover table against the
// capture logs, independently of the table itself.
//
// This exists because the emission tests cannot catch a wrong profile: they
// compare what the emitter writes against the profile that drove it, so the
// profile is its own oracle and any self-consistent edit passes. Collapsing
// microsoft's remainder from 32/74 back to a single 106 kept
// TestOpeningRecordSequenceMatchesCover green while putting 3 server records on
// the wire where the real identity puts 4 — exactly the bug that shipped.
//
// The literals below are transcribed from the logs, so editing the table alone
// fails here. If a measurement is genuinely redone, update both, and say which
// log the new number came from.
func TestCoverProfilesMatchTheMeasurements(t *testing.T) {
	// Sources:
	//   ticket lengths            harvest/cmd/resume        (tls13-resume.log)
	//   PSK extension order       harvest/cmd/shresume
	//   ServerHello 1221          serverhello-resumption-delta.log
	//   burst totals, ResumedClientFlight  tls13-burst-resumption.log  (Chrome)
	//   remainder record SPLIT    postflight-resumed.log      (server side)
	want := map[string]struct {
		cipher       uint16
		binderLen    int
		ticketLen    int
		pskFirst     bool
		remainder    []int
		openingBurst int
		clientFlight int
	}{
		"www.cloudflare.com": {TLS_AES_128_GCM_SHA256, 32, 176, true, []int{64}, 1291, 149},
		"www.google.com":     {TLS_AES_128_GCM_SHA256, 32, 230, true, []int{64}, 1291, 145},
		"www.microsoft.com":  {TLS_AES_256_GCM_SHA384, 48, 256, false, []int{32, 74}, 1333, 164},
	}

	covers := MeasuredCovers()
	if len(covers) != len(want) {
		t.Fatalf("MeasuredCovers has %d entries, this test pins %d: %v", len(covers), len(want), covers)
	}
	for _, host := range covers {
		w, ok := want[host]
		if !ok {
			t.Errorf("%s is offered as a cover but is not pinned to a measurement here", host)
			continue
		}
		p, err := CoverFor(host)
		if err != nil {
			t.Errorf("%s: %v", host, err)
			continue
		}
		if p.CipherSuite != w.cipher {
			t.Errorf("%s cipher %#04x, measured %#04x", host, p.CipherSuite, w.cipher)
		}
		if p.BinderLen != w.binderLen {
			t.Errorf("%s binder %d, measured %d", host, p.BinderLen, w.binderLen)
		}
		if p.TicketLen != w.ticketLen {
			t.Errorf("%s ticket %d, measured %d", host, p.TicketLen, w.ticketLen)
		}
		if p.PSKFirst != w.pskFirst {
			t.Errorf("%s PSKFirst %v, measured %v", host, p.PSKFirst, w.pskFirst)
		}
		if !slices.Equal(p.ResumedRemainder, w.remainder) {
			t.Errorf("%s server remainder %v, measured %v", host, p.ResumedRemainder, w.remainder)
		}
		if p.ResumedClientFlight != w.clientFlight {
			t.Errorf("%s client flight %d, measured %d", host, p.ResumedClientFlight, w.clientFlight)
		}
		// The derived total must agree with the burst the captures recorded,
		// which is what catches a remainder edited to the right total by the
		// wrong split, or vice versa.
		if got := p.ResumedOpeningBurst(); got != w.openingBurst {
			t.Errorf("%s opening burst %d, measured %d", host, got, w.openingBurst)
		}
	}
}

// The remainder is a sequence precisely because two covers coalesce
// EncryptedExtensions and Finished while one does not. A table where every
// entry is a single record would mean the split was never modelled.
func TestSomeCoverSplitsItsRemainder(t *testing.T) {
	var split, single int
	for _, host := range MeasuredCovers() {
		p, err := CoverFor(host)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.ResumedRemainder) == 0 {
			t.Errorf("%s has an empty remainder; the server always sends one", host)
		}
		if len(p.ResumedRemainder) > 1 {
			split++
		} else {
			single++
		}
	}
	if split == 0 {
		t.Error("no cover splits its remainder; microsoft was measured at 32/74, so the split is not modelled")
	}
	if single == 0 {
		t.Error("every cover splits; cloudflare and google were measured coalescing into one 64 B record")
	}
}

// CoverFor lowercases before its lookup, so every per-cover helper must agree
// on case or they answer differently for the same host.
func TestPerCoverHelpersAreCaseInsensitive(t *testing.T) {
	for _, host := range MeasuredCovers() {
		upper := strings.ToUpper(host)
		if got, want := TicketLenForCover(upper), TicketLenForCover(host); got != want {
			t.Errorf("TicketLenForCover(%q)=%d but (%q)=%d", upper, got, host, want)
		}
		if got, want := PSKFirstForCover(upper), PSKFirstForCover(host); got != want {
			t.Errorf("PSKFirstForCover(%q)=%v but (%q)=%v", upper, got, host, want)
		}
	}
	// The github.com fallback is a literal compare, so it is the one that can
	// disagree: 32 is the recorded measurement, DefaultTicketLen is not.
	if got := TicketLenForCover("GitHub.com"); got != 32 {
		t.Errorf("TicketLenForCover(\"GitHub.com\")=%d, want the recorded 32", got)
	}
}

// DrawFullRemainder must actually move. An emitter that sent FullRemainder
// verbatim would be the only host on the network whose certificate flight is
// byte-identical on every connection -- and every test that merely checks the
// sequence is "plausible" would still pass, which is why this asserts variation
// rather than membership.
func TestDrawFullRemainderVariesWithinTheSampledRange(t *testing.T) {
	p := CoverProfile{
		Host:                "example.test",
		FullRemainder:       []int{3846, 100, 8273},
		FullRemainderJitter: []int{2, 0, 1},
	}
	seen := make([]map[int]bool, len(p.FullRemainder))
	for i := range seen {
		seen[i] = map[int]bool{}
	}
	for i := 0; i < 400; i++ {
		got, err := p.DrawFullRemainder()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(p.FullRemainder) {
			t.Fatalf("drew %d records, want %d", len(got), len(p.FullRemainder))
		}
		for j, n := range got {
			lo := p.FullRemainder[j]
			hi := lo + p.FullRemainderJitter[j]
			if n < lo || n > hi {
				t.Fatalf("record %d drew %d, outside the sampled [%d, %d]", j, n, lo, hi)
			}
			seen[j][n] = true
		}
	}
	// Position 0 has jitter 2 and position 2 has jitter 1, so both must have
	// produced more than one value. Position 1 has jitter 0 and must not.
	if len(seen[0]) != 3 {
		t.Errorf("record 0 produced %d distinct lengths over 400 draws, want all 3 of [3846, 3848]: %v", len(seen[0]), seen[0])
	}
	if len(seen[1]) != 1 {
		t.Errorf("record 1 has zero jitter but produced %v", seen[1])
	}
	if len(seen[2]) != 2 {
		t.Errorf("record 2 produced %d distinct lengths over 400 draws, want 2: %v", len(seen[2]), seen[2])
	}
}

// A baseline adopted without its range is what produces the never-varying
// flight above, so Adopt must carry the jitter and must refuse a result whose
// jitter does not line up with its remainder.
func TestAdoptCarriesTheFullRemainderJitter(t *testing.T) {
	base, err := CoverFor("www.microsoft.com")
	if err != nil {
		t.Fatal(err)
	}
	remainder := []int{32, 8273, 286, 74}
	burst := ServerHelloFullLen + len(ChangeCipherSpec())
	for _, n := range remainder {
		burst += n
	}
	res := ProbeResult{
		Host: base.Host, Full: true, ServerHello: ServerHelloFullLen,
		Remainder: remainder, RemainderJitter: []int{0, 1, 0, 0}, OpeningBurst: burst,
	}

	got, err := base.Adopt(res)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.FullRemainderJitter, res.RemainderJitter) {
		t.Errorf("adopted jitter %v, want %v", got.FullRemainderJitter, res.RemainderJitter)
	}

	// A jitter of the wrong length cannot be applied position-by-position, and
	// silently ignoring it would drop the variation without saying so.
	bad := res
	bad.RemainderJitter = []int{0, 1}
	if _, err := base.Adopt(bad); err == nil {
		t.Error("a jitter shorter than the remainder was adopted")
	}
	if _, err := (CoverProfile{
		Host:                base.Host,
		FullRemainder:       remainder,
		FullRemainderJitter: []int{0, 1},
	}).DrawFullRemainder(); err == nil {
		t.Error("DrawFullRemainder accepted a mismatched jitter")
	}
}
