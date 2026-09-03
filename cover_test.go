package twiddle

import (
	"slices"
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
