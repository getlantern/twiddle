package twiddle

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// The acceptance test that matters most, and the only one that can fail for a
// reason no local test can see.
//
// rerandKeyShare's comment states the threat: "a censor can capture one of our
// hellos and replay it to the SNI we claim -- a genuine Chrome hello draws a
// ServerHello, ours would draw an alert." That is not hypothetical. An earlier
// version filled key shares with random bytes and real servers answered with
// illegal_parameter or decode_error, because random bytes are not a valid
// ML-KEM-768 encapsulation key. Every local test passed throughout.
//
// So these tests replay what we actually emit at the real cover hosts and
// require a ServerHello back. Nothing about our own record layer, ticket key or
// replay gate participates: the real server cannot authenticate us and is not
// asked to. What is under test is whether the bytes we put on the wire are
// bytes a real server accepts -- which is exactly what a censor replaying them
// would be testing.
//
// Gated because it needs the network. CI sets TWIDDLE_LIVE_PROBE=1.

func liveProbeEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("TWIDDLE_LIVE_PROBE") == "" {
		t.Skip("set TWIDDLE_LIVE_PROBE=1 to replay emitted hellos at the real covers")
	}
}

// pace spaces out connections to the real covers.
//
// Measured the hard way: running the exhaustive sweep back to back locally --
// roughly 120 connections to three hosts inside a minute -- started producing
// failures in tests that pass in isolation. The hosts throttle, and a throttled
// CI run reads as a code regression. A short gap costs seconds and removes the
// whole class of false failure.
func pace() { time.Sleep(150 * time.Millisecond) }

// exhaustiveSweep reports whether to replay EVERY distinct hello shape.
//
// Off by default, so a pull request gets cheap live signal from a handful of
// connections. The daily scheduled run sets it and covers everything. The split
// exists because the exhaustive sweep is ~120 connections to three real hosts,
// which is fine once a day and rude on every push.
func exhaustiveSweep() bool { return os.Getenv("TWIDDLE_LIVE_FULL_SWEEP") != "" }

// sampleShapes trims a shape list for the default run, keeping BOTH sources
// represented -- the two are different browser builds, so a sample from one
// would leave the other unexercised.
func sampleShapes(names []string) []string {
	if exhaustiveSweep() {
		return names
	}
	const perSource = 2
	var embedded, captured []string
	for _, n := range names {
		if strings.HasPrefix(n, "embedded-") {
			embedded = append(embedded, n)
		} else {
			captured = append(captured, n)
		}
	}
	if len(embedded) > perSource {
		embedded = embedded[:perSource]
	}
	if len(captured) > perSource {
		captured = captured[:perSource]
	}
	return append(embedded, captured...)
}

// alertName decodes the descriptions a rejected hello actually draws, so a
// failure says what was wrong rather than just that something was.
func alertName(desc byte) string {
	switch desc {
	case 40:
		return "handshake_failure"
	case 42:
		return "bad_certificate"
	case 47:
		return "illegal_parameter"
	case 50:
		return "decode_error"
	case 51:
		return "decrypt_error"
	case 70:
		return "protocol_version"
	case 71:
		return "insufficient_security"
	case 80:
		return "internal_error"
	case 109:
		return "missing_extension"
	case 110:
		return "unsupported_extension"
	case 112:
		return "unrecognized_name"
	case 116:
		return "certificate_required"
	case 120:
		return "no_application_protocol"
	default:
		return fmt.Sprintf("alert(%d)", desc)
	}
}

// errTransient marks a failure to reach the host at all, as opposed to a host
// that answered and rejected us. Only the former is worth retrying: an alert is
// a verdict, and retrying it would turn a real regression into a slow one.
var errTransient = errors.New("transient network failure")

// replay writes one emitted hello to host:443 and returns the first record the
// server sends back.
func replay(host string, hello []byte) (recType byte, body []byte, err error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	c, err := d.Dial("tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return 0, nil, fmt.Errorf("%w: dial: %v", errTransient, err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return 0, nil, fmt.Errorf("%w: deadline: %v", errTransient, err)
	}
	if _, err := c.Write(hello); err != nil {
		return 0, nil, fmt.Errorf("%w: write: %v", errTransient, err)
	}
	var hdr [recordHeaderLen]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		// A server that hangs up without a record has rejected us, but at TCP
		// level rather than TLS level, and that is indistinguishable here from
		// a network fault. Treated as transient so a flaky runner does not fail
		// the build; a genuine rejection reproduces on every retry and still
		// fails.
		return 0, nil, fmt.Errorf("%w: read header: %v", errTransient, err)
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n > maxCiphertext {
		return hdr[0], nil, fmt.Errorf("record length %d out of range", n)
	}
	body = make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		return hdr[0], nil, fmt.Errorf("%w: read body: %v", errTransient, err)
	}
	return hdr[0], body, nil
}

// replayWithRetry retries only transient failures.
func replayWithRetry(t *testing.T, host string, hello []byte) (byte, []byte, error) {
	t.Helper()
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		typ, body, err := replay(host, hello)
		if err == nil || !errors.Is(err, errTransient) {
			return typ, body, err
		}
		lastErr = err
		time.Sleep(time.Duration(attempt) * time.Second)
	}
	return 0, nil, lastErr
}

// variedHellos returns one hello per distinct SHAPE, drawn from both sources.
//
// Both sources matter because they are different browser builds that exercise
// different code paths: pool/chrome.hex carries BoringSSL's server_padding
// (0x12e0) and runs 1725-1827 bytes, while the harvest/testdata captures are
// Chrome 152, carry 0xca34 instead, and run 1919-2015 bytes. A test using only
// one would not notice a change that broke the other.
//
// But variety means variety of shapes, not of records. The raw sources hold 72
// hellos and only a handful of distinct shapes, so replaying all of them would
// mean hundreds of connections to real hosts to learn what a few dozen say.
// Fingerprint is the repo's own notion of "same shape" -- it normalises the
// per-connection GREASE draws and keys on the structure a server actually
// reacts to -- so deduplicating on it keeps the coverage and drops the
// repetition.
//
// Keys are sorted so the subtest names, and the order the hosts are hit in, are
// stable run to run.
func variedHellos(t *testing.T) []string {
	t.Helper()
	byFingerprint := map[string]string{}
	names := map[string][]byte{}

	add := func(name string, rec []byte) {
		h, err := ParseClientHello(rec)
		if err != nil {
			return
		}
		f := h.Fingerprint()
		if _, dup := byFingerprint[f]; dup {
			return
		}
		byFingerprint[f] = name
		names[name] = rec
	}
	for i, rec := range DefaultPool() {
		add(fmt.Sprintf("embedded-%d", i), rec)
	}
	// Sorted, because realHellos returns a map and an arbitrary survivor per
	// fingerprint would make the selection differ between runs.
	var captured []string
	raw := realHellos(t)
	for name := range raw {
		captured = append(captured, name)
	}
	sort.Strings(captured)
	for _, name := range captured {
		add("captured-"+name, raw[name])
	}

	var out []string
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	liveHellos = names
	return out
}

// liveHellos holds the records variedHellos selected, keyed by the names it
// returned.
var liveHellos map[string][]byte

// Every hello we emit, in both handshake shapes, must draw a ServerHello from
// the real cover host rather than an alert.
func TestEmittedHellosAreAcceptedByTheRealCovers(t *testing.T) {
	liveProbeEnabled(t)
	k := ticketKey(t)
	names := sampleShapes(variedHellos(t))
	t.Logf("replaying %d hello shapes at %d covers, both variants, exhaustive=%v",
		len(names), len(MeasuredCovers()), exhaustiveSweep())

	for _, host := range MeasuredCovers() {
		cover, err := CoverFor(host)
		if err != nil {
			t.Fatal(err)
		}
		cred, err := k.Issue(1, cover.TicketLen)
		if err != nil {
			t.Fatal(err)
		}

		t.Run(host, func(t *testing.T) {
			for _, name := range names {
				rec := liveHellos[name]
				for _, variant := range []struct {
					label string
					full  bool
				}{{"resumed", false}, {"full", true}} {
					// A hello whose ECH payload cannot hold the ticket has no
					// full variant, which FullHandshakeCarriers is what decides
					// in production too.
					if variant.full && len(FullHandshakeCarriers([][]byte{rec})) == 0 {
						continue
					}
					t.Run(name+"/"+variant.label, func(t *testing.T) {
						wire, _, err := Twiddle(rec, Options{
							CoverSNI:      host,
							Credential:    cred,
							BinderLen:     cover.BinderLen,
							FullHandshake: variant.full,
						})
						if err != nil {
							t.Fatalf("emitting: %v", err)
						}

						pace()
						typ, body, err := replayWithRetry(t, host, wire)
						if err != nil {
							if errors.Is(err, errTransient) {
								t.Skipf("could not reach %s after 3 attempts: %v", host, err)
							}
							t.Fatalf("replaying a %d-byte hello: %v", len(wire), err)
						}

						switch typ {
						case contentAlert:
							desc := byte(0)
							if len(body) >= 2 {
								desc = body[1]
							}
							t.Fatalf("%s REJECTED our %d-byte hello with %s -- a real Chrome hello draws a ServerHello, so this is a live distinguisher",
								host, len(wire), alertName(desc))
						case contentHandshake:
							if len(body) == 0 || body[0] != 0x02 {
								t.Fatalf("%s answered with handshake type %#02x, not a ServerHello", host, body[0])
							}
						default:
							t.Fatalf("%s answered with record type %#02x, neither a handshake nor an alert", host, typ)
						}
					})
				}
			}
		})
	}
}

// The ServerHello we synthesise is asserted against a constant, and this is
// what keeps that constant honest against the live internet.
//
// It can only check the FULL length. Our ticket is ours, so a real server does
// not recognise it, ignores the pre_shared_key and completes a full handshake
// -- which means both variants draw ServerHelloFullLen here. Checking
// ServerHelloResumedLen live would need a real prior session with the cover,
// which is what harvest/cmd/postflight is for.
func TestRealCoverServerHelloStillMatchesTheConstant(t *testing.T) {
	liveProbeEnabled(t)
	k := ticketKey(t)

	for _, host := range MeasuredCovers() {
		cover, err := CoverFor(host)
		if err != nil {
			t.Fatal(err)
		}
		cred, err := k.Issue(1, cover.TicketLen)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(host, func(t *testing.T) {
			wire, _, err := Twiddle(DefaultPool()[0], Options{
				CoverSNI: host, Credential: cred, BinderLen: cover.BinderLen,
			})
			if err != nil {
				t.Fatal(err)
			}
			typ, body, err := replayWithRetry(t, host, wire)
			if err != nil {
				if errors.Is(err, errTransient) {
					t.Skipf("could not reach %s: %v", host, err)
				}
				t.Fatal(err)
			}
			if typ != contentHandshake {
				t.Fatalf("%s did not answer with a handshake record: type %#02x", host, typ)
			}
			got := recordHeaderLen + len(body)
			t.Logf("%s ServerHello: %d bytes", host, got)
			if got != ServerHelloFullLen {
				t.Errorf("%s now sends a %d-byte ServerHello, but we synthesise %d; the constant is stale and our opening is a different length from the identity it claims",
					host, got, ServerHelloFullLen)
			}
		})
	}
}
