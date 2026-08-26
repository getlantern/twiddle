package twiddle

import "crypto/rand"

// Shaping is fitted to measurement, not guessed. From 26,802 application_data
// records across 1,077 real browsing flows (harvest/testdata/record-profile.log):
//
//	client->server   median   87 B   59% are <=100 B   0.1% at max
//	server->client   median 1387 B   14.3% at max     mode 1395 B (5,347 of 20,222)
//
// Two things stand out. Server traffic is strongly bimodal -- an MTU-sized mode
// at 1395 bytes on the wire and a max-record mode at 16401 -- while client
// traffic is dominated by small h2 control frames. And the ratio is 3:1 server
// to client, which is what browsing looks like.
//
// Wire length is 5 (header) + inner + 16 (tag), and the length field a censor
// reads is inner+16. So the measured 1395 corresponds to 1379 inner bytes and
// 16401 to 16385.
//
// A Padder rounds UP to the nearest mode. It can never shrink a burst, which is
// why padding alone does not defeat encapsulated-handshake detection -- see
// docs/traffic-analysis.md. What it does buy is that our record lengths fall
// where real ones do instead of tracking the proxied protocol's own framing.

// Measured wire-length modes, most common first within each band.
var (
	clientModes = []int{26, 34, 53, 87, 317, 777, 1395, 16401}
	serverModes = []int{26, 34, 53, 57, 174, 1386, 1395, 16401}
)

const recordOverhead = 16 // AEAD tag; the inner content-type byte is counted separately

// BrowsingPadder returns a Padder fitted to the measured profile for one
// direction. Payloads round up to the nearest observed mode; anything larger
// than the biggest mode is left alone, since it will be split at maxPlaintext.
func BrowsingPadder(isServer bool) Padder {
	modes := clientModes
	if isServer {
		modes = serverModes
	}
	inner := make([]int, 0, len(modes))
	for _, m := range modes {
		if v := m - recordOverhead; v > 0 && v <= maxInner {
			inner = append(inner, v)
		}
	}
	return func(payload int) int {
		need := payload + 1 // payload plus the inner content-type byte
		for _, target := range inner {
			if need <= target {
				return target
			}
		}
		return need
	}
}

// JitteredPadder is BrowsingPadder with occasional promotion to the next mode
// up, so our size histogram is not sharper than real traffic's. Real records do
// not sit exactly on modes every time.
func JitteredPadder(isServer bool, promoteOneIn int) Padder {
	base := BrowsingPadder(isServer)
	modes := clientModes
	if isServer {
		modes = serverModes
	}
	return func(payload int) int {
		t := base(payload)
		if promoteOneIn > 1 && mrand(promoteOneIn) == 0 {
			for _, m := range modes {
				if v := m - recordOverhead; v > t {
					return v
				}
			}
		}
		return t
	}
}

// randByte is used by shaping decisions that need a coin flip.
func randByte() byte {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}
