package twiddle

// Shaping is fitted to measurement. From 26,802 application_data records across
// 1,077 real browsing flows (harvest/testdata/record-profile.log):
//
//	client->server   median   87 B   59% are <=100 B   0.1% at max
//	server->client   median 1387 B   14.3% at max      mode 1395 B (5,347 of 20,222)
//
// Server traffic is strongly bimodal -- an MTU-sized mode at 1395 bytes and a
// max-record mode at 16401 -- while client traffic is almost all small h2
// control frames, at a 3:1 server-to-client ratio.
//
// Padding ALONE is not enough, and the failure is severe. A proxied connection
// carries inner TLS records, so an MTU-sized one arrives as ~1400 bytes. Padding
// that up to the next mode means jumping from 1379 to 16385 inner -- an 11.9x
// bandwidth amplification on the single most common payload size. Real servers
// do not do that: they SEGMENT, emitting a run of 1395-byte records and a
// remainder. So the shaper decides both how much to take and what to pad to.

// Measured wire-length buckets per direction, ascending. Every value is a size
// actually observed in the capture; none is invented.
//
// Chosen by pinning the six most frequent sizes -- where real traffic genuinely
// clusters, including the 1395 server mode that is 26% of records -- then filling
// gaps so that rounding a payload up to the next bucket never costs more than
// ~1.6x. Weighted by how often each size actually occurs, expected overhead is
// 1.086x client and 1.057x server, with 49% and 66% of real records already
// landing exactly on a bucket.
//
// An earlier eight-bucket list taken from the top modes alone left a gap between
// 174 and 1386, so a 500-byte payload cost 2.8x. Bucket spacing matters as much
// as bucket choice.
var (
	clientModes = []int{
		26, 30, 34, 53, 69, 87, 94, 114, 124, 197,
		278, 419, 601, 773, 1034, 1256, 1644, 2356, 3771, 6019,
		9182, 13732, 16408,
	}
	serverModes = []int{
		26, 34, 53, 57, 69, 74, 96, 135, 174, 210,
		281, 298, 445, 551, 749, 1109, 1395, 2011, 3039, 4246,
		4389, 6852, 7496, 10101, 11317, 16401,
	}
)

const recordOverhead = 16 // AEAD tag; the inner content-type byte is counted separately

// Shaper decides the next record given how many payload bytes are pending.
// take is how many to consume; padTo is the inner length to pad that record to.
type Shaper interface {
	Next(available int) (take, padTo int)
}

// ShaperFunc adapts a function to Shaper.
type ShaperFunc func(available int) (int, int)

func (f ShaperFunc) Next(a int) (int, int) { return f(a) }

// PlainShaper emits records that exactly fit the payload, with no padding. It
// republishes the proxied protocol's framing into the record-length sequence and
// exists only for tests and comparison.
func PlainShaper() Shaper {
	return ShaperFunc(func(a int) (int, int) {
		if a > maxPlaintext {
			a = maxPlaintext
		}
		return a, a + 1
	})
}

// BrowsingShaper segments and pads to the measured profile for one direction.
func BrowsingShaper(isServer bool) Shaper {
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
	// bulk is the largest non-max mode: the size a run of records is built from.
	bulk := inner[0]
	for _, v := range inner {
		if v < maxInner && v > bulk {
			bulk = v
		}
	}

	return ShaperFunc(func(available int) (int, int) {
		need := available + 1 // payload plus the inner content-type byte

		// Small enough for a single non-max record: pad up to the nearest mode.
		if need <= bulk {
			for _, v := range inner {
				if v >= need {
					return available, v
				}
			}
		}
		// Large enough to justify a max-size record.
		if available >= maxPlaintext {
			return maxPlaintext, maxInner
		}
		// Otherwise fill one bulk-sized record exactly and leave the rest,
		// which is what a real server does with a multi-KB response.
		return bulk - 1, bulk
	})
}
