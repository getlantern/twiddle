# twiddle

**[→ twiddle.lantern.io](https://twiddle.lantern.io)** — an interactive byte-by-byte walkthrough of a real
ClientHello, every field we change, and the measurement behind each decision. Source in [`site/`](site).

A TLS-shaped transport whose opening bytes are a **genuine ClientHello harvested from a real browser**,
whose ServerHello is synthesised, and whose payload is an ordinary AEAD tunnel framed as TLS
`application_data` (`0x17`) records.

The name describes the method: we take genuine browser bytes and **twiddle** a handful of fields — the SNI,
the authenticator, the extension order — leaving everything else exactly as the browser produced it.

The security property is not concealment. It is being indistinguishable from the most common thing on the
wire, so that blocking it costs the censor everything else. A gray sedan on a motorway is not hidden; it is
simply not worth pulling over, and pulling it over means pulling over ten thousand identical cars.

## Why this works

Every TLS 1.3 handshake message after the ServerHello is encrypted and framed as an `application_data`
record. Measured against real servers, the entire observable structure of a TLS 1.3 connection is:

| Record | Type | Fidelity required |
|---|---|---|
| ClientHello | `0x16` | **exact** — harvested from a real browser |
| ChangeCipherSpec | `0x14` | one fixed byte |
| ServerHello | `0x16` | structurally plausible (1210 B, PQ-sized `key_share`) |
| ChangeCipherSpec | `0x14` | one fixed byte |
| everything else, forever | `0x17` | **shape only** — opaque to any observer |

So the connection need not be TLS at all. That removes uTLS as a handshake engine, the `key_share`
ephemeral splice, PSK binders as a cryptographic obligation, HelloRetryRequest, and the whole
preset-staleness treadmill. This module depends on **no TLS library** for its own operation.

## Authentication

Two paths, because the richest carrier is not present on every hello:

| Hello type | Carrier |
|---|---|
| resumption | PSK ticket (uniform ephemeral) + binder (MAC) — both opaque *by specification* |
| full handshake | `ClientHello.random` carries the MAC; `key_share` supplies the ephemeral |

**Optional extensions are fidelity obligations when present, never carriers.** Nothing here may depend on a
field only some browser installs send — BoringSSL's `server_padding` (`0x12e0`) is the cautionary case.

## Where the hellos come from

`LoadPool` tries device and config sources in descending order of preference. Its compiled-in snapshot is
available only through the explicit `AllowEmbedded` test fallback:

| Source | Why it ranks here |
|---|---|
| **device** — tapped from this device's own outbound TLS | The only source that cannot go stale: by construction it is what the browser on *this* device emits right now, from the version installed here, with this device's field-trial state |
| **config** — delivered by the config service | Refreshable without shipping a binary |
| **embedded** — `pool/chrome.hex` | Opt-in for tests only; already stale as Chrome moves |

Sources are never merged, and an incoherent source is partitioned by build with the majority winning. A real
browser install emits hellos from exactly one build, so a pool blending two would have this client
alternating fingerprints between TCP connections — which no browser does, and which is a sharper signal than
either pool alone.

The decay is not hypothetical. The embedded pool carries BoringSSL's `server_padding` (`0x12e0`) and runs
1725–1827 bytes; Chrome 152 has dropped `0x12e0`, added `0xca34`, and runs 1919–2015 bytes. It also is not
internally coherent — four of its eight hellos carry `0x12e0` and four do not, because the capture arms
mixed a fresh Chrome profile with an established one.

Hellos tapped off real traffic must be passed through `Sanitize` **before** they are written to disk: a
tapped hello names a site the user actually visited, and a resumption hello also carries that site's session
ticket. Neither belongs in a file we persist.

## Probe resistance

We cannot complete a real TLS handshake, so the splitting egress is load-bearing rather than optional: any
connection that fails authentication is forwarded verbatim to a real cover site, which answers it.

## Layout

```
harvest/            capture and measurement tooling
  cmd/harvest/      capture a browser ClientHello off a local listener
  cmd/capture/      locally-trusted TLS 1.3 server that taps every raw ClientHello
  cmd/resume/       measure session-resumption hellos against real servers
  cmd/flight/       measure the server-side record profile of real TLS 1.3 servers
  cmd/tapproxy/     byte-tap in front of an upstream TLS server (0-RTT measurement)
  cmd/arrival/      how the opening flight is packetised: TCP writes, QUIC datagrams
  cmd/sweep/        repeated captures for per-connection variance
  analyze.py        compare full vs resumption hellos
  compare_arms.py   compare capture arms (headless vs headful, profile state)
  testdata/         captured hellos and measurement logs
docs/               design notes, each backed by a measurement log
  ech.md            why the pooled hellos carry GREASE ECH, and what censors do to ECH
  packetisation.md  TCP writes vs QUIC datagrams; Chaos Protection and a future QUIC mode
site/               source of twiddle.lantern.io, the byte-by-byte walkthrough
```

For the fields themselves — every byte of a real hello, what we change and why — read
**[twiddle.lantern.io](https://twiddle.lantern.io)** rather than the source; it is the same decisions with
the offsets drawn in.

Run the tools from `harvest/` — paths default to `testdata/`.

## Status

**The transport works end to end.** `Client` and `Server` complete an opening, agree a session and carry
traffic over the AEAD record layer, and `go test` covers it over a real socket. What is here:

| | |
|---|---|
| `hello.go` | parse / marshal a ClientHello with extensions held opaque |
| `twiddle.go` | `Shuffle`, `Rerandomize`, and the `Twiddle` emission pipeline |
| `auth.go` | ticket issue/open, `key_share` ephemeral, binder MAC, verification |
| `serverhello.go` | ServerHello synthesis at the measured 1210 B shape |
| `conn.go` | AEAD record layer framed as `application_data` |
| `shaping.go` | record segmentation and padding to the measured browsing profile |
| `source.go`, `pool.go` | hello sourcing: device tap, config, opt-in test fallback |
| `harvest/` | the measurement tooling that established every number above |

Not here yet, and both live on the consumer side rather than in this module:

- **The splitting egress.** `Server` returns `ErrNotOurs` for a connection that fails to authenticate; some
  caller must then forward those bytes verbatim to a real cover site, or an active prober gets silence where
  a real server would answer — see [`docs/passthrough.md`](docs/passthrough.md). The sing-box inbound below
  does this, replaying the peeked bytes byte for byte.
- **Credential provisioning.** `TicketKey.Issue` mints credentials and the egress rotates them inside each
  flight, but the first one has to arrive out of band.

Known fidelity gaps, both measured:

- **`0xca34`'s body is not reproduced.** Chrome 152 varies it per connection at a constant 206 bytes — two
  hellos from one browser carry different contents — and nothing here regenerates that. It is why several
  same-build hellos in a pool are worth holding rather than one: the pool is sampling the variation we
  cannot synthesise. Reproducing it properly means understanding the extension (it looks like Trust Anchor
  Identifiers), which wants its own measurement pass. The embedded pool predates the extension, so this
  bites the device tap — the *preferred* source — and not today's default.
- **The site walkthrough is a version behind.** [twiddle.lantern.io](https://twiddle.lantern.io) annotates a
  hello carrying `server_padding` (`0x12e0`), which Chrome 152 no longer sends, and does not mention
  `0xca34`, which it does.

Recently closed, both found by measuring rather than reading:

- **GREASE is now redrawn per connection.** `Rerandomize` previously left every GREASE codepoint at the
  harvested value, so a pool of eight hellos emitted eight fixed draws forever where Chrome draws from
  sixteen per connection. Six slots are now redrawn — the leading cipher suite, the first and last
  extension types, `supported_groups`, `supported_versions` and `signature_algorithms` — keeping the two
  constraints real hellos hold on 15 of 15 captures: the two extension draws differ, and the
  `key_share` group is the *same* value as `supported_groups`.
- **The GREASE `key_share` value is zero, not random.** It was filled with `rand.Read`; Chrome sends a
  single `0x00` byte on 15 of 15 measured entries. Randomising it was wrong 255 times in 256, on every
  connection.

The sing-box adapter for both — inbound, outbound and options — is in `lantern-box` on
`fisk/twiddle-transport`.

This repo is **public**. It went public when `lantern-box/protocol/twiddle` began importing it: a public
module importing a private one forces credentials into every build, and CI proved the point by failing to
fetch it. The full design, measurements and rollout plan live in `getlantern/discovery-engine`, which is
private — references to it here will not resolve for outside readers.
