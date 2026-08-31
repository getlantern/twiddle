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
  cmd/sweep/        repeated captures for per-connection variance
  analyze.py        compare full vs resumption hellos
  compare_arms.py   compare capture arms (headless vs headful, profile state)
  testdata/         captured hellos and measurement logs
```

Run the tools from `harvest/` — paths default to `testdata/`.

## Status

**Phase 0** — wire-format spike. The protocol packages do not exist yet; only the measurement tooling that
established the design is here.

This repo is **public**. It went public when `lantern-box/protocol/twiddle` began importing it: a public
module importing a private one forces credentials into every build, and CI proved the point by failing to
fetch it. The full design, measurements and rollout plan live in `getlantern/discovery-engine`, which is
private — references to it here will not resolve for outside readers.
