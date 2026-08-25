# Framing

What goes inside the `0x17` records, and why the constructions already in the Lantern tree are the wrong
shape for this transport.

## The observation that decides it

There are two layers, and **only one of them is observable**:

| Layer | What it does | Visible to a censor |
|---|---|---|
| **Record protection** | AEAD over each record's payload | only through *length* |
| **Shaping** | chooses record boundaries, padding, timing | **everything** |

A censor sees a sequence of `(length, direction, timestamp)` triples and nothing else. The AEAD is
invisible; the shaping policy *is* the fingerprint. So the crypto should be the most boring, best-analysed
thing available, and the design effort belongs in the layer above it.

## Why not the constructions we already have

Both in-tree candidates were designed for protocols that carry their length **on the wire in the clear**,
and both spend real bytes hiding it:

| Construction | Length handling | Cost here |
|---|---|---|
| BIP324 | encrypts the 3-byte length with a separate ChaCha20 key | redundant — the TLS record header carries the length anyway |
| Shadowsocks AEAD-2022 | `[enc len][tag][enc payload][tag]` — two AEAD invocations per chunk | **+16 bytes and an extra tag per record**, buying nothing |

Under TLS mimicry the record length **must** be cleartext in the 5-byte header. It is not ours to hide. So
every byte those constructions spend encrypting a length is pure overhead, and — worse — it perturbs our
record-length arithmetic away from TLS's.

This is a case where reuse is the wrong instinct: they solve a problem we are forbidden from having.

## Recommendation: mirror TLS 1.3's own record protection

```
record  = 0x17 0x03 0x03 ‖ len:u16 ‖ AEAD(key, nonce, aad, inner)
nonce   = static_iv XOR seq64          -- never on the wire
aad     = the 5-byte record header      -- binds the length
inner   = payload ‖ content_type:1 ‖ zeros(padding)
```

Six reasons, in rough order of weight:

1. **Overhead is exactly TLS's overhead** — 1 content-type byte plus a 16-byte tag, nothing else. Our record
   lengths are natively TLS-shaped rather than TLS-shaped-plus-a-constant. Any inner header we invented
   would offset every record by a fixed amount, which is a free structural signature.
2. **No nonce on the wire.** Sequence-derived, like TLS 1.3 — saves 12 bytes per record and matches
   structurally.
3. **Padding is native, not bolted on.** The `content_type`-at-the-end-then-zeros trick is what makes
   arbitrary padding free, and padding is the shaping layer's main instrument.
4. **The AAD binds the length**, so a censor cannot splice or truncate records undetected.
5. **`KeyUpdate` comes for free** if long-lived connections need rekeying — same mechanism, same records.
6. It is the most heavily analysed record layer that exists, and we have already committed to looking
   exactly like it.

Reuse TLS's own `content_type` values for the inner byte (`0x17` data, `0x16` control, `0x15` close). If the
construction is ever compromised and decrypted, what is inside still looks like TLS.

**Cipher choice is unconstrained by fidelity.** All three TLS 1.3 suites — `AES_128_GCM_SHA256`,
`AES_256_GCM_SHA384`, `CHACHA20_POLY1305_SHA256` — use a **16-byte tag**, so the suite has no effect on
record length. Pick on performance (ChaCha20 where AES is unaccelerated), and make the synthesised
ServerHello *claim* the suite we actually use, since the suite's hash does set the PSK binder length
(32 vs 48 bytes).

**Multiplexing is required.** An earlier version of this document said the opposite — that a single proxied
byte stream needed no inner framing. That is wrong: Xue et al. 2024 show that any proxy wrapping TLS-bearing
traffic leaks its inner handshakes, and that mux is the countermeasure protocol designers "should treat as a
required component, not an optional optimization." Multiplexing means the inner framing **does** need stream
IDs and per-stream lengths. See [traffic-analysis.md](traffic-analysis.md).

## The part that actually needs design: shaping

This is where a naive implementation leaks. Writing one record per `Write()` call republishes the proxied
protocol's own framing directly into the record-length sequence — the tunnel would be transparent to
traffic analysis despite perfect crypto.

The shaping layer must at minimum:

- **coalesce** small writes rather than emitting a record each
- **split** large writes at plausible boundaries (TLS max plaintext is 2^14 = 16384, but real servers
  frequently use less)
- **pad** toward a target size distribution — but note that **padding alone provably does not defeat
  TLS-in-TLS detection**; it cannot shrink burst sizes or round-trip counts
- **avoid** a fixed inter-record timing signature — and, more importantly, avoid *regularising* the
  human-driven timing already present in the stream, which is a stronger defence than any jitter we could
  synthesise (see [traffic-analysis.md](traffic-analysis.md))

And the target distribution should be *measured*, not guessed. The flight measurements in
`harvest/testdata/tls13-flight.log` cover only the handshake; **steady-state browsing record sizes are not
yet measured**, and that is the input this layer needs. `harvest/cmd/tapproxy` already sits in the right
place to collect it.

## Open

- Measure steady-state record-size and timing distributions from real browsing.
- Decide whether the fake certificate flight and the data stream share one key or use two (two mirrors real
  TLS; one is simpler and equally opaque).
