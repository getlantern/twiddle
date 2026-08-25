# Passthrough mode: don't wrap the user's TLS, carry it

For TLS-bearing traffic — the majority of what a Lantern user generates — wrapping is the thing that
creates the fingerprint. This mode removes the wrapping instead of shaping around it.

## The shape

```
client                          proxy                       example.com
  |-- theatrical ClientHello ----->|                              |     auth
  |<-- theatrical ServerHello -----|                              |
  |                                |                              |
  |-- user's REAL ClientHello ---->|-- forwarded VERBATIM ------->|     SNI read here
  |<-- real ServerHello -----------|<-- relayed VERBATIM ---------|
  |                                |                              |
  |<========= RAW BIDIRECTIONAL PASSTHROUGH, NO FRAMING =========>|
```

The theatrical handshake exists **only to authenticate**. After it, the connection carries the user's
genuine TLS session, byte for byte.

## Why this is stronger than shaping

It does not mitigate the Xue attack — it **dissolves** it.

| Problem | Wrapped tunnel | Passthrough |
|---|---|---|
| Inner-handshake burst | present, must be hidden | there is no *inner* handshake — it is the outer one |
| Record sizes | ours, must be shaped | the real session's, exactly |
| Inter-arrival timing | ours, must not regularise human entropy | **is** human entropy, untouched |
| Multiple inner sessions stacked | the strongest Xue signal | 1:1 — one user session per connection |
| Framing overhead | 1 byte + 16-byte tag per record | **zero** |

The AEGIS human-entropy result (`2026-ferrel-aegis-adversarial-entropy-guided`, detection collapses to
1.17% on genuine human browsing) applies here maximally: this is not human-driven traffic *through* a
proxy, it is the traffic itself.

**And it removes the mux requirement.** Mux was needed to hide *stacked* inner handshakes. With a 1:1
mapping there is nothing to stack — and a browser opening 6–30 parallel connections per page load is what a
browser normally looks like, so 1:1 is *more* natural than mux, not less.

## Two problems, and both are fixable

### 1. SNI would be in the clear

Passing the user's ClientHello verbatim over the wire puts the real SNI in cleartext between client and
proxy — which defeats the entire purpose. ECH would fix it, but adoption is partial and censors strip it.

**Fix: wrap exactly two records, then go raw.** In TLS 1.3, *only* the ClientHello and ServerHello are
`0x16`; every subsequent handshake message is already an opaque `0x17` record. So:

| Record | Treatment |
|---|---|
| user's ClientHello | **wrapped** in our AEAD as `0x17` — hides the SNI |
| example.com's ServerHello | **wrapped** as `0x17` |
| everything after, both directions | **raw passthrough** |

Two records wrapped, and essentially every byte of the session passes untouched. The transcript still
verifies end-to-end: the proxy unwraps and forwards the *original* ClientHello bytes, so client and server
hash identical transcripts. This is real TLS to example.com, with real certificate validation and real
pinning — the proxy never sees plaintext.

### 2. Two handshakes and two round trips

The residual tell the double-ClientHello creates. Two mitigations, and they compose:

**Use a resumption opening.** A theatrical *resumption* handshake is far lighter than a full one — no
certificate flight to imitate, just a small EncryptedExtensions + Finished. The overall connection then
reads as: light resumption handshake, a ~1.8 KB client record, a ~3–5 KB server response, then a session.
**That is what a resumed HTTPS connection doing a page load looks like.** The PSK work is not just an auth
carrier; it makes the opening cheap enough to hide behind.

**Pipeline to reclaim the round trip.** The tunnel key derives from `ECDH(client_ephemeral,
server_static_pk)`, so the client can encrypt *before* seeing any server response. It therefore sends the
theatrical ClientHello and the wrapped inner ClientHello **in the same flight**; the proxy authenticates and
immediately forwards. One RTT to first byte — the same as unproxied TLS.

This makes the opening effectively 0-RTT, which means the replay cache in
[authentication.md](https://github.com/getlantern/discovery-engine) is load-bearing rather than optional.

## What it costs

- **Only covers TLS-bearing traffic.** Everything else still needs the wrapped tunnel, so `ordinary`
  carries both modes and selects per connection.
- **The client must parse the TUN stream** well enough to recognise a ClientHello and find its boundaries.
  That is the same machinery as hello harvesting, so the work is shared — but it does move passthrough
  behind the TUN integration that v1 was designed to avoid.
- **The proxy must read the SNI to route**, as any proxy must.
- **No shaping is possible** once passthrough begins. That is the point, but it means a flaw in the opening
  cannot be papered over downstream.

## Residual risk

The honest one: a censor that counts handshakes per TCP connection still sees two where TLS permits one,
even with both wrapped as `0x17`. Resumption plus pipelining makes the pair *look* like a resumed session
followed by a page load, which is common and unremarkable — but it is camouflage, not identity, and it is
the part of this design most worth attacking before building.

Worth measuring first: the record-size and timing profile of a **real resumed HTTPS page load**, to check
that the composite actually lands inside that distribution. `harvest/cmd/tapproxy` is already positioned to
collect it.
