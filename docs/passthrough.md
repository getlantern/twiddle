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

It does not eliminate the Xue signal, but it collapses the part of it that carries the information.

A wrapped tunnel stacks **many** inner handshakes onto one long-lived outer connection — that repetition is
the strong signal. Passthrough has **exactly one** encapsulated handshake per connection (the ClientHello we
must wrap to hide the SNI), positioned at the front where a connection is expected to be handshaking anyway.
Everything after it is the real session.

| Problem | Wrapped tunnel | Passthrough |
|---|---|---|
| Encapsulated handshakes per outer connection | **many**, one per inner session | **exactly one**, at the front |
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

## Detection is optional, and it is not a TUN feature

An earlier draft of this document put passthrough behind TUN integration. That was wrong. Detection reads
the **first bytes of the stream**, and sing-box already implements it:

```go
// common/sniff/tls.go — takes an io.Reader, not a TUN handle
func TLSClientHello(ctx context.Context, metadata *adapter.InboundContext, reader io.Reader) error
```

Because it operates on an `io.Reader`, it is **inbound-agnostic** — SOCKS5, HTTP `CONNECT`, TUN, or
transparent redirect all reach the outbound as a byte stream, and the first bytes either parse as a
ClientHello or they do not. `lantern-box` inherits this from sing-box, so it is configuration rather than
new work.

Optionality then falls out at three independent levels:

| Level | Mechanism | Effect |
|---|---|---|
| **Config** | `passthrough: false` | transport always uses the wrapped tunnel |
| **Per connection** | first-bytes sniff | no valid ClientHello ⇒ wrapped. **Fail closed** |
| **Negotiated** | server capability bit | egress without passthrough ⇒ client falls back |

Two rules keep this safe:

- **Require a successful parse with a usable SNI** before choosing passthrough. Ambiguity resolves to
  wrapped, never the other way.
- **Signal the mode explicitly** — a mode byte in the first wrapped record — rather than letting the proxy
  infer it from whether the payload happens to parse. Inference invites a parser-differential bug where
  client and proxy disagree about what the connection is.

And a useful consequence of the split: **neither mode ever carries a repeated encapsulated TLS handshake.**
TLS traffic goes passthrough, where the single handshake is the connection's own. Non-TLS traffic goes
through the wrapped tunnel, where there is no inner TLS handshake to find because the payload is not TLS.

## What it costs

- **Only covers TLS-bearing traffic.** Everything else uses the wrapped tunnel, so `twiddle` carries both
  modes and selects per connection.
- **The proxy must read the SNI to route**, as any proxy must.
- **No shaping is possible** once passthrough begins. That is the point, but it means a flaw in the opening
  cannot be papered over downstream.
- **Lazy dial.** Pipelining the theatrical hello with the wrapped inner hello means waiting for the
  application's first write before dialling. Browsers write immediately, so the cost is negligible — and it
  avoids opening connections that are never used.

## Measured: resumed inner handshakes barely form the burst triple

The paper *conjectures* that "irregular handshakes resulting from optimizations such as TLS Session
Resumption and False Start may contribute to the majority of false negative instances," but does not measure
it. We did (`harvest/cmd/burst`, `harvest/testdata/tls13-burst-resumption.log`), using their own burst
representation.

| Host | full server burst | resumed server burst | resumed / full |
|---|---|---|---|
| www.microsoft.com | 9886 B | 1333 B | **13.5%** |
| www.amazon.com | 6408 B | 1313 B | **20.5%** |
| www.wikipedia.org | 5576 B | 1317 B | **23.6%** |
| www.google.com | 5146 B | 1291 B | **25.1%** |
| www.cloudflare.com | 3885 B | 1291 B | **33.2%** |

Two things stand out beyond the 3–8× shrink:

**The resumed server burst is nearly constant — 1291–1333 B, a spread of 42 bytes** — while the full-handshake
burst ranges 3885–9886 B, a spread of 6001 B. That is the certificate chain: full handshakes carry one and
vary with it, resumed handshakes carry none.

**The client burst moves the other way.** Full-handshake client bursts are extremely tight (1488–1492 B);
resumed ones are larger *and* more variable (1673–1810 B), because the PSK extension's size tracks the
ticket. So the burst triple differs in **both** dimensions the `Wb=3` window sees:

```
full     [ +1488,  −5146,  +145 ]
resumed  [ +1765,  −1291,  +145 ]
```

**Control:** github.com returned `DidResume=false` — it declined its own ticket and fell back to a full
handshake — and its "resumed" server burst was **identical to its full one (3087 B both times)**. The
measurement moves only when resumption actually happens, which is what we want from the instrument.

**What this does not establish:** whether Xue's *trained* classifier fires. We cannot replicate their model
against their ISP dataset. What we can say is that the feature it keys on differs by 3–8× in one dimension
and moves in the opposite direction in the other — consistent with their conjecture, and a reason to expect
resumed inner handshakes to be a weak signal rather than a strong one.

## The routing rule this implies

Exposure depends on whether the **user's inner** session resumes, and the sniffer can already tell — a
resumption ClientHello carries `pre_shared_key`. So route per connection into whichever mode has the lower
exposure:

| Inner handshake | Mode | Why |
|---|---|---|
| **resumption** (has `pre_shared_key`) | **passthrough** | weak burst triple, and perfect traffic realism after the opening |
| **full handshake** | **wrapped tunnel + mux** | the strong burst triple — put it where mux drives TPR to 0.13 |
| not TLS | wrapped tunnel | no inner TLS handshake exists to find |

This is better than either mode alone: each connection lands in the mode where its own structure is least
legible. It also means **mux stays in the design** rather than being retired by passthrough, which is the
correction the paper forces.

Indicative but not representative: across our own Chrome captures, resumption was the majority once a
session was warm (6 of 8, and 8 of 10, in two runs) — but those are repeat connections to a *single* origin,
so the real browsing ratio needs measuring before it can be leaned on.

## Residual risk

The honest one: a censor that counts handshakes per TCP connection still sees two where TLS permits one,
even with both wrapped as `0x17`. Resumption plus pipelining makes the pair *look* like a resumed session
followed by a page load, which is common and unremarkable — but it is camouflage, not identity, and it is
the part of this design most worth attacking before building.

Worth measuring first: the record-size and timing profile of a **real resumed HTTPS page load**, to check
that the composite actually lands inside that distribution. `harvest/cmd/tapproxy` is already positioned to
collect it.
