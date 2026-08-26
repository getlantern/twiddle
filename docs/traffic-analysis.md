# Traffic analysis: where `twiddle` is strong, and where it is not

The theater design ([framing.md](framing.md), and the design docs in `discovery-engine`) makes the
**opening** indistinguishable. This document is about everything after it, because that is a separate
attack surface and our design does **not** address it for free.

## The honest answer on TLS-in-TLS

### What the attack actually does

Read from the paper, not a summary. Each flow becomes a sequence of signed integers — magnitude is TCP
payload size, sign is direction — plus inter-arrival times: `(+517, −1400, −1400, +80)`.

**For TLS-cover flows the outer handshake is stripped first**, "in order to only identify handshakes that
are encapsulated." Two classifiers then run, and a flow is flagged only if *both* fire:

1. **Chi-squared over 3-grams** of discretised sizes. Sizes bucket into `|L|=4` groups chosen so that
   ClientHello, ServerHello and ChangeCipherSpec land in distinct buckets; top `f=100` 3-grams;
   observation window `Wo=25` packets.
2. **Mahalanobis distance over bursts** — consecutive same-direction packets aggregated, because "each
   phase of the TLS handshake typically forms its own burst." Window `Wb = 2×RT+1`: **5 for TLS 1.2,
   3 for TLS 1.3.** Slides across the flow, takes the minimum distance.

Deployed 30 days at Merit: 36 TB/day, 3.9M flows, **FPR 0.054%** on TLS.

| Configuration | TPR |
|---|---|
| shadowsocks / vmess / vless / trojan | 0.74–0.85 |
| httpt, Cloak, shadowTLS, gost | 0.69–0.88 |
| obfs4 | 0.438 |
| naiveproxy | 0.328 |
| **MUX (concurrency 8)** | **0.125–0.18** |

And the sting: *"a censor only needs to identify a single flow to block the corresponding proxy server."*
A TPR of 0.13 is still fatal across enough flows.

**Two consequences we got wrong earlier.** Our theatrical handshake is **neutral, not protective** — a
perfect cover handshake is exactly what gets stripped before analysis. And **mux is the strongest evidenced
defence** (0.85 → 0.13) precisely *because* it stacks inner sessions; a 1:1 mapping is the opposite of that.

### The paper's own words

Xue et al., *Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes*, USENIX Security
2024 (`2024-xue-fingerprinting`):

> Obfuscated proxy traffic (including Shadowsocks, VMess, VLESS, Trojan, obfs4, and **REALITY**) can be
> reliably fingerprinted by detecting encapsulated TLS handshakes… This fingerprint is **protocol-agnostic**:
> any proxy that wraps TLS-bearing application traffic will produce it.

Deployed in a mid-size ISP serving over a million users, with minimal collateral damage. Two consequences
we have to accept plainly:

1. **`twiddle` inherits this.** Our theater perfects the outer handshake; this attack reads the *shape of
   what comes after*. The paper names REALITY-style approaches explicitly: making the outer handshake
   indistinguishable from a real TLS server "still expose[s] inner-handshake structure once the censor can
   observe full-stream patterns."
2. **Padding does not fix it.** "Random padding and multiple encapsulation layers do NOT defeat this attack;
   they cannot reduce the size of traffic bursts or the number of round trips."

So: no natural immunity. The good news is that the countermeasures are known, and one of them we get for
free from what Lantern already is.

## Where the theater *does* earn its keep

Kulatilleke et al. 2026 (`2026-kulatilleke-mambanetburst-direct-byte-level`) classify from **the first 5
packets, truncated to 320 bytes each** — 1600 bytes total — at macro-F1 ≥ 0.9824. Their own recommendation:

> Designs that delay the circumvention-specific handshake beyond the opening burst (e.g., by completing a
> full TLS-mimicry exchange before tunneling) gain meaningful protection against burst-level classifiers.

That is precisely what `twiddle` does. Our first 1600 bytes are a genuine harvested ClientHello. The two
defences are complementary, not redundant: **theater owns the opening, shaping must own the steady state.**

## The countermeasure that matters most, and it is not padding

Ferrel 2026 (`2026-ferrel-aegis-adversarial-entropy-guided`) builds a flow-physics classifier that discards
payload entirely and still reaches F1 0.9952 against VLESS Reality. But:

> when VLESS Reality multiplexes **true human entropy** (a human actively browsing web applications), AEGIS
> achieves a detection rate of only **1.17%** … pure automated proxy traffic remains vulnerable regardless of
> cryptographic mimicry.

**Lantern's traffic is human browsing.** That is a structural advantage over a proxy carrying automated
traffic — and it inverts the naive instinct. The risk is not that we lack jitter; it is that **our own
machinery destroys the entropy already present**:

> circumvention tools must source true stochastic IAT from real human interaction rather than PRNG-based
> jitter … eliminate fixed polling intervals, synchronized batching, and any algorithmic scheduling that
> produces cyclical or low-entropy IAT signatures.

Synthetic jitter is also quantitatively weak: 5% IAT noise leaves F1 at 0.9913, 10% at 0.9753, and only
~15% degrades it meaningfully — a level most transports cannot tolerate functionally.

> **Design rule: preserve human entropy, do not manufacture it.** Any coalescing, batching or scheduling in
> the shaping layer must be evaluated for whether it *regularises* timing that was previously human-driven.

## What to build

**1. Multiplexing is mandatory, not an optimisation.** Xue: "protocol designers should treat mux as a
required component." One outer flow carrying many inner connections hides per-connection inner handshakes.
This **reverses** the position taken in [framing.md](framing.md), which is corrected there.

**2. An idle session pool.** AnyTLS (`2026-anon-anytls-anytls-sing-box-2026`) keeps ≥5 pre-established
sessions warm:

> Maintaining a pool of idle pre-authenticated TLS sessions eliminates the per-request handshake burst that
> distinguishes proxy protocols from browser TLS — set `min_idle_session` ≥ 5 so the connection pattern
> resembles persistent HTTP/2 keep-alive traffic.

Defaults: `idle_session_check_interval` 30s, `idle_session_timeout` 30s, `min_idle_session` 5. **AnyTLS is
maintained by the sing-box team**, and `lantern-box` is a sing-box fork — so this is likely portable rather
than novel work. Worth checking before building anything.

**3. Shape from measured traces, not uniform ranges.** AnyTLS's own guidance:

> consider designing padding profiles based on real CDN traffic traces rather than uniform ranges.

We can collect those traces with the same TUN infrastructure planned for hello harvesting. This is the
strongest form of "use real client TLS traffic as the template" — the template comes from real browsing
rather than a PRNG, which is the same argument the AEGIS result makes.

**4. Separate egress IP.** Almutairi 2026 (`2026-almutairi-server`) detects single-IP relays by their
"dual-role" behaviour — a host that is both server and client — at 0.18% FPR. Architectural, not framing,
but it belongs on the same list.

## The ceiling, stated plainly

Xue is explicit that mux plus padding is "inherently limited," because burst sizes and round-trip counts
remain correlated with the number of inner TLS sessions. Fully closing the vector would require "complete
replacement of inner TLS with non-TLS app-layer framing" — for us, terminating TLS at the egress so no inner
handshake ever crosses the tunnel.

**That is almost certainly unacceptable**: it puts plaintext at the egress and breaks certificate pinning and
end-to-end guarantees users reasonably expect. So we are *managing* this attack, not eliminating it, and the
plan should say so rather than imply the countermeasures are a fix.
