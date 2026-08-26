# `ordinary`: the design, consolidated

Where the iterations landed. Supersedes the scattered conclusions in
[framing.md](framing.md), [passthrough.md](passthrough.md) and
[traffic-analysis.md](traffic-analysis.md) where they disagree.

## Two modes, one routing rule

Every connection is sniffed at the outbound (`sniff.TLSClientHello`, already in sing-box, takes an
`io.Reader` — inbound-agnostic) and routed into the mode where its own structure is least legible:

| Inner traffic | Mode | Rationale |
|---|---|---|
| TLS, **resumption** (`pre_shared_key` present) | **passthrough**, 1:1 | measured: resumed burst triple is weak (§ below) |
| TLS, **full handshake** | **wrapped + mux** | strong burst triple — put it where mux drives TPR 0.85 → 0.13 |
| **not TLS** | **wrapped + mux** | no inner TLS handshake exists to find |

Both modes share the same theatrical opening: a harvested Chrome ClientHello with the authenticator in the
PSK ticket + binder, a synthesised ServerHello, and a cover SNI chosen per server
([cover-domains.md](cover-domains.md)).

**The opening is always a resumption hello.** Not only because the PSK binder is the best auth carrier, but
because a resumption opening has no certificate flight to imitate — the server burst drops from ~4–10 KB to
a near-constant ~1.3 KB, so there is far less to synthesise and far less to get wrong.

## Multiplexing: yes, but only on the wrapped path

Settled. Mux is the strongest evidenced defence in the Xue evaluation — TPR 0.74–0.88 without it, **0.125–0.18
with concurrency 8** — and it works by interleaving inner sessions so no clean burst triple forms.

It is also **structurally impossible on the passthrough path**: passthrough's whole value is that bytes pass
verbatim, and muxing means framing them. So the two are alternatives, not layers:

- **passthrough** = 1:1, no mux, perfect post-opening realism, one clean-but-weak (resumed) triple
- **wrapped** = N:1, mux, shaped, muddied triples

An earlier draft claimed passthrough *retired* the mux requirement. It does not — it removes mux only for
the connections it carries.

The wrapped path should be **one long-lived muxed tunnel per egress**, kept warm AnyTLS-style
(`min_idle_session` ≥ 5), so a first-visit connection always has something to be muxed *with*. A mux tunnel
with one stream in it is not multiplexed.

## What HTTP/2 already does for us

This materially changes the exposure arithmetic, and in our favour.

HTTP/2 multiplexes requests **within an origin**, so a browser opens roughly **one** TLS connection per
origin instead of HTTP/1.1's ~6. Connection coalescing cuts it further: Chrome reuses a connection across
origins when the certificate covers both. So the number of inner TLS handshakes per page load is already far
lower than the number of requests — and each surviving connection is long-lived, which is exactly the regime
where passthrough's verbatim carriage covers the largest fraction of bytes.

**But it does not eliminate the problem**, for two reasons:

1. **h2 multiplexes within an origin, not across origins.** A page pulling from 5–20 origins still opens
   5–20 TLS connections, each with its own handshake.
2. **First contact with an origin is a full handshake.** h2 changes how many connections there are, not
   whether the first one resumes.

So h2 shrinks the full-handshake population without removing it — which is precisely why the wrapped + mux
path still has to exist, and also why it should carry a minority of traffic rather than most of it.

## The measurement the routing rule rests on

From `harvest/cmd/burst` against five real servers, in Xue's own burst representation:

```
full     [ +1488,  −5146,  +145 ]      server burst 3885–9886 B  (spread 6001)
resumed  [ +1765,  −1291,  +145 ]      server burst 1291–1333 B  (spread   42)
```

Resumed server bursts are **13.5–33.2%** of full, and nearly constant, because there is no certificate chain.
The client burst moves the other way — full is tight at 1488–1492 B, resumed is larger and more variable at
1673–1810 B, tracking ticket size. So the triple differs in **both** dimensions the `Wb=3` window reads.

github.com is the control: it declined its own ticket, and its "resumed" server burst was **identical** to its
full one (3087 B both). The instrument moves only when resumption actually happens.

## Honest position on detection

Neither mode is a clean win, and the design minimises exposure rather than eliminating it:

- passthrough carries **one** encapsulated handshake per connection, and it is a *weak* (resumed) one
- wrapped + mux muddies triples but still measured **TPR 0.13–0.18** in the paper
- and *"a censor only needs to identify a single flow to block the corresponding proxy server"*

What the theater buys is a *different* axis: Kulatilleke 2026 classify from the first 5 packets at macro-F1
0.98, and their own recommendation is to complete a full TLS-mimicry exchange before tunneling — which is
what we do. **Theater owns the opening; routing and mux own the steady state.** They are complementary, and
neither substitutes for the other.

## One untested idea worth testing

Xue's claim that padding cannot help rests on padding being unable to *shrink* a burst. But a burst is a run
of consecutive same-direction packets, so **interleaving a small client-direction record into the server's
flight splits one large burst into two smaller ones** — which attacks the representation directly rather than
adding bytes to it.

Real h2 connections already do this: clients send `WINDOW_UPDATE` frames during large downloads. So the
technique is plausible traffic, not just evasion. Untested, and Xue note censors can adapt by "leveraging
packet directions over sizes" — but it is cheap to try on the wrapped path.

## Still open

- The real-browsing resumption ratio, which sets how much traffic each path carries. Our captures show
  resumption in the majority once warm (6/8, 8/10) but those are repeat connections to a single origin.
- Candidate pool for cover domains — ranked lists are enumerable by the censor, the long tail strains the
  splitter ([cover-domains.md](cover-domains.md)).
- Whether cover domains should vary per connection rather than per server.
