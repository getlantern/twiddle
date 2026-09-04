# `twiddle`: the design, consolidated

Where the iterations landed. Supersedes the scattered conclusions in
[framing.md](framing.md), [passthrough.md](passthrough.md) and
[traffic-analysis.md](traffic-analysis.md) where they disagree.

## Two modes, one routing rule

Every connection is sniffed at the outbound (`sniff.TLSClientHello`, already in sing-box, takes an
`io.Reader` — inbound-agnostic) and routed into the mode where its own structure is least legible:

| Inner traffic | Mode | Rationale |
|---|---|---|
| **everything** | **wrapped + mux** | measured: resumptions are only 4.1% of real browsing, so passthrough has almost nothing to carry, while 636 connections per session give mux abundant concurrency |

~~Resumed TLS → passthrough~~ was the plan until the resumption share was measured. See below.

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

## Burst interleaving: tested, works, but do not lean on it

Xue's claim that padding cannot help rests on padding being unable to *shrink* a burst. But a burst is a run
of consecutive same-direction packets, so **interleaving a small client-direction record into the server's
flight splits one large burst into two** — attacking the representation rather than adding bytes to it. Real
h2 clients already do this via `WINDOW_UPDATE` during downloads.

We built an approximation of their Algorithm 2 (`harvest/burst_analysis.py`) — train on the first `Wb=3`
bursts of each flow, then slide a 3-burst window over a test sample and take the **minimum** distance — over
a corpus of 30 real servers (`harvest/testdata/burst-corpus.jsonl`).

At a threshold γ = 2.96, chosen to flag 90% of full handshakes:

| Sample | median min-distance | flagged |
|---|---|---|
| full handshake (leave-one-out) | 1.11 | **93.3%** |
| resumed handshake | 81.80 | **0%** |
| handshake flight split in 2 | 13.17 | **0%** |
| handshake flight split in 4 | 29.68 | **0%** |

**Both evade. They are not equally trustworthy.**

**Resumption's evasion is structural.** A resumed handshake genuinely has no certificate chain, so the bytes
the classifier keys on are not there to find. A censor could retrain on resumptions — but the resulting model
flags *resumed TLS*, which is a large fraction of the whole Internet, and the collateral damage is the
censor's problem rather than ours.

**Interleaving's evasion is a training-set gap.** It works because the model never saw interleaved flows, not
because the information is absent. Xue explicitly anticipate this: censors can adapt "by mirroring the
padding schemes, training on padded versions of datasets, and leveraging packet directions over sizes." A
censor could also simply redefine a burst to ignore sub-100-byte direction changes, which costs them nothing
and erases the whole effect.

**And a mechanical split is its own fingerprint.** Our test injected 64-byte records at exact run midpoints.
Regular small client records at geometric positions is a *new* signature, and precisely the mistake AEGIS
warns about — synthetic regularity replacing human variability. If we implement this, the injections must
follow genuine h2 flow-control semantics (receive-window driven), not a "split the burst in half" rule.

**Verdict:** keep it as a cheap add-on on the wrapped path, where the strong triple would otherwise be
exposed. Do not count it in the threat model. **Resumption routing is the load-bearing defence**; interleaving
is a bonus that a motivated censor removes in one retraining cycle.

### What this test does not show

The model is trained **only on full handshakes**, which is why resumptions sit 74× further out than the
training distribution. A censor training on real mixed TLS traffic — as Xue did, labelling with Zeek — gets a
broader model that covers more. The result establishes *separation in the feature space*, not evasion of a
deployed system. Our burst inputs also come from socket reads rather than packet capture; burst aggregation
sums consecutive same-direction bytes so it is robust to read coalescing, but it is still an approximation.

## The tension nobody has priced: passthrough starves mux

These two defences **compete for the same traffic**.

Mux works by interleaving inner sessions so no clean burst triple forms — Xue measured TPR 0.13–0.18 at
concurrency 8, and concurrency is the whole mechanism. But passthrough diverts every resumed TLS connection
*away* from the wrapped tunnel. The better passthrough works, the thinner the mux tunnel gets, and the more
legible the flows that remain in it.

Taken to the limit: if passthrough carried everything except first-visit connections, the wrapped tunnel
might carry one or two streams at a time — which is not multiplexed at all, and lands back at the
0.74–0.88 TPR of the non-mux configurations.

This is not a reason to drop either one, but it means the split point is a **tuning decision with a real
optimum**, not a free architectural choice. Two things follow:

- The wrapped tunnel must be **long-lived and shared across destinations**, so that even a modest arrival
  rate accumulates concurrency. An AnyTLS-style warm pool is what makes this possible.
- If measured concurrency in the wrapped tunnel falls below roughly Xue's 8, it may be **better to route
  some resumed connections back into it** — sacrificing their individual realism to keep the mux dense
  enough to protect the full handshakes that have nowhere else to go.

## MEASURED: the resumption share is ~4%, and it changes the design

The gating question was what fraction of real browsing connections are resumptions. Measured with a tapping
CONNECT proxy (`harvest/cmd/resumeratio`) behind one long-lived Chrome process navigating 16 pages, 6 of
them deliberate revisits (`harvest/testdata/resumption-ratio-session.log`):

```
636 TLS connections   610 full   26 resumed   ->  RESUMPTION SHARE: 4.1%
254 distinct origins from 16 page loads
```

**Not 70%. Four percent.** The per-origin breakdown shows why, and the mechanism is not what we assumed:

```
static01.nytimes.com              17 full /  0 resumed
securepubads.g.doubleclick.net    16 / 0
static01.nyt.com                  15 / 0
www.google.com                    13 / 2
tpsc-uw1.doubleverify.com         11 / 4
```

Seventeen connections to a single origin with **zero** resumption. Browsers open connections to an origin in
a **parallel burst** at page load, so every connection in the burst starts before any session ticket has
arrived and none of them can resume. Resumption only happens on a *sequential* later visit — which is why the
handful of origins that do resume are the ones contacted across multiple page loads.

Our earlier 75–80% figures came from sequential fetches to a single origin. That is the most favourable case
imaginable, and real browsing is close to its opposite: a long tail of 254 origins, most contacted once.

### What this does to the routing rule

Passthrough was justified by carrying most of the traffic. It would carry **4%**. Routing *all* TLS through
it instead is worse, not better: full inner handshakes produce exactly the clean burst triple, at Xue's
non-mux TPR of 0.74–0.88.

Meanwhile the wrapped path gets the opposite news. 636 connections over one browsing session is abundant
concurrency — far more than the concurrency-8 configuration where Xue measured TPR **0.13–0.18**. The
starvation tension identified above resolves itself: there is nothing to starve mux of.

> **Revised: the wrapped + mux tunnel is the primary path. Passthrough is a marginal optimisation and should
> be cut from v1.**

That is a real simplification — no dual-mode routing, no mode byte, no second code path — bought by a
measurement that took an afternoon.

### Outer resumption is a different thing, and it is ours

The 4.1% is about **inner** handshakes — the browser reaching 254 destination origins. It says nothing about
the **outer** connection to our own egress, which is a separate layer and behaves completely differently:

| | inner (browser → destination) | outer (client → our egress) |
|---|---|---|
| who controls the ticket | the destination | **we do** |
| measured/attainable resumption | **4.1%** | **~100%** |
| what it affects | what the censor sees *encapsulated* | the shape of our theatrical opening |

`getlantern/http-proxy` has run outer TLS resumption at scale for years and still carries substantial
traffic — prior art worth reading before implementing the ticket path here. It is also a reason to keep the
theatrical opening as a resumption hello: that decision does not depend on the 4.1%, and the operational
half of it is already proven in production.

> **Amended.** The layer distinction above holds, but the conclusion drawn from it was too strong: the
> censor does not see layers, so our outer connection sits in the same observed population as every inner
> one. `docs/full-handshake-carrier.md` works the argument through and lands somewhere narrower than "match
> 4%" — the anomaly is *exclusivity*, a client that reaches a host already holding a ticket and never once
> completes a full handshake with it. Read that document alongside this section.

**But do not carry the TLS version over.** http-proxy uses TLS 1.2, and for this transport 1.3 is strictly
better: Xue's classifier is *more* precise against 1.2 (`Wb=5`, more consecutive elements must match, lower
FPR) and the paper says explicitly that it is "in censors' interest to focus on TLS 1.2." TLS 1.2 also puts
the certificate chain in cleartext, which is the entire fidelity problem the 1.3 theater design sidesteps.

A separate TLS-1.2-shaped transport is a legitimate thing to want for diversity — different fingerprint,
different failure mode — but it is a different track, not this one.

### Caveats on the number

- Headless Chrome against ad-heavy Western sites. Much of the 254-origin tail is ad and analytics traffic.
- **Ad blocking would change this materially.** A user blocking that tail contacts far fewer origins, each
  more likely to be revisited, which should raise the resumption share. Lantern users plausibly skew that
  way, and it is worth re-measuring with a blocker enabled before treating 4% as universal.
- Long-lived non-browser apps (messaging, sync) hold connections rather than reopening them, so they neither
  resume nor produce repeated handshakes.

## Still open

- The real-browsing resumption ratio, which sets how much traffic each path carries. Our captures show
  resumption in the majority once warm (6/8, 8/10) but those are repeat connections to a single origin.
- Candidate pool for cover domains — ranked lists are enumerable by the censor, the long tail strains the
  splitter ([cover-domains.md](cover-domains.md)).
- Whether cover domains should vary per connection rather than per server.

## Phase 0 size deltas: both closed

**ServerHello — there was no delta.** The 1210 figure had been read off a *handshake body* length, not a
record. Measured properly across five servers
(`harvest/testdata/serverhello-resumption-delta.log`), every one produced an identical layout:

```
full handshake     1215 B   key_share(1128) + supported_versions(6)
resumed handshake  1221 B   ... + pre_shared_key(6)     <- +6 on all five
```

Our opening is always a resumption, so **1221 is the target and the synthesis already hit it**. The test now
asserts the exact value rather than a range, since five servers agreeing makes it a point target.

The measurement did turn up something to imitate: **extension order varies by server but is fixed per
server** — google and cloudflare place `pre_shared_key` first, microsoft, amazon and wikipedia place it last.
One egress impersonates one identity, so a stable per-identity order is the faithful behaviour; `PSKFirst`
selects it.

**ClientHello — real, and the cause is ticket length.** The ticket travels inside `pre_shared_key`, so its
length sets the hello size directly:

| Cover | ticket issued | resulting resumption hello |
|---|---|---|
| cloudflare | 176 B | 1711 B |
| google | 230 B | 1761 B |
| microsoft | 256 B | 1806 B |

**So `TicketLen` is a fidelity parameter, not a free choice.** An egress claiming to be microsoft.com should
issue 256-byte tickets; `TicketLenForCover` carries the measured table and `harvest/cmd/resume` measures new
ones. A test now proves parity: emitting with the ticket length the harvested hello already carried
reproduces its size across 24 captured resumption hellos, differing only by the ECH GREASE bucket that Chrome
itself varies per connection.

