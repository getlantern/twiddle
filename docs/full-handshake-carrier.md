# The full-handshake carrier

**Status:** designed, not built. Everything below the "What already exists" line is groundwork that
landed in #1; the carrier itself is unstarted.

## The problem, measured

twiddle emits a **resumption** hello on every connection. `VerifyTicketAuth` requires
`pre_shared_key` (`auth.go`), and so does `CoverProfile.validateClientHello` (`cover.go`). There is no
other authentication path.

Real browsing is almost never resumption:

| capture | connections | full | resumed | share |
|---|---|---|---|---|
| `harvest/testdata/resumption-ratio-session.log` — 16 pages, 6 revisits | 636 | 610 | 26 | **4.1%** |
| `harvest/testdata/resumption-ratio-cold-perprocess.log` | 485 | 472 | 13 | **2.7%** |

`docs/design.md` records the mechanism: a page load opens each origin's connections in a *parallel
burst*, so every connection in the burst starts before any ticket has arrived and none can resume.
`static01.nytimes.com` shows 17 connections and 0 resumptions. 254 distinct origins from 16 page
loads, most contacted once.

So we sit permanently in a ~4% bucket. A censor filtering on "resumption hello" shrinks its candidate
set ~25× for free.

### Against `docs/design.md`, which argues this does not matter

Read `docs/design.md` §"Outer resumption is a different thing, and it is ours" before this section. It
makes a real argument: 4.1% is an **inner** number — the browser reaching 254 destination origins — while
the **outer** connection to our egress is a layer we own, where ~100% resumption is attainable, and
`getlantern/http-proxy` has run outer resumption at scale for years. It concludes the resumption-hello
decision "does not depend on the 4.1%."

The layer distinction is correct. The conclusion does not follow, for one reason: **the censor does not
see layers.** It sees TCP flows carrying ClientHellos. Our outer connection is not exempt from that
population — it is one more member of it. The relevant question is not "can we attain 100% resumption on
a layer we control" (we can) but "what fraction of the flows the censor observes are resumption hellos"
(~4%), and ours is 100% of them.

So amend, do not overturn:

- design.md is right that attainability is not the issue and that the outer ticket path is ours. Keep it.
- design.md is right that http-proxy is prior art for the operational half. Keep that too.
- What it misses is that **the anomaly is not resumption — it is exclusivity.** A client with a long
  relationship to one host and a stack of its tickets *is* a real pattern (a mail server, a CDN, a sync
  endpoint). What no real client does is reach a host for the first time already holding a ticket, and
  never once complete a full handshake with it.

That reframing sets the bar, and it is much lower than 4%: we do not need to match the wild distribution.
We need first contact to be a full handshake, and resumption afterwards to be what it is everywhere else —
the continuation of an observed relationship. See "Mix policy" below; that is why it needs no dice roll.

**The sharper form of the problem.** You cannot resume a session that was never established. An
observer with flow history sees a `pre_shared_key` hello to an IP it never saw that client complete a
full handshake with — structurally impossible in real TLS. Combined with the SNI/IP inconsistency
(lantern-cloud#3292), that is a cheap two-term pre-filter that needs no DPI.

Softening it, honestly: tickets legitimately survive days, client roaming and server IP rotation, and
CDNs share tickets across IPs, so a censor with finite history gets false positives. It is a strong
signal, not a proof — and note it is exactly the signal the first-contact-full policy erases, which is
the argument for building this at all.

## What already exists

Landed in #1, all of it prerequisite:

- `ServerHelloFullLen = 1215` beside `ServerHelloResumedLen = 1221` (`serverhello.go`). The 6-byte
  delta is `pre_shared_key`.
- `CoverProfile.FullRemainder []int` and `FullRemainderJitter []int`, deliberately **empty in the
  table** — see below. `FullOpeningBurst()` and `CanEmitFullHandshake()` derive from them.
- `CoverProfile.Adopt` is variant-aware. The resumed variant is validated against its measured
  constant; the full variant has no constant to compare to, so it is validated structurally (exact
  ServerHello length, bounded record count, plausible certificate-sized burst).
- `harvest/coverprobe.ProbeBoth` measures both openings from one pair of connections, and
  `SampleFull` measures the jitter. It lives under `harvest/` because it needs `crypto/tls` and
  nothing shipped may import one — enforced by `TestShippedPackagesImportNoTLSLibrary`.

### The measured full-handshake server profile

`harvest/testdata/postflight-full-vs-resumed.log`:

|  | ServerHello | ccs | remainder | burst |
|---|---|---|---|---|
| cloudflare | 1215 | 6 | `[3848]` | 5069 |
| google | 1215 | 6 | `[3921]` | 5142 |
| microsoft | 1215 | 6 | `[32, 8273, 286, 74]` | 9886 |

Three consequences:

1. **The remainder is the certificate**, so a faithful full handshake costs **5–10 KB** of opening
   overhead against ~1.3 KB resumed. Price this deliberately.
2. **It cannot be a table constant.** It moves run to run — cloudflare 3846/3847/3848, google
   3920/3921 — because the DER-encoded ECDSA signature in CertificateVerify varies in length, while
   microsoft's fixed-length RSA signature holds 8273 exactly. It also changes on every certificate
   rotation. `FullRemainder` must come from `coverprobe`, and an emitter must **jitter within the
   sampled range**, or it is the only host on the network whose certificate flight never varies.
   Sampled jitter is a **floor**: 5 samples reported 1 for cloudflare, but it has been seen at 3846,
   3847 *and* 3848.
3. microsoft splits into EncryptedExtensions/Certificate/CertificateVerify/Finished; cloudflare and
   google coalesce all four. `ServerRemainder []int` already models this — the client must read one
   record per entry (a fixed single read is the bug #1 hit).

## The hard part: anti-replay without a ticket

This is the piece that needs a decision, not code. Everything else is mechanical.

The replay gate landed in #1 keys on `clientID` and `Issued`, **both of which come out of the
ticket's authenticated plaintext**. A PSK-less hello has neither. The carrier therefore needs its own
anti-replay story, and it must satisfy the lesson that gate was rebuilt around: *eviction is only
sound when the thing evicted is already rejected by validation.*

### Proposed construction

The README already names the carrier: `ClientHello.random` carries the MAC, `key_share` supplies the
ephemeral. 32 bytes of `random` to work with. Mirror the ticket's own shape:

```
random = AEAD(k_server, nonce, plaintext = clientID ‖ timestamp, aad = key_share ‖ cover_sni)
         ~ 8B nonce + 8B plaintext + 16B tag = 32B
```

Why this shape:

- **Server-key encrypted, like the ticket.** The egress decrypts without knowing which client first,
  so there is no O(clients) trial-verification and no per-client lookup.
- **No linkable identifier on the wire.** A plaintext `clientID` would let a censor correlate every
  connection from one client. Ciphertext under a fresh nonce is uniform to an observer, which is also
  what `random` must look like.
- **`key_share` as AAD binds the ephemeral for free**, preventing substitution without spending bytes.
- **The freshness window can be SHORT.** There is no ticket lifetime to respect, so a ±30–60 s window
  is enough. That makes the replay set O(connections within the window) instead of O(connections
  within 24 h) — and, critically, the window *is* the whole horizon, so the set cannot forget
  anything still valid. That is the property the ticket-keyed gate had to be redesigned to get.

Anti-replay is then: verify the AEAD, check `|now − timestamp| < window`, and dedup on the
`key_share` (32 uniformly random bytes, fresh per connection, a better key than `random`) within the
window.

### Open questions

1. **Byte budget.** 8B nonce + 8B plaintext + 16B tag = 32B exactly, leaving ~4B for clientID and ~4B
   for the timestamp. Is a 4-byte clientID enough for the population? Is a 4-byte second-resolution
   timestamp enough range? Alternative: shrink the tag to 12B and take 4 more bytes of plaintext —
   96-bit authentication may be acceptable here since forging only yields a connection attempt, but
   that is a judgement call.
2. **Clock skew.** The window depends on the client's clock. Mobile clocks are usually fine; decide
   the tolerance and what happens to a client with a badly wrong clock (it fails to the cover path,
   which is safe but invisible to the user).
3. **Where credential rotation lives.** It currently rides a NewSessionTicket-shaped record — but
   cloudflare and google send **no** unprompted post-handshake records at all, so on those covers
   that record has no counterpart. A full-handshake connection has no ticket to rotate anyway; decide
   whether the full path rotates at all, or only issues on first contact.
4. **Mix policy — and it is not a ratio.** Per the reframing above, the target is not 4%. It is that a
   censor watching this client and this egress has *seen the full handshake that the resumption
   continues*. That makes the first connection to an egress full (there is no ticket yet anyway) and
   later ones resumed, with no dice roll.
   The real question is the **re-full cadence**, because the censor's flow history is finite and the
   client's context changes: a reconnection a week later, from a different network, after the egress IP
   rotated, has no observable predecessor even though we hold a valid ticket. Some trigger — new local
   address, new egress IP, elapsed time — has to force a fresh full handshake. Note the resulting ratio
   is likely *far above* 4% (a long-lived muxed tunnel opens few outer connections, so one full per
   handful of resumed), and that is the correct outcome, not a miss: what a censor can check is whether
   the predecessor exists, not whether we hit a population average.

## Implementation sketch

1. `SetRandomAuth` / `VerifyRandomAuth` in `auth.go`, mirroring `SetTicketAuth` / `VerifyTicketAuth`.
   **Ordering matters:** the random binds `key_share`, so it must be written *after* `SetKeyShare` —
   the same "authenticate over the final byte layout" constraint the binder has. The pipeline becomes
   `SetSNI → Rerandomize → Shuffle → SetKeyShare → SetRandomAuth`.
   Note `Rerandomize` currently overwrites `h.Random`, so the auth step must follow it.
2. Branch `validateClientHello` (`cover.go`) and `Server` (`handshake.go`) on whether
   `pre_shared_key` is present, instead of requiring it.
3. A second replay gate keyed on `key_share` within the freshness window. Reuse the horizon-soundness
   argument from `replay.go`; do not reuse its client-keyed structure, which depends on ticket fields.
4. Server emission: `ServerHelloFullLen`, then CCS, then one record per `FullRemainder` entry,
   jittered within `FullRemainderJitter`. Client: one read per entry.
5. Gate on `CanEmitFullHandshake()` — an egress with no probed full profile must not offer the
   carrier. Emitting a guessed certificate flight is worse than only offering the resumed path.
6. Extend `cover_test.go`'s oracle. Note it cannot pin `FullRemainder` to a literal (it is probed and
   jitters); pin the *structure* instead — ServerHello length, record count, plausible range.

## Traps worth knowing before starting

Each of these cost real time in #1:

- **A test whose oracle is the thing under test proves nothing.** `TestOpeningRecordSequenceMatchesCover`
  compared the emitter against the profile that drove it, so collapsing microsoft's `[32 74]` to
  `[106]` kept it green. `cover_test.go` now pins against literals transcribed from the logs. The full
  variant needs the structural equivalent.
- **Mutation-test every guarantee.** Two regression tests in #1 passed with the fix removed. Break the
  thing deliberately and confirm the test fails, or the test is decoration.
- **A flight-style probe measures the wrong handshake.** Emitting a hello and never completing it
  yields the *full* profile (1215, multi-KB) — which is now what we want here, but it cannot reach the
  resumed shape. Do not conflate the two probes.
- **Go's `crypto/tls` is a valid reference for the SERVER and the wrong one for the CLIENT.** Its
  client flights are 64/64/80 against Chrome's measured 149/145/164. Anything client-side needs a
  Chrome capture via `cmd/records` or `cmd/capture`.
