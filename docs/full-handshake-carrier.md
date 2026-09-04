# The full-handshake carrier

**Status:** built and green in twiddle; not yet provisioned or enabled downstream. The carrier, both
handshake paths, credential rotation and the pool filter all landed on `fisk/full-handshake-carrier`.
What is left is the mix policy and the cross-repo provisioning — see "What remains".

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
the continuation of an observed relationship. See "What remains"; that is why it needs no dice roll.

**The sharper form of the problem.** You cannot resume a session that was never established. An
observer with flow history sees a `pre_shared_key` hello to an IP it never saw that client complete a
full handshake with — structurally impossible in real TLS. Combined with the SNI/IP inconsistency
(lantern-cloud#3292), that is a cheap two-term pre-filter that needs no DPI.

Softening it, honestly: tickets legitimately survive days, client roaming and server IP rotation, and
CDNs share tickets across IPs, so a censor with finite history gets false positives. It is a strong
signal, not a proof — and note it is exactly the signal the first-contact-full policy erases, which is
the argument for building this at all.

## Groundwork from #1

Prerequisite, and all of it already on main before this work:

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

## The carrier: where does the ticket go?

### First, a correction

An earlier draft of this document proposed putting `AEAD(k_server, clientID ‖ timestamp)` in
`ClientHello.random`. **That is impossible.** `TicketKey` never leaves the egress (`auth.go`), so a client
cannot encrypt under it. In the resumption path the client does not encrypt anything — it presents a
ciphertext *the server minted for it*. The direction was backwards.

Correcting it shrinks the problem. Provisioned clients always hold a `Credential{Ticket, PSK}`; that is why
every hello is a resumption hello in the first place. So the question was never "authenticate with no
credential." It is:

> **Where does the ticket go, if not in `pre_shared_key`?**

And with the ticket still present, `clientID` and `Issued` come out of `TicketKey.Open` exactly as they do
today — so **the merged `ReplayCache` applies unchanged**, and this document's former "hard part" does not
exist.

### Leading candidate: the GREASE ECH payload

`harvest/testdata/arrival-chrome152.log` measured Chrome 152's ECH extension at **186/218/250/282 bytes**
across 7 hellos, redrawn per connection — a payload of 144/176/208/240 after the 42-byte header
(`config_type ‖ kdf ‖ aead ‖ config_id ‖ enc[32]` plus the two length prefixes). `echGREASELengths` in
`twiddle.go` already models exactly this, and `rerandECHGrease` already overwrites the payload with fresh
random bytes every connection.

That payload is **the one field in the hello where 144–240 uniform bytes are precisely what belongs.** A
ticket is AEAD ciphertext. It is the same object.

```
full-handshake hello:
  no pre_shared_key                      <- looks like a full handshake, because it is one
  ECH payload  = ticket ‖ random padding <- padded to the drawn Chrome bucket
  random       = HMAC(binderKey(psk), hello with random zeroed)
  key_share    = real ephemeral          <- unchanged
```

Why each piece:

- **Ticket length becomes free.** In the resumption path `TicketLen` is a hard fidelity parameter because
  the ticket sets the emitted hello size (`auth.go`: cloudflare 176 → 1711 B). Inside the ECH payload it is
  invisible; only the *payload* length is observable, and that is drawn from Chrome's buckets. So fix the
  full-path ticket at **144 bytes** — it fits the smallest bucket, so every bucket stays reachable — and pad
  with random bytes to whatever length `rerandECHGrease` drew. Length variation stays exactly Chrome's.
- **`random` takes over the binder's job.** The binder lives in `pre_shared_key` and dies with it. A
  32-byte HMAC keyed from the psk fits `random` exactly, and 32 uniform bytes is what `random` is. Same
  "authenticate over the final byte layout" discipline: compute it last, over the marshalled hello with
  `random` zeroed.
- **Nothing new is provisioned.** No new key material, no lantern-cloud or lantern-box change. The client
  already holds the credential; the server already holds the ticket key.

### Measured: the covers publish no ECHConfig, so GREASE holds

The carrier's length model only holds while Chrome sends *GREASE* ECH. A Chrome that obtains an ECHConfig
sends **real** ECH, whose payload length is set by the encrypted inner hello rather than by
`echGREASELengths` — which would make the model wrong. `arrival-chrome152.log` could not settle this: it
captured hellos to a bare IP with no DNS, so real ECH was impossible there by construction.

Settled now — `harvest/testdata/ech-config-published.log`. Querying the HTTPS RR across three independent
resolvers, with `crypto.cloudflare.com` as a positive control that proves the method detects `ech=`:

| host | ECHConfig published |
|---|---|
| `www.cloudflare.com` | no |
| `www.google.com` | no |
| `www.microsoft.com` | no |
| `crypto.cloudflare.com` *(control)* | **yes** |

None of the three cover identities publishes one, so a Chrome with secure DNS fully working still cannot
fetch one for them and sends GREASE. **This is a stronger result than `docs/ech.md`'s**, which reaches the
same conclusion for in-region clients via a contingent route — China censors encrypted DNS resolvers, so no
config is fetched. Here the config does not exist to fetch, so the carrier holds for an unrestricted client
too and does not depend on the censorship it is meant to survive.

Note `www.cloudflare.com` itself does not enable ECH; only the demo host does. Cloudflare has enabled and
rolled back ECH for customer zones before, so this is a **monitorable** condition, not a permanent one — the
log carries the one-line check.

### The objection, which is real

`docs/ech.md` concludes: *"ship ECH, and keep the ability to stop shipping it without shipping anything"* —
because the pool is data, a device tap from a browser that does not send ECH silently produces a non-ECH
pool, and that is the designed escape hatch if China ever blocks `0xfe0d`.

Putting authentication in the ECH payload **couples the full-handshake path to a hedge built to be
dropped.** If the hedge fires, the carrier vanishes.

The answer is that this is degradation, not breakage, and there is already a gate for it:
`CanEmitFullHandshake()` must additionally require an ECH extension with a large enough payload. A pool
without ECH falls back to the resumption path — which is exactly where we are today, so the floor is the
status quo. Say this out loud in the code, because a future reader will otherwise re-derive the objection
and assume it was missed.

### Fallback candidate: ECDH to a server static key

If the ECH coupling proves unacceptable, the REALITY-style construction works:

```
k_open = HKDF(ECDH(client_eph_priv, server_static_pub))
random = AEAD(k_open, nonce = KDF(client_eph_pub), clientID ‖ timestamp ‖ psk_proof)
```

The server does **one** X25519 against its static private key to recover the opener key — no per-client
trial, no O(clients) scan. `docs/uniform-ephemeral.md` warns that "the client never performs a DH," but that
warning is about placing a raw curve point in a *ciphertext-shaped* field. Here the curve point goes in
`key_share`, where `auth.go` already says "a curve point is precisely what belongs and carries no anomaly at
all" — and the client already does exactly this DH today.

Costs, and why it is second choice:

- A new long-term server keypair, provisioned to every client — a lantern-cloud (`pcfg`) and lantern-box
  change, i.e. cross-repo work the ECH carrier does not need.
- No ticket on the wire, so `clientID`/`Issued` no longer come from `TicketKey.Open` and the replay gate
  **does** need the separate short-window construction this document previously described. Keep that
  sketch in the git history for this case.
- Forward secrecy is unchanged for traffic (session keys still come from the ephemeral-ephemeral ECDH plus
  psk), but a later compromise of the static key retroactively reveals the `clientID` in past openings.
  The ECH carrier has no equivalent exposure.

## What was built

All of it mutation-tested — every guarantee below has a deliberate break that fails a test.

| Piece | Where |
|---|---|
| `SetECHTicketAuth` / `VerifyECHTicketAuth`, `FullTicketLen = 144`, `echPayload`, `ECHPayloadLen` | `echcarrier.go` |
| `Credential.FullTicket`, `IssueFullFor`, both tickets sealed at one instant | `auth.go` |
| `CredentialFromWireFull` (additive; `CredentialFromWire` stays resumption-only) | `pool.go` |
| `ServerHelloParams.FullHandshake` — omits `pre_shared_key`, the exact 6-byte delta | `serverhello.go` |
| `validateClientHello` split; `validateFullClientHello`; `DrawFullRemainder`; `Adopt` carries jitter | `cover.go` |
| `Options.FullHandshake`, `pre_shared_key` stripped from the template | `twiddle.go` |
| `ClientConfig.FullHandshake`, server dispatch on PSK presence, jittered emission, two-record rotation | `handshake.go` |
| `FullHandshakeCarriers` — the pool is not uniform, so the draw must be restricted | `echcarrier.go` |
| `ProbeResult.RemainderJitter`, filled by `SampleFull` | `cover.go`, `harvest/coverprobe` |

Measured end to end against the microsoft profile: **ServerHello 1215, ccs 6, remainder
`[32 8273 286 74]`** — the shape from `postflight-full-vs-resumed.log`, with the record *count* right,
which is what an observer counts.

Three decisions worth knowing, because each looks like an omission until you see why:

- **The server does not check that the ECH payload length is one of Chrome's buckets.** That is a property
  of what we *emit*, asserted on the emission side. A server refusing anything else would break the first
  device-tapped pool from a Chrome whose buckets differ from the ones we measured, and strictness there
  buys nothing against a censor, who sees the client's hello and not our validation of it.
- **`Twiddle` strips `pre_shared_key` rather than requiring a clean template.** Harvested hellos routinely
  carry one — they come from real browsing, which resumes, and the hellos in `harvest/testdata` do. The
  emitted hello is then shorter than its source by exactly that extension, which is precisely the
  difference between a real Chrome resumption hello and a real Chrome full one.
- **Both tickets of a credential are sealed at the same instant.** `ReplayCache` refuses a ticket older
  than the client's newest, so a one-second skew between them would make whichever path the client used
  *second* look like a stale capture. That failure is invisible to a test of either path alone.

## What remains

1. **Mix policy — the last twiddle-side question.** `ClientConfig.FullHandshake` is per-connection, so the
   mechanism is in place and the policy is the caller's. What still needs deciding is the **re-full
   cadence**: the censor's flow history is finite and the client's context changes, so a reconnection a
   week later, from a different network, after the egress IP rotated, has no observable predecessor even
   though the ticket is valid. Some trigger — new local address, new egress IP, elapsed time — has to force
   a fresh full handshake. Note the resulting ratio will sit *far above* 4% (a long-lived muxed tunnel
   opens few outer connections, so one full per handful of resumed), and that is the correct outcome: what
   a censor can check is whether the predecessor exists, not whether we hit a population average.
2. **Provisioning the companion ticket.** lantern-cloud's `GenerateTwiddle` (PR #3291, draft) must emit
   `full_ticket` alongside `ticket` and `psk`, and lantern-box must pass it to `CredentialFromWireFull`.
   Until then a provisioned client is resumption-only, which degrades to today's behaviour rather than
   failing. `cmd/twiddlecred` already prints it.
3. **A probed full profile per egress.** `CanEmitFullHandshake()` gates both ends on `FullRemainder`, which
   the table ships empty on purpose, so nothing offers the path until `coverprobe.SampleFull` has run
   against the live upstream and `Adopt` has taken the result. The startup-probe plumbing is the same work
   the resumed profile needs.
4. **`sessionTicketWire = 370` is still wrong for all three covers** (microsoft was measured at 303,
   cloudflare and google issue none unprompted). Pre-existing; rotation now sends two records, which is
   closer to microsoft's measured pair, but the size itself is untouched.

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
