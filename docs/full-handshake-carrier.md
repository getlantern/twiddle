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

## Open questions

1. **Does a real Chrome in-region send GREASE ECH to our cover hosts, or real ECH?** The carrier assumes
   GREASE. `docs/ech.md` argues in-region it is GREASE — China prevents real ECH indirectly by censoring
   encrypted DNS resolvers, so no ECHConfig is fetched — and `arrival-chrome152.log` measured GREASE 7/7 to
   a bare IP with no DNS. But that capture *could not* have produced real ECH. **Measure the DNS-enabled
   case** before building: a Chrome with secure DNS on, against `www.cloudflare.com`, will fetch the HTTPS
   RR and send real ECH, whose payload length is set by the encrypted inner hello rather than by
   `echGREASELengths`. If in-region clients would send real ECH, the payload-length model is wrong for them.
   This is the one measurement that can invalidate the carrier, so run it first.
2. **Re-full cadence.** See "Mix policy" reasoning above: the censor's flow history is finite and the
   client's context changes, so some trigger — new local address, new egress IP, elapsed time — has to
   force a fresh full handshake rather than resuming forever off one observed predecessor.
3. **Where credential rotation lives.** It currently rides a NewSessionTicket-shaped record, but cloudflare
   and google send **no** unprompted post-handshake records at all, so on those covers that record has no
   counterpart. Unchanged by this work, but it lands in the same code.
4. **Full-path ticket length.** 144 bytes is proposed so every ECH bucket stays reachable. Confirm
   `MinTicketLen` (76) leaves enough padding entropy, and decide whether the server should accept only 144
   or any length that decrypts.

## Implementation sketch

1. `SetECHTicketAuth` / `VerifyECHTicketAuth` in `auth.go`, mirroring `SetTicketAuth` / `VerifyTicketAuth`:
   write the ticket into the ECH payload padded to the drawn bucket, then HMAC the marshalled hello with
   `random` zeroed and write the result into `random`.
   **Ordering matters,** the same rule the binder follows: the MAC covers the final byte layout, so it is
   computed last. The pipeline becomes `SetSNI → Rerandomize → Shuffle → SetKeyShare → SetECHTicketAuth`.
   Note `Rerandomize` overwrites `h.Random` (`twiddle.go:82`) *and* redraws the ECH payload
   (`rerandECHGrease`), so both writes must follow it.
2. Branch `validateClientHello` (`cover.go:155`) and `Server` (`handshake.go`) on whether `pre_shared_key`
   is present, instead of requiring it. The full path reads the ticket from ECH and verifies the `random`
   MAC; everything downstream — `TicketKey.Open`, `ReplayCache.Consume`, `DeriveSession` — is unchanged.
3. Extend `CanEmitFullHandshake()` to also require an ECH extension whose payload can hold the ticket. A
   pool without ECH falls back to resumption; say why in the comment (see "The objection" above).
4. Server emission: `ServerHelloFullLen`, then CCS, then one record per `FullRemainder` entry, jittered
   within `FullRemainderJitter`. Client: one read per entry.
5. Extend `cover_test.go`'s oracle. It cannot pin `FullRemainder` to a literal (probed, and it jitters);
   pin the *structure* — ServerHello length, record count, plausible range.
6. Mix policy: first contact to an egress is full, later connections resume, plus the re-full trigger from
   open question 2.

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
