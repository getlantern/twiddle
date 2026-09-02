# Should the pooled hellos carry ECH?

**Yes — GREASE ECH, on every hello, unconditionally.** A pooled hello *without* `encrypted_client_hello`
(`0xfe0d`) is the anomaly, not the one with it.

The intuition that pushes the other way is a good one and worth stating fairly: real users in China mostly
are not *using* ECH, so why would their hellos carry it? The answer is that ECH-in-the-hello and ECH-in-use
are two different things, and only the second is rare.

## GREASE ECH is not ECH

There are two shapes of `0xfe0d` on the wire, and they are distinguishable by the first byte of the
extension payload:

| | `config_type` | Payload | Sent when |
|---|---|---|---|
| **GREASE ECH** | `0x00` (outer) | random bytes, length drawn per connection | always |
| **real ECH** | `0x00` (outer) with a genuine `config_id` from a DNS HTTPS RR | the encrypted inner hello | the server published an ECHConfig *and* secure DNS fetched it |

Chrome sends GREASE ECH on **every** TLS connection. That is the entire point of it: if only ECH users sent
`0xfe0d`, the extension would itself be the signal, so Chrome and Firefox send a decoy on every hello so
that the population sending `0xfe0d` is "everyone". `rerandECHGrease` in `twiddle.go` handles only the
GREASE shape and explicitly leaves anything else alone.

## It is not gated on DNS, and we measured that

The strongest form of the worry is mechanical rather than statistical: real ECH needs an ECHConfig from a
DNS HTTPS RR, Chrome only trusts one fetched over secure DNS, and **secure DNS is blocked in China**
([Niere 2025](#references) — China blocks Cloudflare's DoH/DoT resolver by SNI, Iran blocks Cloudflare and
NextDNS by block-page injection and RST). So if GREASE ECH were gated on secure DNS state, Chinese Chrome
would send bare hellos and our pool would be wrong.

It is not gated. `harvest/cmd/arrival` against Chrome 152 to a **bare IP literal** — no DNS query of any
kind, therefore no HTTPS RR and no reachable DoH resolver — produced ECH GREASE on **7 of 7** hellos
(`harvest/testdata/arrival-chrome152.log`). The whole embedded pool is the same story from the other
direction: all 8 hellos were captured against `localhost` and all 8 carry `0xfe0d`.

Broken DNS suppresses *real* ECH. It does not touch GREASE ECH.

## What censors actually do to ECH

| Censor | Treatment | Bears on us? |
|---|---|---|
| **China** | Does **not** block ECH in the ClientHello. Prevents real ECH indirectly, by censoring encrypted DNS resolvers. The 2020 ESNI block was keyed to extension `0xffce` specifically, and ECH codepoints were not blocked. As of Jan 2025 the QUIC censor does not block ECH payloads unless the *cleartext outer* SNI is on the blocklist. | No |
| **Iran** | Same shape as China: no direct ECH block, encrypted DNS censored instead. | No |
| **Russia** | TSPU **does** drop ECH hellos — but only those whose **outer SNI is `cloudflare-ech.com`** *and* whose destination is in Cloudflare's IP ranges. That is a *real* ECH signature: Cloudflare advertises that one static outer SNI in every ECHConfig it publishes. | No — our outer SNI is the cover domain and our egress is not a Cloudflare IP |
| **Wikimedia trial, 7 global PoPs** | No regional ECH blocking or interference observed anywhere. | No |

Note what Russia's rule implies: the censor went out of its way to key on `cloudflare-ech.com` rather than
on the extension. That is the GREASE shield working as designed — a rule matching `0xfe0d` alone would
block all Chrome and Firefox traffic, which is the collateral no censor has been willing to accept.

## Why stripping ECH would be actively worse

Removing `0xfe0d` from the pool would not make us blander; it would make us *rare and internally
inconsistent*.

1. **Internal contradiction.** We would present Chrome's exact cipher list, Chrome's GREASE positions,
   Chrome's extension set, Chrome's post-quantum `key_share` — and no ECH. No Chrome build emits that
   combination. The whole thesis of this transport is that the hello is a real browser's bytes; an
   extension set no browser ships is precisely the fingerprint mismatch we exist to avoid.
2. **We would give up the shield.** Sitting inside the set of connections a censor cannot block without
   blocking all of Chrome and Firefox is the most valuable place on the wire to be. Leaving it is a
   downgrade.
3. **Length parity breaks.** The ECH bucket is 186/218/250/282 bytes, and `handshake_test.go` uses it as
   the *only* permitted length delta between a harvested hello and an emitted one. Removing the extension
   forfeits that, and it is the strongest structural test in the repo.

## The one real risk, and the answer to it

The evidence above is from 2020–2025 and the most recent China data point is January 2025. Censors iterate;
GFWeb documents the GFW actively fixing previously-published evasions. If China ever *does* start blocking
`0xfe0d` in the ClientHello, we need to be able to move within hours, not within a release cycle.

That is exactly what `LoadPool` buys, and it is why the two questions are one question. Because the pool is
data read off disk — device tap first, config second, embedded last — "do our hellos carry ECH?" is a
**data** question answered by whichever pool is in force, not a code question requiring a build. A pool of
non-ECH hellos would be internally consistent only if it came from a browser that genuinely does not send
ECH, and the device tap is the source that supplies exactly that, automatically, because it copies whatever
the browser on that device actually emits.

So: ship ECH, and keep the ability to stop shipping it without shipping anything.

**Monitor:** ECH-bearing ClientHello reachability from CN/IR/RU vantage points, and HTTPS RR (TYPE65) query
blocking — the Wikimedia trial flags the latter as an untested vector that would degrade ECH without
producing TLS-level failures.

## References

Findings drawn from the circumvention corpus:

- **Niere et al. 2025**, *Encrypted Client Hello (ECH) in Censorship Circumvention* — GREASE-ECH collateral
  damage shield; China/Iran suppress ECH via DNS rather than blocking it; Russia TSPU's
  `cloudflare-ech.com` rule; ECH server support is a Cloudflare monoculture (of 640,694 TLS 1.3 servers in
  the Tranco 1M, only 6 non-Cloudflare servers completed an ECH handshake).
- **Zohaib et al. 2025**, *QUIC SNI blocking* — as of Jan 2025 the GFW does not block ECH-bearing QUIC
  payloads unless the cleartext outer SNI is blocklisted.
- **gfw.report 2020**, *Exposing and Circumventing China's Censorship of ESNI* — the ESNI detector was keyed
  to `0xffce`; ECH codepoints were not blocked.
- **Farrell 2025**, *ECH Trial Report* (Wikimedia) — no regional ECH blocking across 7 global data centres.
- **Hoang et al. 2022** — China RST-injects on ESNI; Russia blocks ESNI per-ISP.
