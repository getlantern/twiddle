# The ephemeral encoding problem

**Status: unresolved. `auth.go` currently ships a known-distinguishable encoding.**

## The problem

The PSK ticket must be indistinguishable from what a real session ticket contains: AEAD ciphertext, i.e.
uniform bytes. We currently place a raw X25519 public key in the first 32 bytes of it, and that is
distinguishable two ways:

1. **Top-bit bias.** An X25519 public key is a field element below 2^255−19, so bit 255 is always zero.
   *Fixed* — we randomise it, which RFC 7748 §5 permits because receivers must mask that bit.
2. **Curve membership.** Only about half of all field elements are valid Curve25519 u-coordinates; the rest
   lie on the quadratic twist. **One Legendre-symbol test separates a real X25519 key from random bytes with
   a full bit of advantage per sample**, and a censor can accumulate that across connections at negligible
   cost. *Not fixed.*

## Why the obvious fixes do not work

Elligator2 is the standard answer — it maps curve points to representatives uniform over the field. But
every readily available Go option shares one flaw:

| Option | Licence | Problem |
|---|---|---|
| obfs4 / Lyrebird `internal/x25519ell2` | **GPL-3** | correct, but `internal/`, and the licence would propagate to this module |
| `github.com/go-i2p/crypto/elligator2` | MIT | `GenerateKeyPair` calls `curve25519.X25519`, which **clamps** |
| a hand-rolled inverse map | — | same clamping trap, plus unreviewed crypto in the auth path |

Clamping is the trap. Lyrebird's own documentation states it plainly:

> The `privateKey` input MUST be the full 32-bytes of entropy (X25519-style "clamping" will result in
> non-uniformly distributed representatives).

Clamping clears the low three bits, so the scalar is a multiple of 8 and the public key always lands in the
prime-order subgroup — one eighth of the curve. Elligator2's image is the whole curve, so representatives of
those points are **not** uniform. Monocypher works around it with a "dirty" key carrying a random low-order
component. This is a well-known trap that most implementations fall into, which is reason enough not to
hand-roll it here.

## Recommended fix: make the ticket a real ticket

The cleanest resolution removes the exotic crypto instead of getting it right.

Real TLS tickets are `AEAD(server_ticket_key, session_state)` — uniform by construction, with no curve
structure to detect. We can do exactly that, because we already have a provisioning relationship with every
client through the config path:

```
ticket = nonce ‖ AEAD(k_server, client_id ‖ psk ‖ issued_at)
binder = HMAC(derive(psk), truncated ClientHello)
```

The server decrypts with its own long-term ticket key, recovers the psk, and verifies the binder. The client
never performs a DH. Tickets rotate — the server issues the next one inside the encrypted flight, exactly as
`NewSessionTicket` does — and the first arrives via config provisioning.

**This is literally TLS 1.3 resumption**, which is a virtue: the semantics match the thing we are imitating,
so there is nothing to get subtly wrong.

**The tradeoff.** [authentication.md](https://github.com/getlantern/discovery-engine) chose ECDH-to-a-static-key
so the client holds *no* long-term secret: obtaining a client's config would teach a censor only a public
key, useless for verifying anyone. With tickets, a stolen config lets a censor verify that client's
connections until the ticket rotates. Against that: anyone can obtain a config by becoming a user, and it
only ever compromises the one client, whose ticket is single-use and short-lived.

## Decision needed

- **Ticket-based (recommended)** — no exotic crypto, uniform by construction, matches TLS semantics; costs
  the no-long-term-secret property.
- **ECDH + Elligator2** — keeps that property; costs either a GPL-3 dependency or a correct dirty-key
  implementation that needs real cryptographic review.

Until one is chosen, `auth.go` remains distinguishable by the Legendre test and **must not ship**.
