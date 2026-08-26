# Cover domains

Every server picks a domain it masquerades as. The choice should be **as random as possible**, per server,
drawn from the unblocked long tail — for the same reason the rest of the transport blends rather than hides.

## Why per-server, and why random

**Per-server** means blocking a cover SNI costs the censor **one server**, not the fleet. A single shared
cover domain would be a fleet-wide kill switch sitting in plaintext on every connection we make.

**As random as possible** attacks enumerability. A small curated list is learnable: a censor collects our
SNIs over time, and once the list is known, blocking it is cheap and precise. Drawn from a large enough
space, the set is not enumerable, and blocking it means blocking an arbitrary slice of the web — which is
the collateral cost we want the censor to face.

Some of this exists already. `lantern-cloud`'s config generation picks a per-proxy cover with
`tmasqorigins.RandomOrigin(tmasqorigins.PrunedDefault)`, and `masquerade_domain` is already an experiment
axis in `cmd/api/experiment/mutation.go`. So the mechanism is there; what this document argues for is
**widening the draw** and making the constraints on it explicit.

## What bounds the randomness

A uniformly random domain is not automatically a good cover. Four constraints, roughly in order of how much
they bite:

**1. SNI/IP consistency.** A censor can resolve the SNI we present and compare it to the IP we are talking
to. Systematic mismatch across a fleet is a cheap, durable signal — and it is the main reason "as random as
possible" cannot mean "uniform over all domains."

The mismatch is not damning in isolation: CDNs, multi-tenant hosting, DNS load balancing, split-horizon DNS
and HTTP/2 connection coalescing all break the correlation legitimately, and plenty of real traffic shows
SNI that does not resolve to the connected IP. But *ours* would break it the same way every time, on every
server, which is what makes a pattern out of a coincidence. **Prefer covers whose real hosting makes the
mismatch unremarkable** — domains behind large CDNs and multi-tenant providers, where an IP legitimately
serves thousands of names.

**2. The splitter needs a real forwarding target.** Under theater we cannot complete a genuine handshake, so
every failed authentication must be forwarded to something that answers convincingly
(`forwardToMasquerade`). The cover therefore has to be reachable from the egress, speak TLS 1.3, and behave
plausibly under a probe. That rules out a large part of the long tail.

**3. Traffic-profile plausibility.** A tiny site cannot absorb a proxy's volume. Hundreds of gigabytes a
month toward an obscure domain, at an IP that is not that domain's, is anomalous on two axes at once. The
cover's plausible traffic envelope should be at least as large as what the server actually carries.

**4. Regional reachability.** "Unblocked" is per-region and changes. A cover that works from Russia may be
blocked from Iran, and either may change next week.

## Which makes this a measurement problem, not a configuration one

Constraint 4 is the reason cover selection belongs in the promotion substrate rather than a static list.
`masquerade_domain` is already an axis, so the machinery exists: candidate covers are proposed, ramped
0.02 → 1.0, and demoted automatically when success rate drops in a region.

> **"Chosen as randomly as possible" is the prior; the bandit narrows it to "randomly, from the set that
> empirically survives in this region."**

That also gives rotation for free. A burned cover shows up as a per-region success collapse on that axis
value and is demoted without anyone paging.

## Two open choices

**Per-connection instead of per-server?** A shared-hosting or CDN IP legitimately serves many names, so
varying the cover per connection is *more* realistic for those IP types, not less. The cost is that the
splitter must then forward to whichever domain the connection claimed. Worth deciding deliberately rather
than defaulting to per-server.

**Where the candidate pool comes from.** A ranked list (Tranco, Cloudflare Radar) gives reachability and
volume plausibility but is itself enumerable — a censor can draw from the same list. Sampling the long tail
is less enumerable but strains constraints 2 and 3. This tension is unresolved and is the part most worth
thinking about before wide deployment.

## Implementation note

Substituting the cover SNI into a harvested ClientHello is a length-changing edit: it cascades through five
nested length fields (extension, extensions block, ClientHello body, handshake message, record). Nothing
absorbs the delta — modern Chrome does not send the `padding` extension (absent in all 18 captures), and ECH
GREASE length was measured to be **independent** of SNI length, varying randomly in 32-byte buckets. That is
fine, because real hellos to different sites genuinely differ in length; it just means the cascade has to be
computed rather than assumed.
