# Packetisation of the opening flight

The hello is not just a byte string; it is a byte string delivered in some number of packets, at some set of
boundaries. That is observable, so it is part of the fidelity surface. This note records what Chrome does and
what we should do about it.

Measurements: `harvest/cmd/arrival`, log in `harvest/testdata/arrival-chrome152.log`.

## TCP: one write, and we already match

Chrome hands the entire ClientHello to the socket in **one write**. Measured against Chrome 152, seven
hellos of 1919–2015 bytes each arrived as a single read. It does not split the record, and it does not
stagger the write.

`handshake.go` does `raw.Write(wire)` once. That is the faithful behaviour, and the interesting conclusion
is a negative one: **do not add write-splitting.** Segmentation on a real path is the kernel's job, and given
equal total length the kernel produces the same segments for us as for Chrome. Since we already hold total
length to within the ECH bucket (`handshake_test.go`), segmentation parity comes for free.

Deliberate splitting would be worse than neutral. Splitting a ClientHello across TCP segments is a
*well-known censorship-evasion signature*, and the corpus is clear that it is both fingerprintable and
increasingly ineffective: GFWeb documents the GFW improving fragmented-packet reassembly specifically to
close it, and Russia's TSPU added TCP reassembly that defeats fragmentation-only bypasses. A transport whose
whole claim is "these are a browser's bytes" should not adopt the one packetisation pattern browsers do not
use and censors have built detectors for.

How many segments a hello actually spans is then just arithmetic on the length:

| MSS | 1919 B hello | 2015 B hello |
|---|---|---|
| 1460 (Ethernet) | 2 | 2 |
| 1400 | 2 | 2 |
| 1360 (common tunnelled) | 2 | 2 |
| 1008 or below | 3 | 3 |

So on TCP the hello is a two-segment object across every common path, and three only under an unusually
small MSS. **Worth noting for Lantern specifically:** twiddle may itself run inside a tunnel that lowers the
effective MSS. That does not create a mismatch — the browser on the same path would be segmented
identically — but it does mean segment counts observed in the field are a property of the path, not of us,
and should not be "corrected" toward a number measured somewhere else.

## QUIC: where "three packets" comes from

The three-packet story is real, and it is a **QUIC** story, not a TCP one.

A QUIC Initial packet is capped at the anti-amplification datagram size — Chrome uses 1250 bytes. A
post-quantum ClientHello is ~1950 bytes and does not fit. So Chrome splits it across CRYPTO frames in
consecutive Initial packets. Measured:

```
udp 1: 1250 B  Initial  @    0.00ms   <-- opening flight
udp 2: 1250 B  Initial  @    2.08ms   <-- opening flight
udp 3: 1250 B  Initial  @  302.63ms   retransmit
udp 4: 1250 B  Initial  @  906.06ms   retransmit
```

Two datagrams, back to back, both padded to 1250. **Two is the floor, not the norm** — our capture went to
an IP literal, so it carried no `server_name` at all. A real hello with an SNI, a top-bucket ECH GREASE and
a fuller ALPN list crosses 2500 bytes and needs a third.

On top of that, Chrome deliberately scrambles the layout. **Chaos Protection** (`QuicChaosProtector` in
QUICHE, shipped since 2021) splits the CRYPTO stream into multiple frames, reorders them, and interleaves
PADDING and PING frames — originally an anti-ossification measure, to stop middleboxes assuming the
ClientHello arrives as one contiguous in-order frame at a fixed offset. Wireshark had to add out-of-order
CRYPTO reassembly to cope with it. Wustrow's group models it as a fingerprint dimension in
`refraction-networking/uquic`: frame-splitting layout, PADDING frame count and placement, and PING
positioning are all part of what a QUIC client looks like.

This has a censorship consequence that runs in our favour and is worth knowing: the GFW decrypts QUIC
Initials (since April 2024) but **does not reassemble** CRYPTO frames split across datagrams, nor split
within one datagram. Chrome's own chaos protection therefore incidentally evades the GFW's QUIC SNI
extraction.

### What this means for twiddle

**Today: nothing.** twiddle is TCP-framed. Chaos protection has no analogue in a TLS-over-TCP hello — there
are no CRYPTO frames to shuffle, and TLS record fragmentation is *not* the same thing and is not something
Chrome does.

**If a QUIC mode is ever added, this becomes a hard requirement, not a nicety.** The `Shuffle`-and-emit
approach that suffices on TCP would not: emitting a harvested QUIC Initial with a fixed frame layout, a
fixed PADDING count and a contiguous CRYPTO frame would be distinguishable from Chrome at a glance, and
distinguishable in exactly the dimension Wustrow's group has already published tooling to measure. The
packetisation would have to be re-randomised per connection the same way `Shuffle` re-randomises extension
order — and for the same reason, that holding it constant is itself the tell. `uquic` is the reference for
what has to be reproduced.

The cheap thing to do now is to have written that down, which is this paragraph.

## Retransmission

Both transports expose a retransmit schedule if the peer stalls. Chrome's QUIC Initial backoff measured
~300 / 600 / 1200 / 1900 ms, then the attempt is abandoned and a fresh connection opens from a new source
port. twiddle's egress answers immediately, so this is not currently a live surface — but a slow or
overloaded egress would produce client retransmits, and a *timeout* pattern unlike a real server's is
another thing a censor can measure. Filed here rather than acted on.

## References

- `harvest/testdata/arrival-chrome152.log` — the measurements above.
- `QuicChaosProtector`, QUICHE — frame splitting, reordering, PADDING/PING interleaving.
- `refraction-networking/uquic` — QUIC Initial fingerprint dimensions, including chaos-protection layout.
- **Zohaib et al. 2025** — the GFW does not reassemble QUIC CRYPTO frames across or within datagrams;
  Chrome's chaos protection and PQ key sizes exploit this incidentally.
- **GFWeb** — the GFW has improved fragmented-packet reassembly, deprecating TCP-segmentation evasion.
- **Niere et al. 2025** — TSPU added TCP reassembly; fragmentation alone no longer bypasses it.
