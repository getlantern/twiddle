#!/usr/bin/env python3
"""The FAQ: one list that generates both the visible FAQ section and its
schema.org FAQPage markup in index.html, so the two can't drift apart.

Edit FAQ below, then run: python3 site/tools/faq.py
Answers are HTML (links allowed); the JSON-LD gets the same text with tags
stripped. The script also writes the rest of the JSON-LD graph.
"""
import html
import json
import re
from pathlib import Path

SITE = "https://twiddle.lantern.io/"
REPO = "https://github.com/getlantern/twiddle"

FAQ = [
    ("What is twiddle?",
     "twiddle is an experimental censorship-circumvention transport from "
     "<a href=\"https://lantern.io\">Lantern</a>, written in Go. A connection opens with a "
     "genuine ClientHello harvested from a real browser, with a handful of fields changed. "
     "The server answers with a synthesised ServerHello, and after the compatibility "
     "ChangeCipherSpec records, the connection is an AEAD tunnel framed as ordinary TLS "
     "<code>application_data</code> (<code>0x17</code>) records."),
    ("Why is it called twiddle?",
     "It describes the method: take the bytes a real browser sent and twiddle a handful of "
     "fields, such as the SNI, the authenticator and the extension order, leaving everything "
     "else exactly as the browser produced it."),
    ("Why doesn't twiddle need a real TLS handshake?",
     "In TLS&nbsp;1.3, every handshake message after the ServerHello is encrypted and framed "
     "as an <code>application_data</code> record. Of the TLS records themselves, an observer "
     "can read only the ClientHello, the ServerHello and two one-byte ChangeCipherSpec "
     "records; the rest are opaque. So the connection has to open like TLS, not be TLS. "
     "Record sizes, counts and timing, destination addresses and connection history are "
     "still visible, which is why twiddle pads and segments its records to a measured "
     "browsing profile and picks covers with care."),
    ("How is twiddle different from uTLS?",
     "uTLS is a TLS library that imitates browser fingerprints. twiddle's shipped packages "
     "don't use uTLS or any other TLS library, and a test enforces that. Instead of "
     "driving a TLS stack with a browser preset, twiddle sends a hello a real browser "
     "produced, so there's no key-share splicing, PSK binder obligation or "
     "HelloRetryRequest to handle. Captured hellos still go stale as browsers update, which "
     "is why twiddle prefers hellos tapped from the device's own browser."),
    ("What does twiddle change in the ClientHello?",
     "On every connection it replaces the SNI with the cover hostname, draws fresh random "
     "and session ID bytes, generates fresh key shares, redraws the GREASE values, refreshes "
     "the GREASE ECH extension, shuffles the interior extensions and recomputes the lengths. "
     "Then it adds its authenticator. Ordinary cipher suites, ALPN and the other extension "
     "payloads are copied from the browser's hello. See <a href=\"#rewrites\">exactly what "
     "changes</a>."),
    ("How does a twiddle server recognise its own clients?",
     "Through one of two carriers. A resumption-shaped opening carries a twiddle credential "
     "in the <code>pre_shared_key</code> ticket, with a binder that is an HMAC over the "
     "hello, both opaque to observers by specification. A full-handshake-shaped opening puts "
     "a 144-byte companion ticket in the GREASE ECH payload and an HMAC over the whole hello "
     "in <code>ClientHello.random</code>. Either way, the X25519 key share supplies forward "
     "secrecy."),
    ("What happens when a censor probes a twiddle server?",
     "A connection that fails to authenticate must be forwarded byte for byte to the real "
     "cover site, so the prober gets that site's genuine TLS handshake. twiddle's "
     "<code>Server</code> returns <code>ErrNotOurs</code> for such connections and leaves "
     "the forwarding to the caller; Lantern's sing-box inbound in lantern-box does it."),
    ("Can a captured twiddle handshake be replayed?",
     "The server is built to refuse it. Credentials rotate on every connection, and the "
     "server's replay gate remembers the newest ticket each client has presented, so a spent "
     "or forged ticket takes the cover path like any other connection that fails to "
     "authenticate. One known limit: a replay cache pushed to its client-capacity limit can "
     "evict a still-valid entry."),
    ("Where do twiddle's ClientHellos come from?",
     "In order of preference: hellos tapped from the device's own outbound TLS, then hellos "
     "delivered by configuration. The core uses its compiled-in snapshot only when the caller "
     "explicitly opts in, which is meant for tests; lantern-box currently enables that "
     "fallback, so a working connection doesn't prove the fingerprint is fresh. Sources are never merged, and tapped hellos must pass "
     "through <code>Sanitize</code> before they're stored, because they name sites the user "
     "visited."),
    ("Does twiddle provide post-quantum protection?",
     "No. If the browser's hello offers X25519MLKEM768, twiddle sends a fresh, valid hybrid "
     "key share so the hello looks right, but it discards those private keys. The real key "
     "agreement uses X25519."),
    ("Is twiddle ready to use?",
     "It's experimental. The core transport works end to end and is tested over a real "
     "socket, and lantern-box has a twiddle inbound and outbound, but cloud provisioning is "
     "still in review and this site isn't a deployment announcement. See the "
     "<a href=\"#status\">implementation status</a>. To get around censorship today, "
     "<a href=\"https://lantern.io/download\">download Lantern</a>."),
    ("Where is twiddle's source code?",
     "At <a href=\"" + REPO + "\">github.com/getlantern/twiddle</a>, which is public. It "
     "includes the Go transport and the <code>harvest/</code> tooling and logs behind every "
     "measurement on this page."),
    ("Who makes twiddle?",
     "<a href=\"https://lantern.io\">Lantern</a>, the team behind the Lantern VPN and "
     "censorship-circumvention app, run by Brave New Software Project, Inc."),
]


def strip(s: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", s)).replace(" ", " ")


def faq_html() -> str:
    items = []
    for q, a in FAQ:
        slug = re.sub(r"[^a-z0-9]+", "-", q.lower()).strip("-")
        items.append(
            f'      <div class="qa" id="{slug}">\n'
            f'        <h3>{html.escape(q)}</h3>\n'
            f'        <p>{a}</p>\n'
            f'      </div>'
        )
    return "\n".join(items)


def faq_jsonld() -> dict:
    return {
        "@type": "FAQPage",
        "@id": SITE + "#faq",
        "isPartOf": {"@id": SITE + "#webpage"},
        "mainEntity": [
            {"@type": "Question", "name": q,
             "acceptedAnswer": {"@type": "Answer", "text": strip(a)}}
            for q, a in FAQ
        ],
    }


def graph() -> dict:
    org = {
        "@type": "Organization",
        "@id": "https://lantern.io/#organization",
        "name": "Lantern",
        "legalName": "Brave New Software Project, Inc.",
        "url": "https://lantern.io",
        "sameAs": ["https://github.com/getlantern"],
    }
    return {
        "@context": "https://schema.org",
        "@graph": [
            org,
            {
                "@type": "WebSite",
                "@id": SITE + "#website",
                "url": SITE,
                "name": "twiddle",
                "publisher": {"@id": org["@id"]},
                "inLanguage": "en",
            },
            {
                "@type": "WebPage",
                "@id": SITE + "#webpage",
                "url": SITE,
                "name": "twiddle — a TLS ClientHello, byte by byte, from Lantern",
                "isPartOf": {"@id": SITE + "#website"},
                "about": {"@id": SITE + "#software"},
                "publisher": {"@id": org["@id"]},
                "primaryImageOfPage": SITE + "og.png",
                "inLanguage": "en",
            },
            {
                "@type": "SoftwareSourceCode",
                "@id": SITE + "#software",
                "name": "twiddle",
                "description": strip(FAQ[0][1]),
                "codeRepository": REPO,
                "programmingLanguage": "Go",
                "url": SITE,
                "author": {"@id": org["@id"]},
                "keywords": "censorship circumvention, TLS ClientHello, TLS fingerprinting, "
                            "uTLS, active probing, GREASE, ECH, pre_shared_key",
            },
            faq_jsonld(),
        ],
    }


def main() -> None:
    p = Path(__file__).resolve().parent.parent / "index.html"
    s = p.read_text()
    s = re.sub(r"(<!-- faq:start -->).*?(\n[ \t]*<!-- faq:end -->)",
               lambda m: m.group(1) + "\n" + faq_html() + m.group(2), s, flags=re.S)
    ld = json.dumps(graph(), ensure_ascii=False, indent=1)
    s = re.sub(r'(<script type="application/ld\+json">\n).*?(\n</script>)',
               lambda m: m.group(1) + ld + m.group(2), s, flags=re.S)
    p.write_text(s)


if __name__ == "__main__":
    main()
