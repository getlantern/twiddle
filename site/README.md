# site

The twiddle protocol site, deployed to Cloudflare Pages. Static — no build step, no
framework, no bundler. Three files plus a headers policy.

## Local

```bash
python3 -m http.server 8899 --bind 127.0.0.1   # then open http://127.0.0.1:8899/
```

## Deploy

Either connect this repo in the Cloudflare Pages dashboard with **build command: none** and
**output directory: `site`**, or push directly:

```bash
wrangler pages deploy site --project-name twiddle --branch main
```

Live at **https://twiddle.lantern.io** (custom domain; the project's own `pages.dev` name is
`twiddle-7qq`, because `twiddle.pages.dev` is taken by an unrelated account and those subdomains are
global rather than per-account).

## Regenerating the byte map

`app.js` embeds a real ClientHello captured from Chrome, with its fields annotated. To rebuild
it from a different capture, point the generator at another line of `pool/chrome.hex` — the
span offsets are computed by walking the record, not hard-coded, so any valid hello works.

The rendered capture's SNI is `localhost`: it was taken against a local server, so the file
carries no one's browsing.

## Not-found page

`404.html` is the not-found page. Without it, Cloudflare Pages answers every path that has no
file with `index.html` and a 200, so crawlers see a copy of the home page at every broken link. It uses `style.css`, because
the `_headers` CSP blocks inline styles.

## The FAQ and structured data

The FAQ lives in `tools/faq.py`, which writes both the visible FAQ section and the schema.org
`FAQPage` markup into `index.html`, so the two always say the same thing. To change a question or
answer, edit the list there and run `python3 site/tools/faq.py`. The same script writes the rest of
the JSON-LD graph (`Organization`, `WebSite`, `WebPage`, `SoftwareSourceCode`). Check every answer
against the repo before changing it; there's no `license` in the graph because the repo has no
LICENSE file yet.

`og.png` is the 1200×630 link-preview image, a screenshot of `tools/og.html` (styles in
`tools/og.css`); its bytes are the first bytes of `pool/chrome.hex`. `robots.txt` and `sitemap.xml`
point crawlers at the one page; update the sitemap's `lastmod` when the page changes.
