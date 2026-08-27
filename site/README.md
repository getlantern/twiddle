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
npx wrangler pages deploy site --project-name twiddle
```

## Regenerating the byte map

`app.js` embeds a real ClientHello captured from Chrome, with its fields annotated. To rebuild
it from a different capture, point the generator at another line of `pool/chrome.hex` — the
span offsets are computed by walking the record, not hard-coded, so any valid hello works.

The rendered capture's SNI is `localhost`: it was taken against a local server, so the file
carries no one's browsing.
