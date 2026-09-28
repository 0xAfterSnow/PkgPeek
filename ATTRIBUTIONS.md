# Attributions

The tools directory displays third-party brand marks. This file records where
each one came from, so the provenance is auditable.

**Trademarks belong to their respective owners.** Their inclusion here is for
identification in a directory of tools, which is nominative use — it is not a
claim of endorsement, affiliation, or sponsorship. Simple Icons is a
[CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) (public domain)
collection, which is why it is the preferred source.

## Current marks

| Tool | File | Source | Licence |
| ---- | ---- | ------ | ------- |
| Snyk Security | `snyk-security-487f695c.svg` | [Simple Icons](https://simpleicons.org/?q=snyk) | CC0 1.0 — trademark © Snyk |
| npm Audit | `npm-audit-6b58690f.svg` | [Simple Icons](https://simpleicons.org/?q=npm) | CC0 1.0 — trademark © npm, Inc. |
| OWASP Checker | `owasp-checker-b93b94c9.svg` | [Simple Icons](https://simpleicons.org/?q=owasp) | CC0 1.0 — trademark © OWASP Foundation |
| npm audit | `npm-audit-6b58690f.svg` | [Simple Icons](https://simpleicons.org/?q=npm) | CC0 1.0 — trademark © npm, Inc. |
| Snyk CLI | `snyk-cli-487f695c.svg` | [Simple Icons](https://simpleicons.org/?q=snyk) | CC0 1.0 — trademark © Snyk |
| Retire.js | `retire-js-b19f882b.png` | **PkgPeek-generated monogram** | MIT (this repo) |
| Dependabot | `dependabot-98396477.svg` | [Simple Icons](https://simpleicons.org/?q=dependabot) | CC0 1.0 — trademark © GitHub, Inc. |
| Socket Security | `socket-security-39c5f558.svg` | [Simple Icons](https://simpleicons.org/?q=socket) | CC0 1.0 — trademark © Socket, Inc. |
| OSV Database | `osv-database-a6eac83e.png` | **PkgPeek-generated monogram** | MIT (this repo) |

## Why two entries are monograms rather than brand marks

We do not invent, approximate, or trace a mark that the owner has not published
as a vector.

- **OSV** publishes only a rasterised 53×20 wordmark
  ([`logo.png`](https://osv.dev/static/img/logo.png)). Tracing that to a path
  would produce something inaccurate at the size a card renders it, so it is left
  as a monogram.
- **Retire.js** publishes no official mark.

If either project publishes a vector mark, add it with
`python tools/fetch_brand_logos.py` (edit `BRANDS` first) and drop the row here.

## White-on-transparent alternates

`snyk-on-dark.svg` is white artwork on a transparent background, kept as an
alternate for the two Snyk entries. To use it, point the tool at it and set the
tile so it stays visible:

```jsonc
{
  "name": "Snyk CLI",
  "logo": "/logos/curated/snyk-on-dark.svg",
  "logo_tile": "dark"      // white artwork needs a dark tile
}
```

The default `logo_tile` is `light`, which is correct for the dark monochrome
marks. The value lives in `data/detections/tools.json` rather than being guessed
from the file extension, because only the artwork knows which is which.

## Why filenames carry a content hash

Every curated file is named `<slug>-<8 hex of sha256>.<ext>`, for example
`snyk-cli-487f695c.svg`. Logos are served with
`Cache-Control: immutable, max-age=1y`, which is only safe if a URL never
changes meaning. Under a stable name, regenerating a logo would reuse the URL,
and every browser that had already cached it would keep showing the old mark
indefinitely. Hashing the bytes into the name means changed content produces a
changed URL.

If you add a logo by hand, suffix it with a hash too:

```bash
python -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest()[:8])" static/logos/my-logo.svg
```

Both generator scripts do this for you.

## Advertiser uploads

Logos submitted through `/submit-tool` are **not** listed here. They belong to
whoever submitted them. When `BYTESHIP_API_KEY` is set they are stored on
[Byteship](https://byteship.dev) and served from its CDN; otherwise they land in
`static/uploads/logos/` under randomised filenames. Either way they are
restricted to raster formats and identified by magic bytes. Paid placement is
always labelled **Sponsored** and is never presented as an organic
recommendation.

## Re-fetching or replacing a mark

```bash
python tools/fetch_brand_logos.py            # report what is available
python tools/fetch_brand_logos.py --write    # download into static/logos/
python tools/generate_logos.py               # monograms for anything without a mark
python database.py                           # verify every path resolves
```

`python database.py` fails if any `logo` path is unserveable or points at a file
that does not exist, so a broken mark cannot ship.
