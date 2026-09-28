# Security Policy

## Reporting a vulnerability in PkgPeek

**Please do not open a public issue for a security vulnerability in this
project.** Email the maintainer instead, or use GitHub's private vulnerability
reporting on this repository.

Include what an attacker can do, and how to reproduce it. Please give us a
reasonable window to ship a fix before disclosing.

## Reporting a malicious npm package

That is not a vulnerability in PkgPeek — it is the thing PkgPeek is for. Use
[/report](https://pkgpeek.example/report). Submissions are reviewed by a
maintainer and never applied automatically.

## Supported versions

PkgPeek is pre-1.0. Fixes land on `main` and there are no backports to older
tags.

## How PkgPeek handles untrusted input

Worth knowing if you are auditing it or extending it:

| Surface                | Handling                                                                 |
| ---------------------- | ------------------------------------------------------------------------ |
| Package reports        | Validated, length-capped, control characters stripped, queued for review.  |
| Tool listings          | Same, plus URL scheme allowlist (`http`/`https`) and a 200-char description cap. |
| Logo uploads           | Identified by magic bytes, not by filename or Content-Type. PNG/JPEG/WebP only — **uploads cannot be SVG** because an SVG is an XML document that can carry script. Filenames are randomised, never user-controlled. |
| Curated logos          | May be SVG: they are committed to git and only land through a reviewed pull request. Served with the same sandbox CSP, so script is blocked even on direct navigation, and SVG in an `<img>` cannot execute anyway. |
| Logo serving           | `X-Content-Type-Options: nosniff` plus `Content-Security-Policy: default-src 'none'; sandbox`. |
| Byteship API key       | Server-side only, read from `BYTESHIP_API_KEY` and never returned by any endpoint — `byteship.config()` exposes the host and folder but not the key. All uploads are server-to-server, so no browser upload token is needed. |
| Byteship object paths  | Random `token_hex(16)` filename, so no user input reaches the path and two advertisers can never overwrite each other's logo. |
| State-changing requests| CSRF token required, validated with a constant-time compare.               |
| Admin endpoints        | HTTP Basic auth, reusing the same check as the admin panel. No second auth system. |
| Listing status pages   | Addressed by an unguessable token, not by numeric id, so ids cannot be enumerated. |
| Rate limiting          | `/api/scan` 10/min, public submission endpoints 5/hour.                      |
| Session cookie         | `HttpOnly` + `SameSite=Lax`; set `PKPEEK_SECURE_COOKIES=1` behind TLS.        |

### Known limitations

- **User-submitted data is not durable without `DATABASE_URL`.** Reports, tool
  submissions, paid listings and uploaded logos are written to the database and
  to `static/uploads/`. With the default local SQLite that means `data/pkguard.db`
  plus files on disk. On a host with an **ephemeral** filesystem — Render,
  Railway, Fly.io, most container platforms — all of it is destroyed on every
  redeploy, taking pending submissions, live paid listings, their logos, and
  customers' email addresses with it. The detection dataset is unaffected
  because it lives in git. `/admin` shows a warning banner when user data is at
  risk, and `GET /admin/storage` reports it as JSON. **Set `DATABASE_URL` to
  PostgreSQL before enabling `/submit-tool`.**
- **Uploaded logos are never garbage-collected.** A submission's logo is only
  removed when you delete it explicitly; rejected and expired listings keep
  theirs. On a persistent volume that is harmless, but it does grow.
- **Rate limiting uses in-memory storage by default.** Limits reset on restart
  and are per-process, so they are weaker behind multiple gunicorn workers. Set
  `LIMITER_STORAGE_URI` to a Redis URL in production.
- **CSRF tokens are embedded in cached HTML.** The service worker therefore
  serves navigations network-first rather than cache-first. A page served from
  cache offline cannot submit a form.
- **Tool listings expire but are never purged.** Expired rows stay in the
  database so a listing can be renewed manually.
- **No webhook verification for payments.** By design for this MVP: payment is
  confirmed manually by a maintainer against the Dodo dashboard. Until
  webhooks exist, the "I've completed payment" button is *not* proof of
  payment and the app does not claim it is.
- **An old service worker can serve stale directory data.** If you have PkgPeek
  installed as a PWA from before the rename, the v2 worker cached `/` and
  `/api/*`. The current worker (`pkgpeek-v3`) skips `/api/`, self-updates via
  `skipWaiting` + `clients.claim`, and deletes old caches on activate, so one
  reload resolves it. If a tool's logo looks stale, hard-refresh.

## Reporting a false positive

Use "This looks wrong" on a scan result, or
[/report](https://pkgpeek.example/report). The best fix is a regression test in
the same pull request — see [CONTRIBUTING.md](CONTRIBUTING.md).
