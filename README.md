<div align="center">

# 🛡 PkgPeek

**npm supply chain security scanner**

Paste your `package.json`, get every dependency checked against known malware,
live CVE advisories, typosquat patterns and suspicious publish signals — with
the evidence behind every finding.

[![CI](https://github.com/0xaftersnow/pkgpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/0xaftersnow/pkgpeek/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## Why this exists

Most "is my dependency safe" tools are a thin wrapper over `npm audit`, which
only knows about CVEs. The attacks that actually cost people their credentials —
the ones that run code on `npm install` — do not have a CVE number. Those
land in a curated dataset, and PkgPeek is built so that dataset is public,
editable, and reviewable.

Three things make it different from a scanner you'd normally point at:

- **Every finding is auditable.** Not "❌ Malicious", but the source, the
  evidence link, when it was recorded, and exactly which versions are affected.
- **Anyone can improve it.** Detections are JSON in a public repository. Fixing
  a false positive is a pull request plus a regression test.
- **Submissions are never trusted automatically.** Reports go to a review
  queue. Nobody can mark `react` as critical with a text box.

## How it works

```
package.json
     │
     ▼
┌──────────────────────────────────────────┐
│  4 independent checks, per dependency    │
├──────────────────────────────────────────┤
│  1  PkgPeek dataset   (data/detections)  │  known malware, CVEs, typosquats
│  2  OSV.dev           (live API)         │  upstream advisories + fixed version
│  3  Typosquat engine  (local)            │  name similarity vs 70 known targets
│  4  npm Registry      (live API)         │  age, maintainers, publish velocity
└──────────────────────────────────────────┘
     │
     ▼
  risk score 0–100  +  a suggested fix
```

For anything flagged, PkgPeek resolves a concrete next step rather than leaving
you to work it out:

| Situation                    | Suggestion                                          |
| ---------------------------- | --------------------------------------------------- |
| Vulnerable version           | The exact minimum patched version from the advisory  |
| Typosquat                    | `npm uninstall <bad> && npm install <real>`           |
| Package missing from npm     | "Did you mean X?" (83% match)                        |
| Latest is also compromised   | "Remove this package"                                |
| Already on latest            | "Await upstream patch"                               |

## Try it

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"packageJson": "{\"dependencies\":{\"lodash\":\"4.17.15\",\"mongose\":\"1.0.0\"}}"}'
```

## Quick start

```bash
git clone https://github.com/0xaftersnow/pkgpeek.git
cd pkgpeek

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

cp .env.example .env      # add a SECRET_KEY
python database.py        # create + seed the database
python app.py             # http://localhost:5000
```

Production:

```bash
gunicorn wsgi:app --workers 2 --timeout 60 --bind 0.0.0.0:$PORT
```

A `Procfile` is included for Render, Railway and Fly.io, and a `Dockerfile` for
anything container-based. See [`.env.example`](.env.example) for every setting,
and the [contributing guide](CONTRIBUTING.md) for the full setup.

### The start command is always `python serve.py`

Set the start command to exactly that, on every platform:

```bash
python serve.py
```

**Do not put server flags in the platform config.** That is the most common way
a deploy breaks: a platform with the server set to Uvicorn but a start command
read from a gunicorn `Procfile` passes gunicorn's `--timeout` to uvicorn, which
has no such option, and the service exits with

```
Error: No such option '--timeout'. (Did you mean one of: '--timeout-keep-alive', ...?)
```

`serve.py` exists to make that impossible. It initialises the database, then
picks the server and its own flags:

- **Uvicorn + `asgi:app`** when uvicorn is installed. Single process, no
  `fork()`, so this is the only option on WASM/WASI targets such as Wasmer.
- **Gunicorn + `wsgi:app`** otherwise, with `--worker-class gthread
  --threads 4`, which suits the I/O-bound scanning work.

Override with `PKPEEK_SERVER=asgi` or `PKPEEK_SERVER=wsgi` if the automatic
choice is wrong. `PKPEEK_THREADS` tunes the gunicorn thread count.

On a normal Linux host, install gunicorn. On Wasmer, make sure uvicorn ends up
installed — its build step does that when its server setting is Uvicorn, or add
it to the install command explicitly.

### Container notes

Two things that bite on hosts with a read-only or ephemeral filesystem:

- `python database.py` runs at **startup**, not at build time, so a
  `DATABASE_URL` that only exists at runtime still initialises the real database.
  Doing it at build time would set up SQLite and leave the real one empty.
- The healthcheck uses Python rather than curl, so the image needs no
  `apt-get` at all — one dependency source, and one less thing to fail on a
  slow or restricted network.

`PKPEEK_DB_PATH` defaults to `/tmp/pkgpeek.db` in the image, because `/app` is
read-only on most hosts. That is a deliberate fallback: it works, but the file
is discarded on every redeploy, so set `DATABASE_URL` for anything real.

### WASM / WASI targets (Wasmer)

Wasmer builds for `wasix_wasm32`, which changes two things:

- **No `fork()`.** Gunicorn's `--workers 2` cannot work, so `Procfile` uses
  `--worker-class gthread --threads 4` instead: one process, four threads. That
  is the right shape for this app anyway, since a scan blocks on the OSV.dev and
  npm registry APIs.
- **Wasmer may pick an ASGI server.** If its build config sets the server to
  Uvicorn, use the `asgi.py` entry point, which serves the same Flask app over
  ASGI without adding a hard dependency:

  ```bash
  pip install uvicorn
  uvicorn asgi:app --host 0.0.0.0 --port $PORT
  ```

  Uvicorn is deliberately **not** in `requirements.txt`; it is only needed on
  targets that cannot run a WSGI server.

Two build details worth knowing, both of which caused real failures here:

- Wasmer runs the install step **before** copying the source in, so
  `pip install -r requirements.txt` cannot find the file. Either use the
  committed `Dockerfile`, point the install command at a raw URL, or set
  `DOCKERFILE = true` in the build config.
- Wasmer's build runs `uv add`, which **requires a `pyproject.toml`**. One is
  committed for exactly that reason, with `package = false` so `uv` does not try
  to build a wheel. Dependencies stay in `requirements.txt`; a test asserts
  `pyproject.toml` never duplicates them.

### ⚠ Set `DATABASE_URL` before taking paid listings

The detection dataset lives in git, so it is always safe. **Everything a user
submits is not.** Package reports and tool listings go to the database, and
uploaded logos go to `static/uploads/logos/`. With the default local SQLite
those live in `data/pkguard.db` and on disk — which is fine locally, and
**destroyed on every redeploy** on any host with an ephemeral filesystem
(Render, Railway, Fly.io, most container platforms).

That means losing pending submissions, published paid listings, their logos, and
customers' email addresses. Set `DATABASE_URL` to a managed PostgreSQL instance
before you enable `/submit-tool`. The admin panel shows a warning banner when
user data is sitting in non-durable storage, and `GET /admin/storage` reports
the same as JSON:

```bash
DATABASE_URL=postgresql://user:pass@host:5432/pkgpeek
```

Uploaded logos are the other half of this. Set `BYTESHIP_API_KEY` and they go to
[Byteship](https://byteship.dev) and are served from its CDN, so they survive a
redeploy too:

```bash
BYTESHIP_API_KEY=bship_...   # needs the files:write scope
BYTESHIP_FOLDER=pkgpeek/logos
```

Unset, they fall back to `static/uploads/logos/` — fine locally, gone on
redeploy in production.

## Project layout

```
pkgpeek/
├── app.py            # Flask routes, auth, CSRF, rate limiting
├── scanner.py        # the four checks + the suggestion engine
├── detections.py     # read access to the dataset
├── database.py       # connections, schema, migrations, dataset sync
├── reports.py        # package reports + false-positive queue
├── toolstore.py      # tool directory + paid listing lifecycle
├── logos.py          # logo storage: curated vs uploaded, path rules
├── byteship.py       # Byteship client for advertiser-uploaded logos
├── validate.py       # one place for all untrusted-input rules
├── tools/            # maintainer scripts (generate + repair logos)
├── data/detections/  # ← the source of truth, edit this in a PR
│   ├── malicious.json
│   ├── vulnerabilities.json
│   ├── typosquats.json
│   ├── suspicious.json
│   └── tools.json
├── templates/        # index, report, contribute, submit-tool, admin
├── static/           # main.js, style.css, service worker
└── tests/            # 168 tests
```

The database is a **cache**. `data/detections/*.json` is the source of truth,
rebuilt into the tables on every start. Adding a detection means editing a JSON
file — there is no migration to write.

## Contributing

Detection or code, both welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for how
detections are evaluated, how severity is assigned, and what evidence is
required.

```bash
pytest -q                       # 168 tests, no network required
python database.py              # validate the dataset
```

CI runs the suite on Python 3.11–3.13 against both SQLite and PostgreSQL.

## Data sources

| Source                        | What it covers                                     |
| ----------------------------- | -------------------------------------------------- |
| `data/detections/*.json`      | Known malware, backdoors, hijacks, typosquats, dependency confusion |
| [OSV.dev](https://osv.dev)    | Live upstream advisories and minimum fixed versions |
| [npm Registry](https://registry.npmjs.org) | Publish age, maintainer count, publish velocity |

## API

| Method   | Endpoint                        | Auth | Purpose                        |
| -------- | ------------------------------- | ---- | ------------------------------ |
| `POST`   | `/api/scan`                     | —    | Scan a `package.json`          |
| `GET`    | `/api/stats`                    | —    | Dataset totals                 |
| `GET`    | `/api/community`                | —    | Contribution statistics        |
| `GET`    | `/api/tools`                    | —    | Live tool directory            |
| `POST`   | `/api/report`                   | —    | Report a package / false positive |
| `POST`   | `/api/tool-submissions`         | —    | Submit a paid listing          |
| `GET`    | `/api/reports`                  | ✅    | Review queue                   |
| `GET`    | `/api/admin/submissions`        | ✅    | Listing queue                  |
| `POST`   | `/api/tools`                    | ✅    | Add a curated tool             |
| `DELETE` | `/api/tools/<id>`               | ✅    | Remove a curated tool          |

✅ = HTTP Basic auth. All mutating endpoints require a CSRF token.

## Security

Please don't file security bugs as public issues — see
[SECURITY.md](SECURITY.md), which also documents how each untrusted input
surface is handled.

## Licence

MIT © [Aftersnow](https://aftersnow.xyz) · [Contributing](CONTRIBUTING.md) ·
[Code of conduct](CODE_OF_CONDUCT.md)
