# Contributing to PkgPeek

Thanks for helping keep the npm ecosystem safer. This project is a scanner plus
a **public detection dataset**, and contributions come in four flavours:

| I want to…                          | Do this                                        |
| ----------------------------------- | ---------------------------------------------- |
| Report a malicious package          | [/report](https://pkgpeek.example/report)       |
| Fix a wrong detection               | "This looks wrong" on a scan result, or an issue |
| Add a detection to the dataset      | Edit `data/detections/*.json` in a PR           |
| Improve the scanner                 | Open a PR against `scanner.py`                  |

---

## The one rule

**Nothing anyone submits becomes a detection automatically.**

Reports and corrections land in a review queue. A maintainer has to verify the
evidence and land a change in `data/detections/` in git. This is deliberate:
if submissions were trusted on arrival, the dataset would be one
`{"package": "react", "severity": "critical", "reason": "I don't like React"}`
away from poisoning everyone's dependency tree.

The database is a cache. `data/detections/*.json` is the source of truth.

---

## How detections are evaluated

A detection entry is only merged when a maintainer can answer "what is the
evidence for this?" The bar:

- **A public, linkable source.** A GitHub advisory, an incident write-up, a
  researcher blog post, a package deprecation notice.
- **A specific claim.** "This version range is vulnerable", not "this package
  is sketchy".
- **Version scope that is honest.** If it affects every version, say so with
  `"versions": []`. If it affects two versions, list both.

### Severity

Severity is assigned from **impact if installed and executed**, not from how
interesting the story is.

| Severity | Means                                                                            |
| -------- | -------------------------------------------------------------------------------- |
| critical | Code execution, credential theft, or data exfiltration on install.                  |
| high     | A known CVE with a working exploit path, or sabotage that breaks consumers badly.  |
| medium   | A real weakness with meaningful preconditions, or a strong abuse signal.            |
| low      | Informational. A signal worth surfacing, not worth blocking.                        |

When in doubt, err high and say why in the description. A false negative is
worse than a noisy flag, because the user has to notice a false positive and a
missing detection is invisible.

### Detection file format

`data/detections/` holds five files. Put each entry in the one that matches its
`reason`:

| File                   | For                                                    |
| ---------------------- | ----------------------------------------------------- |
| `malicious.json`       | `malware`, `backdoor`, `sabotage`                     |
| `vulnerabilities.json` | `vulnerability` (CVEs we record ahead of OSV)         |
| `typosquats.json`      | `targets` (legit names) and `detections` (bad copies)  |
| `suspicious.json`      | `dependency confusion` and similar abuse patterns     |
| `tools.json`           | the curated tools directory                           |

```jsonc
{
  "package": "some-package",
  "versions": ["1.2.3", "1.2.4"],  // [] means every version
  "reason": "malware",              // malware|backdoor|sabotage|typosquat|
                                    // vulnerability|dependency confusion
  "severity": "critical",           // critical|high|medium|low
  "description": "What it actually does, and how you know.",
  "cve": "CVE-2026-0001",           // or GHSA-xxxx, or null
  "source": "npm incident 2026",    // who documented it
  "source_url": "https://…",        // the link a reviewer will open
  "reported_at": "2026-09-21",      // when it was first observed (optional)
  "contributor": "@yourhandle"      // filled in by the maintainer on merge
}
```

### Validate before you push

```bash
python database.py
```

This loads every dataset file, checks each entry, applies migrations, and prints
the totals. It exits non-zero with a list of problems if anything is malformed.
CI runs it too, so a bad entry fails fast rather than at deploy time.

### Tool logos

`tools.json` entries take an optional `logo`. **The path must match a file in
`static/logos/`, or the app will not boot** — the dataset validator checks this
and names the offending tool.

```jsonc
{ "name": "Socket", "cls": "tt-cli", "type": "CI / CD", "desc": "…",
  "url": "https://socket.dev",
  "logo": "/logos/curated/socket.png" }
```

| Path                        | Source                              | Committed | Formats                        |
| --------------------------- | ----------------------------------- | --------- | ------------------------------ |
| `/logos/curated/<slug>.ext` | `static/logos/`                      | yes       | png, jpg, jpeg, webp, **svg**  |
| `/logos/<32 hex>.ext`       | advertiser upload, randomised name   | no        | png, jpg, jpeg, webp           |

Note the **`/curated/` segment** — a path without it is treated as an upload
path and will 404. SVG is allowed for curated logos only: uploads are untrusted
so they stay raster-only, whereas curated files live in git and can only land
through a reviewed pull request.

Filenames must be lowercase, matching `[a-z0-9._-]`.

#### Adding a logo

1. Drop the file in `static/logos/` (lowercase name).
2. Set `logo` in `data/detections/tools.json` to `/logos/curated/<filename>`,
   where `<filename>` is `<slug>-<8 hex of sha256>.<ext>`. The hash keeps the URL
   unique per revision so an `immutable` cache can never pin a stale mark —
   compute it with:

   ```bash
   python -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest()[:8])" static/logos/my-logo.svg
   ```
3. Set `logo_tile` to `light` for a dark mark, `dark` for white artwork on a
   transparent background. It is explicit in the data rather than guessed from
   the extension, because only the artwork knows which it is.
4. `python database.py` to confirm it resolves, then restart the app — the
   database is a cache and only re-syncs at startup.

Easier: let the scripts do it.

```bash
python tools/fetch_brand_logos.py --write    # official marks (Simple Icons, CC0)
python tools/generate_logos.py --write       # monograms for anything left
```

If you rename or replace a file and the dataset now points at nothing, repair the
paths against what is actually on disk:

```bash
python tools/fix_logo_paths.py           # report
python tools/fix_logo_paths.py --write   # apply
```

#### Generated monograms

`tools/generate_logos.py` fills in anything without a published vector mark,
as a **bare ink glyph** (no background, no tile) so it sits on the same white
card tile as the real brand marks. It skips any tool that already has an SVG.

Re-run it after adding or renaming a tool; it disambiguates slugs on its own
(there are legitimately both an "npm Audit" extension and an "npm audit" CLI).

Brand marks come from [Simple Icons](https://simpleicons.org), a CC0 collection.
See [ATTRIBUTIONS.md](ATTRIBUTIONS.md) for provenance of every file in the
directory. We do not invent, trace, or approximate a mark that a vendor has not
published as a vector.

To add a curated tool from the admin panel instead, use `/admin` → *Add curated
tool*, which accepts a logo upload (raster only, magic-byte checked). For a
durable change, still add it to `data/detections/tools.json` — the database is
a cache.

#### Where uploaded logos go

Advertiser submissions are not curated tools, so they are **not** committed. Set
`BYTESHIP_API_KEY` (a Byteship project key with `files:write`) and uploads go to
[Byteship](https://byteship.dev) and are served from its CDN:

```bash
BYTESHIP_API_KEY=bship_...
BYTESHIP_FOLDER=pkgpeek/logos
```

Without it they fall back to `static/uploads/logos/`, which is fine locally but
is wiped on redeploy on any host with an ephemeral filesystem. The admin panel
shows which provider is live. `safeUrl()` in `static/main.js` already accepts
CDN URLs and still rejects `javascript:`, so no frontend change is needed.

---

## False positives

A false positive is a bug, and the fix is a **regression test**, not a quiet
edit to the data.

1. Open a report with kind `correction` and say what is wrong.
2. Add a test that fails before the fix:

   ```python
   def test_legit_package_is_not_flagged(scanner):
       result = scanner.scan({"dependencies": {"express": "4.18.2"}})
       assert result["direct"][0]["safe"] is True
   ```

3. Fix the detector or the dataset entry.
4. Open the PR with both.

---

## Development setup

```bash
git clone https://github.com/0xaftersnow/pkgpeek.git
cd pkgpeek
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env          # then fill in SECRET_KEY
python database.py            # create + seed the database
python app.py                 # http://localhost:5000
```

The SQLite database is created and seeded from the dataset automatically. You
do not need to write a migration to add a detection.

### Tests

```bash
pytest -q                                  # everything
pytest tests/test_scanner.py -v            # one file
pytest -q --cov=. --cov-report=term-missing # with coverage
```

The suite is hermetic. It sets every environment variable it cares about, so a
`.env` containing `DATABASE_URL`, `GITHUB_TOKEN` or a Redis limiter URI cannot
leak in through the `load_dotenv()` call in `app.py`. No test makes a network
call — `tests/conftest.py` fails any test that reaches out and gives you
`stub_npm` / `stub_osv` to fake those responses — and uploads go to a temporary
directory rather than `static/uploads/`. Your local configuration cannot break
the tests. Node is optional; the client-escaping tests skip without it.

CI runs the suite on Python 3.11–3.13, against **both SQLite and PostgreSQL**,
because a detection that behaves differently per backend is a detection you
cannot trust.

---

## Adding a detection engine

The scanner is four methods on `PackageScanner` in `scanner.py`:

| Method                | Checks                                        |
| --------------------- | --------------------------------------------- |
| `_check_local_db`     | the detection dataset                          |
| `_check_osv`          | OSV.dev advisories                             |
| `_check_typosquat`    | name similarity against known targets          |
| `_check_npm_meta`     | age, maintainer count, publish velocity        |

A new check needs two things:

1. **A `provenance` block on every flag it returns.** Source, evidence, when it
   was detected, which versions are affected. A detection a user cannot audit is
   a detection they cannot act on.
2. **A test**, with the network stubbed.

Never let a check raise. Wrap it so that an API being down degrades to "no
result" rather than a 500 — a failed OSV lookup must not take out a scan.

---

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security issues

Do not open a public issue for an exploitable vulnerability in PkgPeek itself.
See [SECURITY.md](SECURITY.md).

## Licence

MIT. See [LICENSE](LICENSE).
