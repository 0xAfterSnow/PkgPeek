#!/usr/bin/env python3
"""
Fetch official brand SVGs for the curated tools directory.

Sources, in order of preference:

1. **Simple Icons** (https://simpleicons.org) -- a CC0 1.0 (public domain)
   collection of brand marks maintained as vector paths. This is the cleanest
   licensing story available, so it is the default.
2. A hand-placed file in ``static/logos/`` for brands with no Simple Icons entry.

Only marks that exist as published vectors are fetched. Where a vendor publishes
nothing but a rasterised wordmark (OSV) or has no mark at all (Retire.js), nothing
is invented -- ``tools/generate_logos.py`` produces a typographic monogram
instead, and that is recorded in ATTRIBUTIONS.md.

    python tools/fetch_brand_logos.py            # report
    python tools/fetch_brand_logos.py --write    # download into static/logos/

Trademarks remain the property of their owners. See ATTRIBUTIONS.md.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import logos  # noqa: E402

LOGO_DIR = logos.CURATED_DIR
TOOLS_JSON = os.path.join(ROOT, "data", "detections", "tools.json")
ATTRIBUTIONS = os.path.join(ROOT, "ATTRIBUTIONS.md")

SIMPLEICONS = "https://cdn.simpleicons.org/{slug}/{colour}"
INK = "111110"
TIMEOUT = 20

# tool slug in tools.json -> Simple Icons brand slug.
# A tool left out here has no published vector mark and keeps its monogram.
BRANDS = {
    "npm-audit": "npm",
    "npm-audit-1": "npm",      # same brand, two entries in the directory
    "owasp-checker": "owasp",
    "dependabot": "dependabot",
    "socket-security": "socket",
    "snyk-security": "snyk",
    "snyk-cli": "snyk",
}
# Entries with no Simple Icons mark available as of writing:
#   osv-database    -- OSV publishes only a 53x20 rasterised wordmark
#   retire-js       -- no official mark is published
NO_VECTOR = {
    "osv-database": "OSV publishes only a rasterised wordmark; no vector mark exists",
    "retire-js": "Retire.js publishes no official mark",
}


def slugify(name):
    import re

    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "pkgpeek-logo-fetch"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read()


def looks_like_svg(data: bytes) -> bool:
    head = data[:400].lstrip()
    return head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in data[:400])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument(
        "--force",
        action="store_true",
        help="repoint entries even if they already reference a curated SVG "
        "(use after the filename scheme changes)",
    )
    args = parser.parse_args()

    with open(TOOLS_JSON, encoding="utf-8") as fh:
        tools = json.load(fh)["tools"]

    os.makedirs(LOGO_DIR, exist_ok=True)
    fetched, skipped, failed = [], [], []

    for tool in tools:
        name = tool.get("name", "")
        slug = slugify(name)
        brand = BRANDS.get(slug)

        if not brand:
            skipped.append((name, NO_VECTOR.get(slug, "not in BRANDS; keeping existing")))
            continue

        url = SIMPLEICONS.format(slug=brand, colour=INK)
        try:
            data = fetch(url)
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            failed.append((name, brand, str(exc)))
            continue

        if not looks_like_svg(data):
            failed.append((name, brand, "response was not an SVG"))
            continue

        target_name = logos.hashed_filename(slug, "svg", data)
        if args.write:
            with open(os.path.join(LOGO_DIR, target_name), "wb") as fh:
                fh.write(data)
        fetched.append((name, brand, target_name, url, len(data)))

    for name, brand, entry, url, size in fetched:
        print(f"  {name:20} <- simple-icons/{brand}  ({size} bytes) -> {entry}")
    for name, why in skipped:
        print(f"  {name:20} kept existing: {why}")
    for name, brand, err in failed:
        print(f"  {name:20} FAILED simple-icons/{brand}: {err}")

    if failed:
        print("\nSome brands could not be fetched. Not writing.")
        return 1

    if args.write:
        # Point each tool with a known brand at its freshly hashed mark. A curated
        # SVG that is already referenced is a deliberate hand-placed choice, so
        # only a generated monogram PNG gets superseded.
        hashed = {slugify(_n): entry for _n, _b, entry, _u, _s in fetched}
        for tool in tools:
            slug = slugify(tool.get("name", ""))
            entry = hashed.get(slug)
            if not entry:
                continue
            current = tool.get("logo") or ""
            if (
                not args.force
                and current.endswith(".svg")
                and current.startswith("/logos/curated/")
            ):
                continue
            tool["logo"] = f"/logos/curated/{entry}"
        with open(TOOLS_JSON, "w", encoding="utf-8") as fh:
            json.dump({"tools": tools}, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"\nWrote {len(fetched)} logo(s) and updated {TOOLS_JSON}")
        print("Now set logo_tile in tools.json for any white-on-transparent mark.")
    else:
        print(f"\n{len(fetched)} available, {len(skipped)} kept. Re-run with --write.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
