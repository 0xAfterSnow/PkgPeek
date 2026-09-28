#!/usr/bin/env python3
"""
Repair the `logo` paths in data/detections/tools.json against the files that
actually exist in static/logos/.

A curated logo is only useful if the path in the dataset matches a real file, and
a mismatch is invisible until the browser 404s. The dataset validator now fails
the boot with a message, and this script fixes the paths for you:

    python tools/fix_logo_paths.py          # report only
    python tools/fix_logo_paths.py --write  # apply

Matching order, per tool:
  1. the existing path, if that file is there
  2. <slug>.<ext> for any supported extension (png/jpg/jpeg/webp/svg)
  3. a unique fuzzy match on the slug (one file, one candidate)
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import logos  # noqa: E402

TOOLS_JSON = os.path.join(ROOT, "data", "detections", "tools.json")
LOGO_DIR = logos.CURATED_DIR


def slugify(name):
    import re

    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def available():
    """Map basename -> (slug, ext) for every servable file in the logo dir."""
    found = {}
    if not os.path.isdir(LOGO_DIR):
        return found
    for entry in sorted(os.listdir(LOGO_DIR)):
        stem, _, ext = entry.rpartition(".")
        ext = ext.lower()
        if not stem or ext not in logos.CURATED_EXTENSIONS:
            continue
        found[entry] = (stem, ext)
    return found


def best_for(slug, files, claimed):
    """Pick the best existing file for a tool slug, avoiding files already taken.

    The directory legitimately holds both an "npm Audit" extension and an
    "npm audit" CLI, which share a slug. Whichever comes second gets a numbered
    variant rather than sharing the first one's file.
    """
    for ext in logos.CURATED_EXTENSIONS:
        name = f"{slug}.{ext}"
        if name in files and name not in claimed:
            return name
    candidates = [
        name for name, (stem, _e) in files.items()
        if stem.startswith(slug) and name not in claimed
    ]
    if len(candidates) == 1:
        return candidates[0]
    # Every candidate is taken, or nothing matched: mint a numbered variant if
    # one happens to exist on disk.
    for n in range(1, 6):
        for ext in logos.CURATED_EXTENSIONS:
            name = f"{slug}-{n}.{ext}"
            if name in files:
                return name
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="apply the fixes")
    args = parser.parse_args()

    with open(TOOLS_JSON, encoding="utf-8") as fh:
        doc = json.load(fh)
    tools = doc["tools"]
    files = available()

    if not files:
        print(f"No logo files found in {LOGO_DIR}")
        print("Run `python tools/generate_logos.py` to create monograms first.")
        return 1

    changes, ok, missing = [], 0, []
    claimed = set()
    for tool in tools:
        name = tool.get("name", "<unnamed>")
        current = tool.get("logo") or ""
        if current and logos.resolve(current):
            ok += 1
            claimed.add(current.rsplit("/", 1)[-1])
            continue
        slug = slugify(name)
        match = best_for(slug, files, claimed)
        if match:
            claimed.add(match)
            new_path = f"/logos/curated/{match}"
            changes.append((name, current or "(none)", new_path))
            tool["logo"] = new_path
        else:
            missing.append(name)

    for name, old, new in changes:
        print(f"  {name}: {old}  ->  {new}")
    for name in missing:
        print(f"  {name}: no matching file in {LOGO_DIR} (left as-is)")

    print(f"\n{ok} already correct, {len(changes)} to fix, {len(missing)} unmatched")

    if args.write and changes:
        with open(TOOLS_JSON, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"Wrote {TOOLS_JSON}")
    elif changes:
        print("Re-run with --write to apply.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
