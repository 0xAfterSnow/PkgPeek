#!/usr/bin/env python3
"""
Generate monogram logos for curated tools that have no published vector mark.

The curated directory should not be a wall of grey letter-boxes, but we are not
going to scrape or redistribute third-party trademarked logos either. So each
tool without an official mark gets a generated monogram in the site's ink
colour, as a **bare glyph** -- no background, no tile -- so it sits on the same
white card tile as the real brand marks fetched by
``tools/fetch_brand_logos.py``.

    python tools/generate_logos.py

Output: static/logos/<slug>.png  (committed to the repo)
Requires: pillow

Trademarks remain the property of their owners. See ATTRIBUTIONS.md.
"""

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import logos  # noqa: E402
TOOLS_JSON = os.path.join(ROOT, "data", "detections", "tools.json")
OUT_DIR = os.path.join(ROOT, "static", "logos")

SIZE = 256
INK = (17, 17, 16)  # --ink, the site's near-black

def slugify(name):
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug


def find_font():
    """Locate a bold serif/sans face, preferring the site's own display serif.

    Falls back to scanning the system font directories rather than assuming a
    distribution layout, and errors out loudly instead of silently producing
    unreadable bitmap-default logos.
    """
    from PIL import ImageFont

    preferred = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSerif-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSerif-Bold.ttf",
        "/usr/share/fonts/dejavu-sans-fonts/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ]
    for path in preferred:
        if os.path.exists(path):
            return path

    for root in ("/usr/share/fonts", "/usr/local/share/fonts", os.path.expanduser("~/.fonts")):
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in sorted(files):
                low = name.lower()
                if low.endswith((".ttf", ".otf")) and "bold" in low and (
                    "serif" in low or "sans" in low
                ):
                    if "italic" in low or "oblique" in low or "condensed" in low:
                        continue
                    return os.path.join(dirpath, name)
    return None


def load_font(path):
    from PIL import ImageFont

    return ImageFont.truetype(path, int(SIZE * 0.54))




def render(name, cls, font):
    """A bare ink glyph on transparency -- the same treatment as a brand mark."""
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Monogram: the first alphanumeric character, uppercased.
    letter = next((c for c in name if c.isalnum()), "?").upper()
    box = draw.textbbox((0, 0), letter, font=font)
    draw.text(
        ((SIZE - (box[2] - box[0])) / 2 - box[0], (SIZE - (box[3] - box[1])) / 2 - box[1]),
        letter,
        font=font,
        fill=INK + (255,),
    )
    return img


def unique_slugs(tools):
    """Slugify each tool, disambiguating collisions.

    The directory legitimately contains both "npm Audit" (a VS Code extension)
    and "npm audit" (a CLI), which slugify identically.
    """
    seen = {}
    for tool in tools:
        base = slugify(tool["name"])
        slug = base
        if slug in seen:
            slug = f"{base}-{seen[slug]}"
        seen[base] = seen.get(base, 1) + 1
        seen[slug] = 1
        yield tool, slug


def _png_bytes(img):
    """Serialise once so the content hash matches the bytes we actually write."""
    import io

    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="write files and update tools.json")
    args = parser.parse_args()
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        sys.exit("pillow is required: pip install pillow")

    with open(TOOLS_JSON, encoding="utf-8") as fh:
        tools = json.load(fh)["tools"]

    os.makedirs(OUT_DIR, exist_ok=True)
    font_path = find_font()
    if not font_path:
        sys.exit('No bold font found. Install fonts-dejavu-core or a Noto/Liberation set.')
    font = load_font(font_path)
    print(f'Using font: {font_path}\n')

    for tool, slug in unique_slugs(tools):
        # Skip anything that already has a real brand mark, so regenerating never
        # clobbers a fetched logo.
        current = tool.get("logo") or ""
        if current.endswith(".svg"):
            print(f"{tool['name']:22} has a vector mark, skipping")
            continue
        img = render(tool["name"], tool.get("cls", "tt-service"), font)
        data = _png_bytes(img)
        name = logos.hashed_filename(slug, "png", data)
        if args.write:
            with open(os.path.join(OUT_DIR, name), "wb") as fh:
                fh.write(data)
        # Keep the dataset in step so the grid picks the logo up automatically.
        tool["logo"] = f"/logos/curated/{name}"
        print(f"{name}  <- {tool['name']} (monogram)")

    if args.write:
        with open(TOOLS_JSON, "w", encoding="utf-8") as fh:
            json.dump({"tools": tools}, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"\nUpdated logo paths in {TOOLS_JSON}")
    else:
        print("\nRe-run with --write to apply.")


if __name__ == "__main__":
    main()
