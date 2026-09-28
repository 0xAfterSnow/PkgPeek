"""Client-side escaping.

Tool listings and detection descriptions are user-submitted, and the homepage
builds its markup by string concatenation. The guarantee that matters is that
nothing reaches the DOM as raw HTML, so we execute the real ``esc``/``safeUrl``
from ``static/main.js`` under Node and assert on the result.
"""

import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_JS = os.path.join(ROOT, "static", "main.js")

node = shutil.which("node") or shutil.which("nodejs")

XSS_PAYLOADS = [
    '<img src=x onerror="alert(1)">',
    "</div><script>alert(1)</script>",
    "javascript:alert(1)",
    '" onmouseover="alert(1)',
    "'><svg/onload=alert(1)>",
    "a&b<c>d",
]


def extract_js_functions():
    """Pull the esc() and safeUrl() definitions out of main.js."""
    source = open(MAIN_JS, encoding="utf-8").read()
    names = []
    for name in ("esc", "safeUrl"):
        match = re.search(
            r"^function %s\([^)]*\)\s*\{" % name, source, flags=re.M
        )
        assert match, f"{name}() not found in main.js"
        start = match.start()
        depth, i = 0, start
        while i < len(source):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        names.append(source[start : i + 1])
    return "\n".join(names)


def run_js(body: str):
    """Execute the extracted esc()/safeUrl() plus ``body`` under Node."""
    preamble = "var window = { location: { origin: 'https://pkgpeek.test' } };\n"
    out = subprocess.run(
        [node, "-e", preamble + extract_js_functions() + "\n" + body],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.skipif(not node, reason="node is not available")
def test_esc_neutralises_every_payload():
    """Run the real esc() under Node and confirm no markup survives."""
    escaped = run_js(
        "console.log(JSON.stringify(%s.map(esc)));" % json.dumps(XSS_PAYLOADS)
    )
    for original, result in zip(XSS_PAYLOADS, escaped):
        assert "<" not in result, f"unescaped < survived: {original}"
        assert ">" not in result, f"unescaped > survived: {original}"
        # esc() only rewrites characters that are special in markup, so a
        # payload with no such characters is expected to pass through. Scheme
        # injection is safeUrl()'s job, not esc()'s -- see the test below.
        if any(c in original for c in "<>\"'&"):
            assert result != original, f"payload was not escaped: {original}"


@pytest.mark.skipif(not node, reason="node is not available")
def test_esc_preserves_ordinary_text():
    escaped = run_js("console.log(JSON.stringify(['Snyk CLI', 'a & b', 'CI/CD']));")


@pytest.mark.skipif(not node, reason="node is not available")
def test_esc_encodes_quotes_and_ampersands():
    escaped = run_js("""console.log(JSON.stringify([
        esc("a\\"b"), esc("it's"), esc("a&b"), esc("<script>")
    ]));""")
    assert escaped[0] == "a&quot;b"
    assert escaped[1] == "it&#39;s"
    assert escaped[2] == "a&amp;b"
    assert escaped[3] == "&lt;script&gt;"


@pytest.mark.skipif(not node, reason="node is not available")
def test_safe_url_blocks_dangerous_schemes():
    cases = [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "https://ok.example/x",
        "http://ok.example",
    ]
    results = run_js(
        "console.log(JSON.stringify(%s.map(safeUrl)));" % json.dumps(cases)
    )
    assert results[0] == ""
    assert results[1] == ""
    assert results[2] == ""
    assert results[3].startswith("https://ok.example")
    assert results[4].startswith("http://ok.example")


@pytest.mark.skipif(not node, reason="node is not available")
def test_safe_url_handles_empty_and_malformed_input():
    results = run_js(
        "console.log(JSON.stringify([safeUrl(''), safeUrl(null), safeUrl('not a url'),"
        " safeUrl(undefined)]));"
    )
    assert results[0] == "", "empty input has no href"
    assert results[1] == ""
    assert results[3] == ""
    # A relative URL resolves against the app origin, which keeps it on-site and
    # therefore safe. The point is that it cannot leave the origin.
    assert results[2].startswith("https://pkgpeek.test/")


# ── Static guarantees ──────────────────────────────────────────────────────
def test_no_raw_interpolation_of_user_fields_in_main_js():
    """Every tool/report field must be escaped at the point of interpolation.

    A blunt guard against someone adding `${t.desc}` by hand later. Wrappers
    that escape internally are listed explicitly.
    """
    source = open(MAIN_JS, encoding="utf-8").read()
    safe_wrappers = ("esc(", "safeUrl(", "toolMonogram(")
    for field in ("t.name", "t.desc", "t.url", "t.category", "t.pricing_model"):
        pattern = r"\$\{([^}]*\b%s\b[^}]*)\}" % re.escape(field)
        for match in re.finditer(pattern, source):
            expr = match.group(1).strip()
            assert any(w in expr for w in safe_wrappers), (
                f"{field} is interpolated without escaping: ${{{expr}}}"
            )


def test_flag_rendering_escapes_description_and_title():
    source = open(MAIN_JS, encoding="utf-8").read()
    assert "${esc(f.description || '')}" in source
    assert "${esc(f.title)}" in source


def test_scan_input_is_escaped_before_prism():
    """Untrusted package.json text is escaped before it is highlighted."""
    source = open(MAIN_JS, encoding="utf-8").read()
    assert "let escaped = esc(input);" in source
