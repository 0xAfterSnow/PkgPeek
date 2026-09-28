"""The admin panel's fetch wrapper must never drop the CSRF header.

This is a regression guard for a real bug: the helper spread its options after
`headers`, so any call that supplied its own headers object replaced the merged
one and silently dropped ``X-CSRF-Token``. Approve, mark-paid, reject, review
and add-tool all pass ``Content-Type``, so all of them 403'd with
"Invalid or missing CSRF token" while delete appeared to work.
"""

import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN_HTML = os.path.join(ROOT, "templates", "admin.html")

node = shutil.which("node") or shutil.which("nodejs")


def extract_api_helper():
    """Pull the CSRF constant and api() wrapper out of the admin template."""
    source = open(ADMIN_HTML, encoding="utf-8").read()

    token = re.search(r"const CSRF = .*?;", source, re.S)
    assert token, "CSRF constant not found in admin.html"

    start = re.search(r"^const api = ", source, re.M)
    assert start, "api() helper not found in admin.html"

    # Brace-match from the arrow function's *body*, not its parameter list --
    # `(url, opts = {})` contains braces that would end the match immediately.
    # body.end() is relative to the slice searched, so offset it back.
    body = re.search(r"=>\s*\{", source[start.start() :])
    assert body, "api() body not found"

    open_brace = start.start() + body.end() - 1
    depth, i = 0, open_brace
    while i < len(source):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return token.group(0) + "\n" + source[start.start() : i + 1]


def run_js(body: str):
    # The admin template reads its token from the DOM and has no Node equivalent.
    preamble = (
        "var document = { querySelector: () => ({ content: 'TOKEN_FROM_META' }) };\n"
    )
    out = subprocess.run(
        [node, "-e", preamble + extract_api_helper() + "\n" + body],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.skipif(not node, reason="node is not available")
def test_api_sends_csrf_when_caller_supplies_no_headers():
    """The delete-tool call: no custom headers, token must still be present."""
    result = run_js(
        """
        let captured;
        global.fetch = (url, opts) => { captured = opts; return Promise.resolve(); };
        api('/api/tools/1', { method: 'DELETE' });
        console.log(JSON.stringify(captured.headers));
        """
    )
    assert "X-CSRF-Token" in result
    assert result["X-CSRF-Token"] == "TOKEN_FROM_META"


@pytest.mark.skipif(not node, reason="node is not available")
def test_api_sends_csrf_when_caller_supplies_json_headers():
    """The approve / mark-paid / reject / add-tool call: this is the one that broke."""
    result = run_js(
        """
        let captured;
        global.fetch = (url, opts) => { captured = opts; return Promise.resolve(); };
        api('/api/admin/submissions/1/approve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({})
        });
        console.log(JSON.stringify(captured.headers));
        """
    )
    assert "X-CSRF-Token" in result, "CSRF header was dropped by the api() wrapper"
    assert result["Content-Type"] == "application/json", "caller headers must survive"


@pytest.mark.skipif(not node, reason="node is not available")
def test_api_forwards_method_and_body():
    """Spreading opts must not swallow method/body either."""
    result = run_js(
        """
        let captured;
        global.fetch = (url, opts) => { captured = opts; return Promise.resolve(); };
        api('/api/tools', { method: 'POST', body: 'FormDataHere' });
        console.log(JSON.stringify({ method: captured.method, body: captured.body }));
        """
    )
    assert result["method"] == "POST"
    assert result["body"] == "FormDataHere"


def test_admin_template_does_not_reintroduce_the_bad_spread_order():
    """Static guard: `...opts` must not come after `headers` in the wrapper."""
    source = open(ADMIN_HTML, encoding="utf-8").read()
    start = re.search(r"^const api = ", source, re.M)
    assert start, "api() helper not found"
    block = source[start.start() : start.start() + 400]
    headers_at = block.find("headers")
    spread_at = block.find("...opts")
    if spread_at != -1 and headers_at != -1:
        assert headers_at < spread_at, (
            "if api() is reintroduced with `...opts`, it must be spread before "
            "the merged headers, or the CSRF token is dropped"
        )


def test_admin_passes_json_headers_on_a_post():
    """reviewSubmission and friends must still send Content-Type."""
    source = open(ADMIN_HTML, encoding="utf-8").read()
    assert "headers: { 'Content-Type': 'application/json' }" in source


def test_admin_add_tool_form_has_a_logo_field():
    source = open(ADMIN_HTML, encoding="utf-8").read()
    assert 'id="t-logo"' in source
    assert 'name="logo"' in source
    assert "image/png" in source
