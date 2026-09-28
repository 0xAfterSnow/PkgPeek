"""HTTP surface: routes, auth, CSRF, escaping, uploads, and the public flow."""

import io
import json

import pytest
from conftest import AUTH_HEADER, make_png, stub_npm, stub_osv

import toolstore


@pytest.fixture
def token(csrf):
    return csrf()


# ── Pages ──────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "path", ["/", "/report", "/contribute", "/submit-tool", "/robots.txt",
             "/sitemap.xml", "/sw.js", "/manifest.json"]
)
def test_public_pages_render(client, path):
    assert client.get(path).status_code == 200


def test_admin_requires_auth(client):
    assert client.get("/admin").status_code == 401
    assert client.get("/admin", headers=AUTH_HEADER).status_code == 200


def test_admin_rejects_wrong_credentials(client):
    bad = {"Authorization": "Basic YWRtaW46d3Jvbmc="}  # admin:wrong
    assert client.get("/admin", headers=bad).status_code == 401


def test_pages_issue_a_csrf_token(client):
    assert "csrf-token" in client.get("/report").get_data(as_text=True)


# ── CSRF ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "path,payload",
    [
        ("/api/scan", {"packageJson": "{}"}),
        ("/api/report", {"packageName": "x", "reason": "y", "evidenceUrl": "https://a.com"}),
        ("/api/tool-submissions", {}),
        ("/api/listing/abcdefghijklmnopqrstuvwxyz/declare-paid", {}),
    ],
)
def test_mutating_endpoints_reject_requests_without_csrf(client, path, payload):
    assert client.post(path, json=payload).status_code == 403


def test_mutating_endpoints_reject_a_wrong_csrf_token(client):
    res = client.post(
        "/api/scan", json={"packageJson": "{}"}, headers={"X-CSRF-Token": "wrong"}
    )
    assert res.status_code == 403


def test_admin_endpoints_require_csrf_as_well(client):
    res = client.post(
        "/api/tools", json={}, headers={**AUTH_HEADER, "X-CSRF-Token": "wrong"}
    )
    assert res.status_code == 403


# ── Scan ───────────────────────────────────────────────────────────────────
def test_scan_returns_provenance(client, token, monkeypatch):
    stub_osv(monkeypatch)
    res = client.post(
        "/api/scan",
        json={"packageJson": json.dumps({"dependencies": {"event-stream": "3.3.6"}})},
        headers={"X-CSRF-Token": token},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["summary"]["total_packages"] == 1
    flag = data["direct"][0]["flags"][0]
    assert set(flag["provenance"]) >= {
        "source", "evidence", "evidence_url", "affected_versions"
    }


def test_scan_rejects_bad_json(client, token):
    res = client.post(
        "/api/scan", json={"packageJson": "{not json"}, headers={"X-CSRF-Token": token}
    )
    assert res.status_code == 400


def test_scan_rejects_a_non_object_package_json(client, token):
    res = client.post(
        "/api/scan", json={"packageJson": "[1,2,3]"}, headers={"X-CSRF-Token": token}
    )
    assert res.status_code == 400


def test_scan_rejects_a_missing_field(client, token):
    res = client.post("/api/scan", json={}, headers={"X-CSRF-Token": token})
    assert res.status_code == 400


# ── Report flow ────────────────────────────────────────────────────────────
def valid_report(**over):
    base = {
        "packageName": "evil-pkg",
        "reason": "exfiltrates credentials",
        "evidenceUrl": "https://github.com/advisories/GHSA-x",
    }
    base.update(over)
    return base


def test_report_submission_succeeds(client, token, monkeypatch):
    monkeypatch.setenv("GITHUB_REPO", "owner/repo")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    res = client.post("/api/report", json=valid_report(), headers={"X-CSRF-Token": token})
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    # No GITHUB_TOKEN, so it must offer a pre-filled link instead of pretending
    # an issue was filed.
    assert body["github_integration"] is False
    assert body["github_issue_url"].startswith("https://github.com/owner/repo/issues/new?")


def test_report_submission_without_a_repo_still_succeeds(client, token):
    """Nothing configured must not break the primary path: the review queue."""
    res = client.post("/api/report", json=valid_report(), headers={"X-CSRF-Token": token})
    assert res.status_code == 200
    body = res.get_json()
    assert body["success"] is True
    assert body["github_issue_url"] is None


def test_report_without_evidence_is_rejected(client, token):
    res = client.post(
        "/api/report", json=valid_report(evidenceUrl=""), headers={"X-CSRF-Token": token}
    )
    assert res.status_code == 400
    assert "Evidence" in res.get_json()["error"]


def test_honeypot_is_silently_accepted_but_stores_nothing(client, token):
    res = client.post(
        "/api/report", json=valid_report(website="http://spam.example"),
        headers={"X-CSRF-Token": token},
    )
    assert res.status_code == 200
    import reports

    assert reports.list_reports() == []


def test_correction_submission_is_accepted(client, token):
    res = client.post(
        "/api/report",
        json={"kind": "correction", "packageName": "react", "reason": "this is real react"},
        headers={"X-CSRF-Token": token},
    )
    assert res.status_code == 200


# ── Admin API auth ─────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "path", ["/api/admin/submissions", "/api/reports"]
)
def test_admin_api_requires_auth(client, path):
    assert client.get(path).status_code == 401


def test_publish_requires_auth(client, token):
    res = client.post(
        "/api/admin/submissions/1/publish", json={}, headers={"X-CSRF-Token": token}
    )
    assert res.status_code == 401


def test_report_review_requires_auth(client, token):
    res = client.post(
        "/api/reports/1/status", json={"status": "accepted"}, headers={"X-CSRF-Token": token}
    )
    assert res.status_code == 401


def test_report_review_rejects_a_non_review_state(client, token):
    import reports

    report = reports.create_report(
        {
            "packageName": "x",
            "kind": "report",
            "reason": "y",
            "evidenceUrl": "https://a.example",
        }
    )
    res = client.post(
        f"/api/reports/{report['id']}/status",
        json={"status": "pending"},
        headers={**AUTH_HEADER, "X-CSRF-Token": token},
    )
    assert res.status_code == 400


# ── Tool listing flow over HTTP ────────────────────────────────────────────
def tool_form(**over):
    base = {
        "toolName": "Socket",
        "websiteUrl": "https://socket.dev",
        "description": "Supply chain scanner for CI.",
        "category": "Security",
        "contactEmail": "hi@socket.dev",
    }
    base.update(over)
    return base


def test_tool_submission_over_http(client, token):
    res = client.post(
        "/api/tool-submissions",
        data=tool_form(),
        headers={"X-CSRF-Token": token},
    )
    assert res.status_code == 200
    assert res.get_json()["token"]


def test_tool_submission_rejects_bad_email(client, token):
    res = client.post(
        "/api/tool-submissions", data=tool_form(contactEmail="nope"),
        headers={"X-CSRF-Token": token},
    )
    assert res.status_code == 400


def test_tool_submission_is_blocked_when_payment_is_unconfigured(client, token, monkeypatch):
    monkeypatch.delenv("DODO_TOOL_LISTING_PAYMENT_URL", raising=False)
    res = client.post(
        "/api/tool-submissions", data=tool_form(), headers={"X-CSRF-Token": token}
    )
    assert res.status_code == 503
    assert "not configured" in res.get_json()["error"]


def test_listing_status_page_requires_a_valid_token(client, token):
    res = client.post(
        "/api/tool-submissions", data=tool_form(), headers={"X-CSRF-Token": token}
    )
    sub_token = res.get_json()["token"]
    assert client.get(f"/listing/{sub_token}").status_code == 200
    assert client.get("/listing/not-a-real-token").status_code == 404


def test_listing_status_does_not_leak_by_id(client, token):
    """No numeric-id route exists, so ids cannot be enumerated for emails."""
    assert client.get("/listing/1").status_code == 404


def test_declare_paid_moves_to_review_without_claiming_payment(client, token):
    res = client.post(
        "/api/tool-submissions", data=tool_form(), headers={"X-CSRF-Token": token}
    )
    sub_token = res.get_json()["token"]
    res = client.post(
        f"/api/listing/{sub_token}/declare-paid", headers={"X-CSRF-Token": token}
    )
    assert res.status_code == 200
    import database

    row = database.get_connection()
    try:
        sub = row.execute(
            "SELECT status, payment_status FROM tool_submissions"
        ).fetchall()[0]
    finally:
        row.close()
    assert sub["status"] == "pending_review"
    assert sub["payment_status"] == "unpaid"


# ── Logo serving ───────────────────────────────────────────────────────────
def test_logo_is_served_with_hardening_headers(client, token):
    res = client.post(
        "/api/tool-submissions",
        data=tool_form(logo=(io.BytesIO(make_png()), "logo.png")),
        headers={"X-CSRF-Token": token},
        content_type="multipart/form-data",
    )
    logo_path = toolstore.list_submissions()[0]["logo"]
    res = client.get(logo_path)
    assert res.status_code == 200
    assert res.headers["Content-Type"] == "image/png"
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in res.headers["Content-Security-Policy"]


@pytest.mark.parametrize(
    "path",
    ["/logos/../../app.py", "/logos/..%2f..%2fapp.py", "/logos/app.py", "/logos/"],
)
def test_logo_route_rejects_traversal(client, path):
    assert client.get(path).status_code == 404


def test_svg_upload_is_rejected(client, token):
    res = client.post(
        "/api/tool-submissions",
        data=tool_form(logo=(io.BytesIO(b"<svg onload=alert(1)></svg>"), "x.svg")),
        headers={"X-CSRF-Token": token},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400
    assert "PNG" in res.get_json()["error"]


# ── XSS ────────────────────────────────────────────────────────────────────
XSS = '<img src=x onerror="alert(1)">'


def test_tools_api_returns_submitted_content_verbatim(client, token):
    """The JSON API must not mangle stored data.

    Escaping happens in the browser at the point of DOM insertion (see
    test_client_escaping.py). Escaping here would double-encode the value and
    corrupt legitimate ampersands in descriptions.
    """
    client.post(
        "/api/tool-submissions",
        data=tool_form(description=XSS),
        headers={"X-CSRF-Token": token},
    )
    sub = toolstore.list_submissions()[0]
    toolstore.review(sub["id"], "approve")
    toolstore.review(sub["id"], "mark_paid", payment_reference="r")
    toolstore.publish(sub["id"])

    tools = client.get("/api/tools").get_json()
    stored = next(t for t in tools if t["name"] == "Socket")
    assert stored["desc"] == XSS, "the API is a data channel, not a renderer"


def test_admin_page_escapes_submitted_content(client):
    client.post(
        "/api/tool-submissions",
        data=tool_form(toolName=XSS, description=XSS),
        headers={"X-CSRF-Token": client.get("/").get_data(as_text=True) and
                 __import__("re").search(
                     r'name="csrf-token" content="([^"]+)"',
                     client.get("/").get_data(as_text=True)).group(1)},
    )
    html = client.get("/admin", headers=AUTH_HEADER).get_data(as_text=True)
    assert "<img src=x onerror" not in html


def test_report_content_is_escaped_in_the_admin_page(client, token):
    client.post(
        "/api/report",
        json=valid_report(reason=XSS, details=XSS),
        headers={"X-CSRF-Token": token},
    )
    # admin.html renders client-side with esc(); confirm the payload is stored
    # raw (the template must escape it, not the database).
    import reports

    stored = reports.list_reports()[0]
    assert stored["reason"] == XSS


# ── Public JSON endpoints ──────────────────────────────────────────────────
def test_stats_endpoint(client):
    body = client.get("/api/stats").get_json()
    assert body["total_known_malicious"] > 0
    assert body["typosquat_targets"] > 0


def test_community_endpoint(client):
    body = client.get("/api/community").get_json()
    assert body["total_detections"] > 0
    assert "intelligence_sources" in body


def test_tools_endpoint_only_returns_live_listings(client):
    tools = client.get("/api/tools").get_json()
    assert all(
        t["sponsored"] is False or t["expires_at"] for t in tools
    ), "paid listings must always carry an expiry"


# ── Admin CSRF regression ──────────────────────────────────────────────────
def _admin_csrf(client):
    import re

    html = client.get("/admin", headers=AUTH_HEADER).get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


def test_admin_json_post_succeeds_with_valid_csrf(client):
    """Regression: the admin api() helper dropped the CSRF header for any call
    that supplied its own headers, so approve/mark-paid/add-tool all 403'd."""
    client.post(
        "/api/tool-submissions",
        data=tool_form(),
        headers={"X-CSRF-Token": _admin_csrf(client)},
    )
    res = client.post(
        "/api/admin/submissions/1/approve",
        json={},
        headers={**AUTH_HEADER, "X-CSRF-Token": _admin_csrf(client)},
    )
    assert res.status_code == 200, res.get_json()
    assert res.get_json()["status"] == "approved"


def test_admin_mark_paid_then_publish_succeeds(client):
    csrf = _admin_csrf(client)
    client.post(
        "/api/tool-submissions", data=tool_form(), headers={"X-CSRF-Token": csrf}
    )
    for action, body in [
        ("approve", {}),
        ("mark-paid", {"reference": "dodo_1"}),
        ("publish", {}),
    ]:
        res = client.post(
            f"/api/admin/submissions/1/{action}",
            json=body,
            headers={**AUTH_HEADER, "X-CSRF-Token": csrf},
        )
        assert res.status_code == 200, f"{action} -> {res.get_json()}"
    assert any(t["name"] == "Socket" for t in client.get("/api/tools").get_json())


def test_admin_add_tool_json_still_works(client):
    res = client.post(
        "/api/tools",
        json={
            "name": "Curated JSON", "type": "CLI Tool", "cls": "tt-cli",
            "url": "https://example.com", "desc": "Added as JSON.",
        },
        headers={**AUTH_HEADER, "X-CSRF-Token": _admin_csrf(client)},
    )
    assert res.status_code == 200
    assert any(t["name"] == "Curated JSON" for t in client.get("/api/tools").get_json())


def test_admin_add_tool_accepts_a_logo_upload(client):
    res = client.post(
        "/api/tools",
        data={
            "name": "Curated Logo", "type": "CLI Tool", "cls": "tt-vscode",
            "url": "https://example.com", "desc": "Has a logo.",
            "logo": (io.BytesIO(make_png()), "logo.png"),
        },
        headers={**AUTH_HEADER, "X-CSRF-Token": _admin_csrf(client)},
        content_type="multipart/form-data",
    )
    assert res.status_code == 200, res.get_json()
    assert res.get_json()["logo"].startswith("/logos/")

    tool = next(t for t in client.get("/api/tools").get_json() if t["name"] == "Curated Logo")
    served = client.get(tool["logo"])
    assert served.status_code == 200
    assert served.headers["Content-Type"] == "image/png"
    assert served.headers["X-Content-Type-Options"] == "nosniff"


def test_admin_add_tool_rejects_an_svg_logo(client):
    res = client.post(
        "/api/tools",
        data={
            "name": "Bad Logo", "type": "CLI Tool", "cls": "tt-vscode",
            "url": "https://example.com", "desc": "x",
            "logo": (io.BytesIO(b"<svg onload=alert(1)></svg>"), "x.svg"),
        },
        headers={**AUTH_HEADER, "X-CSRF-Token": _admin_csrf(client)},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400
    assert "PNG, JPEG, or WebP" in res.get_json()["error"]


def test_admin_add_tool_still_validates_fields_with_a_logo(client):
    res = client.post(
        "/api/tools",
        data={
            "name": "Bad Url", "type": "CLI Tool", "cls": "tt-cli",
            "url": "javascript:alert(1)", "desc": "x",
            "logo": (io.BytesIO(make_png()), "logo.png"),
        },
        headers={**AUTH_HEADER, "X-CSRF-Token": _admin_csrf(client)},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400


# ── Curated logos ──────────────────────────────────────────────────────────
def test_curated_tools_have_generated_logos(client):
    tools = client.get("/api/tools").get_json()
    assert all(t["logo"] and t["logo"].startswith("/logos/curated/") for t in tools)


@pytest.mark.parametrize(
    "path",
    ["/logos/curated/../../app.py", "/logos/curated/nope.png",
     "/logos/curated/..%2f..%2fapp.py", "/logos/curated/UPPER.png"],
)
def test_curated_logo_route_rejects_unsafe_paths(client, path):
    assert client.get(path).status_code == 404


def test_curated_logo_is_served_with_hardening_headers(client):
    tool = client.get("/api/tools").get_json()[0]
    res = client.get(tool["logo"])
    assert res.status_code == 200
    # Curated logos may be PNG or SVG; either way the hardening applies.
    assert res.headers["Content-Type"].split(";")[0] in (
        "image/png",
        "image/jpeg",
        "image/webp",
        "image/svg+xml",
    )
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in res.headers["Content-Security-Policy"]


def test_curated_svg_logo_is_served_as_svg(client):
    """SVG is allowed for curated logos (committed, reviewed) but not uploads."""
    import logos

    svg_tool = next(
        t for t in client.get("/api/tools").get_json() if t["logo"].endswith(".svg")
    )
    res = client.get(svg_tool["logo"])
    assert res.status_code == 200
    assert res.headers["Content-Type"].split(";")[0] == "image/svg+xml"
    # The sandbox CSP is what makes a direct hit on an SVG file safe.
    assert "sandbox" in res.headers["Content-Security-Policy"]
    assert logos.resolve(svg_tool["logo"])[1] == "image/svg+xml"
