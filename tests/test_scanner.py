"""Scanner behaviour, including a regression test for the `targets` NameError."""

import pytest
from conftest import stub_npm, stub_osv

from scanner import PackageScanner


@pytest.fixture
def scanner():
    return PackageScanner()


# ── The bug ────────────────────────────────────────────────────────────────
def test_not_found_package_suggests_a_correction(scanner):
    """Regression: this raised NameError because the loop read `targets`
    instead of `tgts`, so every not_found result 500'd the request."""
    flags = [
        {
            "type": "not_found",
            "severity": "medium",
            "title": "Package not found on npm",
            "description": "does not exist",
            "cve": None,
            "reference": None,
            "provenance": {"source": "npm Registry"},
        }
    ]
    suggestion = scanner._get_suggestion("lodahs", "4.17.15", flags)
    assert suggestion is not None
    assert suggestion["name"] == "lodash"
    assert suggestion["install"] == "npm install lodash"


def test_not_found_flag_does_not_crash_a_full_scan(scanner, monkeypatch):
    """The same path, driven end to end through the public entry point."""
    stub_npm(monkeypatch, status=404)
    stub_osv(monkeypatch)
    result = scanner.scan({"dependencies": {"lodahs": "1.0.0"}})
    flagged = result["direct"][0]
    assert flagged["safe"] is False
    assert flagged["suggestion"]["name"] == "lodash"


def test_best_match_never_returns_the_same_name(scanner):
    # 'lodash' is a target; asking for it must not suggest it.
    assert scanner._best_match("lodash")[0] is None


# ── Local dataset detections ───────────────────────────────────────────────
def test_known_malicious_package_is_flagged_with_provenance(scanner):
    result = scanner.scan({"dependencies": {"event-stream": "3.3.6"}})
    pkg = result["direct"][0]
    assert pkg["safe"] is False
    assert pkg["max_severity"] == "critical"

    flag = next(f for f in pkg["flags"] if f["type"] == "backdoor")
    prov = flag["provenance"]
    assert prov["source"] == "PkgPeek community database"
    assert prov["source_id"] == "pkgpeek-dataset"
    assert prov["affected_versions"] == "3.3.6"
    assert prov["evidence"]
    assert prov["evidence_url"].startswith("https://")


def test_all_version_detection_reports_all_versions(scanner):
    result = scanner.scan({"dependencies": {"ansi-html": "9.9.9"}})
    flag = result["direct"][0]["flags"][0]
    assert flag["provenance"]["affected_versions"] == "All versions"


def test_safe_package_has_no_flags(scanner):
    result = scanner.scan({"dependencies": {"express": "4.18.2"}})
    assert result["direct"][0]["safe"] is True
    assert result["direct"][0]["suggestion"] is None


# ── Typosquats ─────────────────────────────────────────────────────────────
def test_typosquat_is_flagged_and_resolved(scanner):
    result = scanner.scan({"dependencies": {"mongose": "1.0.0"}})
    flags = result["direct"][0]["flags"]
    # mongose is in the dataset as a known typosquat, and the similarity engine
    # independently flags it too. Both paths must agree on the real package.
    engine_flag = next(f for f in flags if f["source_id"] == "typosquat-engine")
    assert engine_flag["provenance"]["match"]["target"] == "mongoose"
    assert result["direct"][0]["suggestion"]["name"] == "mongoose"
    assert result["direct"][0]["suggestion"]["install"] == (
        "npm uninstall mongose && npm install mongoose"
    )


def test_legitimate_package_is_not_flagged_as_typosquat(scanner):
    result = scanner.scan({"dependencies": {"mongoose": "7.0.0"}})
    assert not any(
        f["type"] == "typosquat" for f in result["direct"][0]["flags"]
    )


# ── OSV ────────────────────────────────────────────────────────────────────
def test_osv_flag_carries_advisory_and_fixed_version(scanner, monkeypatch):
    stub_npm(monkeypatch, latest="4.20.0")
    stub_osv(
        monkeypatch,
        [
            {
                "id": "GHSA-test-0001",
                "aliases": ["CVE-2026-0001"],
                "summary": "Prototype pollution",
                "published": "2026-01-02T00:00:00Z",
                "modified": "2026-02-03T00:00:00Z",
                "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [
                    {
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "4.20.0"},
                                ],
                            }
                        ]
                    }
                ],
            }
        ],
    )
    result = scanner.scan({"dependencies": {"express": "4.18.2"}})
    flag = next(f for f in result["direct"][0]["flags"] if f["source_id"] == "osv")
    assert flag["cve"] == "CVE-2026-0001"
    assert flag["fixed_version"] == "4.20.0"
    assert flag["provenance"]["advisory"] == "GHSA-test-0001"
    assert flag["provenance"]["affected_versions"] == "0 - 4.20.0"
    assert flag["provenance"]["detected"] == "2026-01-02"
    # suggestion uses the exact minimum patched version
    assert result["direct"][0]["suggestion"]["version"] == "4.20.0"


@pytest.mark.parametrize(
    "score,expected",
    [
        ("9.8", "critical"),
        ("7.5", "high"),
        ("5.0", "medium"),
        ("2.0", "low"),
    ],
)
def test_osv_severity_thresholds(scanner, score, expected):
    assert scanner._osv_severity({"severity": [{"score": score}]}) == expected


def test_osv_failure_is_not_fatal(scanner, monkeypatch):
    """A flaky OSV must degrade, not raise."""

    def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr("requests.post", boom)
    result = scanner.scan({"dependencies": {"lodash": "4.17.15"}})
    assert result["direct"][0]["safe"] is False  # still caught by the local dataset


# ── npm metadata ───────────────────────────────────────────────────────────
def test_new_package_is_flagged(scanner, monkeypatch):
    from datetime import datetime, timedelta, timezone

    created = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    stub_npm(
        monkeypatch,
        payload={"time": {"created": created}, "maintainers": [{"name": "a"}, {"name": "b"}]},
    )
    stub_osv(monkeypatch)
    result = scanner.scan({"dependencies": {"brand-new-thing": "1.0.0"}})
    types = [f["type"] for f in result["direct"][0]["flags"]]
    assert "new_package" in types


def test_single_maintainer_is_flagged(scanner, monkeypatch):
    from datetime import datetime, timedelta, timezone

    created = (datetime.now(timezone.utc) - timedelta(days=900)).isoformat()
    stub_npm(
        monkeypatch,
        payload={"time": {"created": created}, "maintainers": [{"name": "solo"}]},
    )
    stub_osv(monkeypatch)
    result = scanner.scan({"dependencies": {"lonely-pkg": "1.0.0"}})
    types = [f["type"] for f in result["direct"][0]["flags"]]
    assert "single_maintainer" in types


# ── Summary / scoring ──────────────────────────────────────────────────────
def test_risk_score_weights_and_caps():
    s = PackageScanner()
    assert s._risk_score({"critical": 0, "high": 0, "medium": 0, "low": 0}) == 0
    assert s._risk_score({"critical": 1, "high": 0, "medium": 0, "low": 0}) == 40
    assert s._risk_score({"critical": 0, "high": 2, "medium": 0, "low": 0}) == 40
    assert s._risk_score({"critical": 9, "high": 9, "medium": 9, "low": 9}) == 100


def test_summary_counts(scanner):
    result = scanner.scan(
        {"dependencies": {"event-stream": "3.3.6", "express": "4.18.2"}}
    )
    summary = result["summary"]
    assert summary["total_packages"] == 2
    assert summary["flagged"] == 1
    assert summary["safe"] == 1


def test_direct_and_indirect_are_separated(scanner):
    result = scanner.scan(
        {
            "dependencies": {"express": "4.18.2"},
            "devDependencies": {"event-stream": "3.3.6"},
            "peerDependencies": {"ansi-html": "1.0.0"},
        }
    )
    assert [p["name"] for p in result["direct"]] == ["express", "event-stream"]
    assert [p["name"] for p in result["indirect"]] == ["ansi-html"]
    assert all(p["is_direct"] for p in result["direct"])
    assert not any(p["is_direct"] for p in result["indirect"])


def test_malformed_dependency_values_do_not_crash(scanner):
    """A lockfile with a null version should not blow up the scan."""
    result = scanner.scan({"dependencies": {"weird": None, "ok": "1.0.0"}})
    assert [p["name"] for p in result["direct"]] == ["ok"]


def test_version_specifiers_are_cleaned(scanner):
    assert scanner._clean_version("^4.17.15") == "4.17.15"
    assert scanner._clean_version("~1.2.3") == "1.2.3"
    assert scanner._clean_version(">=2.0.0 <3.0.0") == "2.0.0"
    assert scanner._clean_version("") == ""
