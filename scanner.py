"""
PkgPeek scan engine.

Four independent checks run against every dependency, and every flag they
produce carries a ``provenance`` block so the result is auditable: where the
intelligence came from, what the evidence is, and when it was recorded.
"""

import difflib
from datetime import datetime, timezone

import requests

import detections
from database import init_db

OSV_API = "https://api.osv.dev/v1/query"
NPM_API = "https://registry.npmjs.org"
TIMEOUT = 6

DATASET_URL = "https://github.com/0xaftersnow/pkgpeek/blob/main/data/detections"

# Stable identifiers for each intelligence source, so a report or correction can
# point back at exactly which detector fired.
SOURCE_PKGPEEK = "pkgpeek-dataset"
SOURCE_OSV = "osv"
SOURCE_TYPOSQUAT = "typosquat-engine"
SOURCE_NPM = "npm-registry"

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


class PackageScanner:
    def __init__(self):
        self._targets = None  # cached per scanner instance

    @property
    def targets(self):
        """Legitimate package names used for typosquat comparison.

        Cached because it is otherwise re-queried for every dependency.
        """
        if self._targets is None:
            self._targets = detections.target_names()
        return self._targets

    # ------------------------------------------------------------------ #
    #  Public entry point
    # ------------------------------------------------------------------ #
    def scan(self, pkg_json: dict) -> dict:
        direct = self._extract_deps(pkg_json, direct=True)
        indirect = self._extract_deps(pkg_json, direct=False)

        direct_results = [self._scan_package(name, ver, is_direct=True) for name, ver in direct.items()]
        indirect_results = [self._scan_package(name, ver, is_direct=False) for name, ver in indirect.items()]

        all_results = direct_results + indirect_results
        return {
            "summary": self._build_summary(all_results),
            "direct": direct_results,
            "indirect": indirect_results,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_stats(self) -> dict:
        return detections.stats()

    # ------------------------------------------------------------------ #
    #  Dependency extraction
    # ------------------------------------------------------------------ #
    def _extract_deps(self, pkg_json: dict, direct: bool) -> dict:
        deps = {}
        if direct:
            deps.update(pkg_json.get("dependencies") or {})
            deps.update(pkg_json.get("devDependencies") or {})
        else:
            deps.update(pkg_json.get("peerDependencies") or {})
            deps.update(pkg_json.get("optionalDependencies") or {})
        # Guard against non-string values, which would break _clean_version.
        return {k: v for k, v in deps.items() if isinstance(k, str) and isinstance(v, str)}

    # ------------------------------------------------------------------ #
    #  Per-package scan
    # ------------------------------------------------------------------ #
    def _scan_package(self, name: str, version_spec: str, is_direct: bool) -> dict:
        clean_ver = self._clean_version(version_spec)
        result = {
            "name": name,
            "version": version_spec,
            "is_direct": is_direct,
            "flags": [],
            "safe": True,
        }

        result["flags"].extend(self._check_local_db(name, clean_ver))
        result["flags"].extend(self._check_osv(name, clean_ver))
        result["flags"].extend(self._check_typosquat(name))
        result["flags"].extend(self._check_npm_meta(name, clean_ver))

        if result["flags"]:
            result["safe"] = False
            result["max_severity"] = self._max_severity(
                [f.get("severity", "low") for f in result["flags"]]
            )
            result["suggestion"] = self._get_suggestion(name, version_spec, result["flags"])
        else:
            result["max_severity"] = "safe"
            result["suggestion"] = None

        return result

    # ------------------------------------------------------------------ #
    #  Check 1: PkgPeek community detection dataset
    # ------------------------------------------------------------------ #
    def _check_local_db(self, name: str, version: str) -> list:
        flags = []
        for row in detections.find_detections(name, version):
            reason = row.get("reason") or "malware"
            affected = (
                "All versions"
                if row.get("affects_all_versions")
                else ", ".join(row.get("versions") or [])
            )
            # Prefer the publisher's own URL; fall back to the dataset file.
            evidence = row.get("source_url") or f"{DATASET_URL}/malicious.json"
            flags.append(
                {
                    "source": "PkgPeek community database",
                    "source_id": SOURCE_PKGPEEK,
                    "type": reason,
                    "severity": row["severity"],
                    "title": f"Known {reason.replace('_', ' ')} — {row['severity'].upper()}",
                    "description": row.get("description") or "",
                    "cve": row.get("cve"),
                    "reference": evidence,
                    "provenance": {
                        "source": "PkgPeek community database",
                        "source_id": SOURCE_PKGPEEK,
                        "evidence": row.get("source") or "PkgPeek detection dataset",
                        "evidence_url": evidence,
                        "detected": row.get("reported_at") or (row.get("created_at") or "")[:10] or None,
                        "affected_versions": affected,
                        "advisory": row.get("cve"),
                        "contributor": row.get("contributor"),
                    },
                }
            )
        return flags

    # ------------------------------------------------------------------ #
    #  Check 2: OSV (Google Open Source Vulnerability DB)
    # ------------------------------------------------------------------ #
    def _check_osv(self, name: str, version: str) -> list:
        try:
            payload = {"package": {"name": name, "ecosystem": "npm"}}
            if version:
                payload["version"] = version
            resp = requests.post(OSV_API, json=payload, timeout=TIMEOUT)
            if resp.status_code != 200:
                return []
            vulns = resp.json().get("vulns", [])
        except Exception:
            return []

        flags = []
        for v in vulns[:5]:  # cap at 5 per package
            aliases = v.get("aliases", [])
            cve = next((a for a in aliases if a.startswith("CVE-")), None)
            advisory_id = v.get("id", "Advisory")
            ref = f"https://osv.dev/vulnerability/{advisory_id}"
            fixed_version = self._osv_fixed_version(v)
            affected = self._osv_affected_range(v)
            flags.append(
                {
                    "source": "OSV.dev",
                    "source_id": SOURCE_OSV,
                    "type": "vulnerability",
                    "severity": self._osv_severity(v),
                    "title": advisory_id,
                    "description": (v.get("summary") or v.get("details") or "")[:200],
                    "cve": cve,
                    "reference": ref,
                    "fixed_version": fixed_version,
                    "provenance": {
                        "source": "OSV.dev",
                        "source_id": SOURCE_OSV,
                        "evidence": f"Upstream advisory {advisory_id}",
                        "evidence_url": ref,
                        "detected": (v.get("published") or "")[:10] or None,
                        "modified": (v.get("modified") or "")[:10] or None,
                        "affected_versions": affected or (version or "unknown"),
                        "advisory": advisory_id,
                        "aliases": aliases,
                        "fixed_version": fixed_version,
                        "attribution": (v.get("credits") or [{}])[0].get("name"),
                    },
                }
            )
        return flags

    # ------------------------------------------------------------------ #
    #  Check 3: Typosquatting
    # ------------------------------------------------------------------ #
    def _check_typosquat(self, name: str) -> list:
        lowered = name.lower()
        for legit in self.targets:
            if lowered == legit.lower():
                continue  # it IS the legit one
            ratio = difflib.SequenceMatcher(None, lowered, legit.lower()).ratio()
            if ratio > 0.82:
                npm_url = f"https://www.npmjs.com/package/{legit}"
                return [
                    {
                        "source": "PkgPeek typosquat engine",
                        "source_id": SOURCE_TYPOSQUAT,
                        "type": "typosquat",
                        "severity": "high",
                        "title": f"Possible typosquat of '{legit}'",
                        "description": (
                            f"'{name}' is suspiciously similar to the popular package "
                            f"'{legit}' ({ratio:.0%} similarity). Verify you spelled it "
                            "correctly and that the install script is what you expect."
                        ),
                        "cve": None,
                        "reference": npm_url,
                        "provenance": {
                            "source": "PkgPeek typosquat engine",
                            "source_id": SOURCE_TYPOSQUAT,
                            "evidence": f"Name similarity {ratio:.1%} against known target '{legit}'",
                            "evidence_url": npm_url,
                            "detected": None,
                            "affected_versions": "all",
                            "advisory": None,
                            "match": {"target": legit, "similarity": round(ratio, 3)},
                        },
                    }
                ]
        return []

    # ------------------------------------------------------------------ #
    #  Check 4: npm registry metadata
    # ------------------------------------------------------------------ #
    def _check_npm_meta(self, name: str, version: str) -> list:
        try:
            resp = requests.get(f"{NPM_API}/{name}", timeout=TIMEOUT)
        except Exception:
            return []

        npm_url = f"https://www.npmjs.com/package/{name}"

        if resp.status_code == 404:
            return [
                {
                    "source": "npm Registry",
                    "source_id": SOURCE_NPM,
                    "type": "not_found",
                    "severity": "medium",
                    "title": "Package not found on npm",
                    "description": (
                        f"'{name}' does not exist on the npm registry. This may be a "
                        "misspelling, or a dependency-confusion risk where the name "
                        "resolves to a private registry instead."
                    ),
                    "cve": None,
                    "reference": None,
                    "provenance": {
                        "source": "npm Registry",
                        "source_id": SOURCE_NPM,
                        "evidence": "HTTP 404 from registry.npmjs.org",
                        "evidence_url": npm_url,
                        "detected": None,
                        "affected_versions": version or "unknown",
                        "advisory": None,
                    },
                }
            ]
        if resp.status_code != 200:
            return []

        try:
            meta = resp.json()
        except Exception:
            return []

        flags = []
        time_data = meta.get("time") or {}
        created_str = time_data.get("created")

        def prov(evidence):
            return {
                "source": "npm Registry",
                "source_id": SOURCE_NPM,
                "evidence": evidence,
                "evidence_url": npm_url,
                "detected": (created_str or "")[:10] or None,
                "affected_versions": version or "all",
                "advisory": None,
            }

        if created_str:
            try:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - created).days
            except ValueError:
                age_days = None
            if age_days is not None and age_days < 30:
                flags.append(
                    {
                        "source": "npm Registry",
                        "source_id": SOURCE_NPM,
                        "type": "new_package",
                        "severity": "medium",
                        "title": f"Very new package ({age_days} days old)",
                        "description": (
                            f"Published {age_days} days ago. Recently published packages "
                            "have had less community scrutiny, which is when most supply "
                            "chain compromises land."
                        ),
                        "cve": None,
                        "reference": npm_url,
                        "provenance": prov(f"First published {created_str[:10]}"),
                    }
                )

        maintainers = meta.get("maintainers") or []
        if len(maintainers) == 1:
            flags.append(
                {
                    "source": "npm Registry",
                    "source_id": SOURCE_NPM,
                    "type": "single_maintainer",
                    "severity": "low",
                    "title": "Single maintainer",
                    "description": (
                        "Only one account can publish this package. A single account "
                        "compromise affects every downstream user at once."
                    ),
                    "cve": None,
                    "reference": npm_url,
                    "provenance": prov(f"1 maintainer: {maintainers[0].get('name', 'unknown')}"),
                }
            )

        versions = list((meta.get("versions") or {}).keys())
        if len(versions) >= 3 and age_days is not None:
            span = max(age_days, 1)
            velocity = len(versions) / span
            if velocity > 1.0:
                flags.append(
                    {
                        "source": "npm Registry",
                        "source_id": SOURCE_NPM,
                        "type": "high_velocity",
                        "severity": "low",
                        "title": f"Unusual publish velocity ({len(versions)} versions in {span} days)",
                        "description": (
                            "This package publishes unusually often. Not malicious on its "
                            "own, but rapid version churn around a maintainer change is a "
                            "known precursor to tampering."
                        ),
                        "cve": None,
                        "reference": npm_url,
                        "provenance": prov(f"{len(versions)} versions in {span} days"),
                    }
                )

        return flags

    # ------------------------------------------------------------------ #
    #  Suggestion engine
    # ------------------------------------------------------------------ #
    def _get_npm_latest(self, name: str) -> str | None:
        """Fetch dist-tags.latest from the npm registry."""
        try:
            resp = requests.get(f"{NPM_API}/{name}/latest", timeout=TIMEOUT)
            if resp.status_code == 200:
                return resp.json().get("version")
        except Exception:
            pass
        return None

    def _best_match(self, name: str, threshold: float = 0.6):
        """Closest legitimate package name to ``name``, or (None, 0.0)."""
        best, best_ratio = None, 0.0
        for t in self.targets:
            ratio = difflib.SequenceMatcher(None, name.lower(), t.lower()).ratio()
            if ratio > best_ratio:
                best_ratio, best = ratio, t
        if best and best_ratio > threshold and best.lower() != name.lower():
            return best, best_ratio
        return None, best_ratio

    def _get_suggestion(self, name: str, version_spec: str, flags: list) -> dict | None:
        """Return a suggestion dict for a flagged package, or None."""
        flag_types = {f["type"] for f in flags}

        # 1. Typosquat -> point at the legitimate package name
        if "typosquat" in flag_types:
            legit = None
            for f in flags:
                if f["type"] == "typosquat":
                    match = (f.get("provenance") or {}).get("match") or {}
                    if match.get("target") and match["target"].lower() != name.lower():
                        legit = match["target"]
                        break
            if not legit:
                legit, _ = self._best_match(name)
            if legit:
                return {
                    "name": legit,
                    "version": "latest",
                    "reason": f"'{name}' looks like a typosquat -- install the real package",
                    "url": f"https://www.npmjs.com/package/{legit}",
                    "install": f"npm uninstall {name} && npm install {legit}",
                    "warning": False,
                }

        # 2. Package not found -> did you mean ...?
        if "not_found" in flag_types:
            best, ratio = self._best_match(name)
            if best:
                return {
                    "name": best,
                    "version": "latest",
                    "reason": f"Did you mean '{best}'? ({ratio:.0%} match)",
                    "url": f"https://www.npmjs.com/package/{best}",
                    "install": f"npm install {best}",
                    "warning": False,
                }

        # 3. Vulnerability / malware / backdoor / sabotage -> safe version
        actionable = {"vulnerability", "malware", "backdoor", "sabotage", "dependency confusion", "typosquat"}
        if flag_types & actionable:
            fixed_version = next(
                (f["fixed_version"] for f in flags if f.get("fixed_version")), None
            )
            if fixed_version:
                return {
                    "name": name,
                    "version": fixed_version,
                    "reason": "Minimum patched version per OSV advisory",
                    "url": f"https://www.npmjs.com/package/{name}",
                    "install": f"npm install {name}@{fixed_version}",
                    "warning": False,
                }

            latest = self._get_npm_latest(name)
            if latest is None:
                return {
                    "name": None,
                    "version": None,
                    "reason": "Package unreachable on npm -- consider removing it",
                    "url": None,
                    "install": None,
                    "warning": True,
                }

            if detections.is_flagged(name, latest):
                return {
                    "name": None,
                    "version": None,
                    "reason": f"Latest ({latest}) is also compromised -- remove this package",
                    "url": f"https://www.npmjs.com/package/{name}",
                    "install": None,
                    "warning": True,
                }

            if self._clean_version(version_spec) == latest:
                return {
                    "name": None,
                    "version": None,
                    "reason": f"Already on latest ({latest}) -- await an upstream patch or find an alternative",
                    "url": f"https://www.npmjs.com/package/{name}",
                    "install": None,
                    "warning": True,
                }

            return {
                "name": name,
                "version": latest,
                "reason": "Upgrade to latest safe version",
                "url": f"https://www.npmjs.com/package/{name}",
                "install": f"npm install {name}@{latest}",
                "warning": False,
            }

        return None

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #
    def _clean_version(self, version_spec: str) -> str:
        if not version_spec:
            return ""
        return version_spec.lstrip("^~>=<").split(" ")[0].strip()

    def _osv_severity(self, vuln: dict) -> str:
        for entry in vuln.get("severity") or []:
            raw = entry.get("score") or ""
            try:
                score = float(raw.split("/")[0]) if "/" in raw else float(raw)
            except (ValueError, TypeError):
                continue
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            return "low"
        return "medium"

    @staticmethod
    def _osv_fixed_version(vuln: dict) -> str | None:
        """First ``fixed`` version across the advisory's SEMVER ranges."""
        for affected in vuln.get("affected") or []:
            for rng in affected.get("ranges") or []:
                if rng.get("type") != "SEMVER":
                    continue
                for event in rng.get("events") or []:
                    if "fixed" in event:
                        return event["fixed"]
        return None

    @staticmethod
    def _osv_affected_range(vuln: dict) -> str | None:
        """Human-readable affected range, e.g. ``1.0.0 - 1.4.2``."""
        spans = []
        for affected in vuln.get("affected") or []:
            for rng in affected.get("ranges") or []:
                if rng.get("type") != "SEMVER":
                    continue
                introduced = None
                for event in rng.get("events") or []:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    elif "fixed" in event:
                        spans.append((introduced or "*", event["fixed"]))
                        introduced = None
                    elif "last_affected" in event:
                        spans.append((introduced or "*", event["last_affected"]))
                        introduced = None
        if not spans:
            return None
        return ", ".join(f"{a} - {b}" for a, b in spans)

    def _max_severity(self, severities: list) -> str:
        for s in SEVERITY_ORDER:
            if s in severities:
                return s
        return "low"

    def _build_summary(self, all_results: list) -> dict:
        total = len(all_results)
        flagged = [r for r in all_results if not r["safe"]]
        by_sev = {s: 0 for s in SEVERITY_ORDER}
        for r in flagged:
            sev = r.get("max_severity", "low")
            if sev in by_sev:
                by_sev[sev] += 1
        return {
            "total_packages": total,
            "safe": total - len(flagged),
            "flagged": len(flagged),
            "by_severity": by_sev,
            "risk_score": self._risk_score(by_sev),
        }

    def _risk_score(self, by_sev: dict) -> int:
        return min(
            100,
            by_sev["critical"] * 40
            + by_sev["high"] * 20
            + by_sev["medium"] * 8
            + by_sev["low"] * 2,
        )


def create_scanner() -> PackageScanner:
    """Bootstrap the database and return a ready scanner."""
    init_db()
    return PackageScanner()
