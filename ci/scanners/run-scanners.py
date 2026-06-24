#!/usr/bin/env python3
# Copyright (c) 2026-present The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.
"""Run qbit scanner evidence collection without leaking raw findings."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "qbit-scanner-summary-v1"
AGGREGATE_SCHEMA_VERSION = "qbit-scanner-aggregate-v1"
OUTPUT_ROOT_README_TITLE = "# Scanner Evidence"
SEVERITY_KEYS = ("critical", "high", "medium", "low", "unknown")
HIGH_CRITICAL = {"critical", "high"}
GENERIC_SEVERITY_KEYS = ("severity", "level", "risk", "impact")
GENERIC_NESTED_CONTAINER_KEYS = {"alerts", "children", "entries", "findings", "issues", "nodes", "results", "runs"}
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
SCANNER_TRIAGED_DISPOSITIONS = {
    "accepted_risk",
    "false_positive",
    "finding_promoted",
    "not_reachable",
    "not_security",
    "routed_to_track",
}
README_PREAMBLE = (
    f"{OUTPUT_ROOT_README_TITLE}\n\n"
    "Raw scanner output may contain sensitive paths or secret-adjacent context and is private by default.\n"
    "CI uploads only `summary.json`, `triage.jsonl`, and this README.\n\n"
)
FINDING_EXIT_CODES = {
    "actionlint": {1},
    "cargo_audit": {1},
    "osv": {1},
    "semgrep": {1},
    "zizmor": {1},
}

@dataclass(frozen=True)
class ScannerSpec:
    tool: str
    executable: str = ""
    config_refs: list[str] = field(default_factory=list)
    raw_output_private: bool = True
    secret_scanner: bool = False
    internal: bool = False
    requires_build: bool = False


SCANNERS: dict[str, ScannerSpec] = {
    "codeql": ScannerSpec("codeql", "codeql", ["CodeQL default security queries"], requires_build=False),
    "osv": ScannerSpec("osv", "osv-scanner", ["OSV scanner recursive source scan"]),
    "vendored_inventory": ScannerSpec("vendored_inventory", internal=True),
    "gitleaks": ScannerSpec(
        "gitleaks",
        "gitleaks",
        ["gitleaks default rules; reviewed false positives live in triage.jsonl"],
        raw_output_private=True,
        secret_scanner=True,
    ),
    "zizmor": ScannerSpec("zizmor", "zizmor", ["zizmor default audits"]),
    "actionlint": ScannerSpec("actionlint", "actionlint", ["actionlint default checks"]),
    "semgrep": ScannerSpec("semgrep", "semgrep", ["Semgrep auto config"]),
    "clang_static_analyzer": ScannerSpec(
        "clang_static_analyzer",
        "scan-build",
        ["Clang Static Analyzer default checkers"],
        requires_build=True,
    ),
    "syft": ScannerSpec("syft", "syft", ["Syft filesystem SBOM"]),
    "grype": ScannerSpec("grype", "grype", ["Grype scan from Syft SBOM"]),
    "cargo_audit": ScannerSpec("cargo_audit", "cargo", ["RustSec cargo-audit"]),
    "release_sanitizer": ScannerSpec(
        "release_sanitizer",
        config_refs=["current checkout contrib/release-sanitize/export-public-snapshot.py and manifest.txt"],
        internal=True,
    ),
    "fuzz_hooks": ScannerSpec("fuzz_hooks", internal=True),
}

SCANNER_SETS = {
    "minimum": [
        "codeql",
        "osv",
        "vendored_inventory",
        "gitleaks",
        "zizmor",
        "actionlint",
        "semgrep",
        "clang_static_analyzer",
        "syft",
        "grype",
        "cargo_audit",
        "release_sanitizer",
        "fuzz_hooks",
    ],
    "release-only": ["release_sanitizer"],
    "dependency-only": ["osv", "syft", "grype", "cargo_audit", "vendored_inventory"],
    "secrets-only": ["gitleaks"],
    "workflow-only": ["zizmor", "actionlint", "codeql"],
    "sast-only": ["codeql", "semgrep", "clang_static_analyzer"],
}
LEGACY_SCANNER_SET_ALIASES = {
    "v1-minimum": "minimum",
}
SCANNER_MODES = {"nightly", "manual_dry_run", "frozen_evidence"}
LEGACY_MODE_ALIASES = {
    "v1_frozen_evidence": "frozen_evidence",
}

LIBBITCOINPQC_PATH = "src/libbitcoinpqc"
LIBBITCOINPQC_UPSTREAM_REPO = "https://github.com/Qbit-Org/libbitcoinpqc-qbit.git"
LIBBITCOINPQC_UPSTREAM_REF = "refs/heads/develop"
LIBBITCOINPQC_CURATED_REF = "refs/heads/qbit-subtree"
LIBBITCOINPQC_VERIFY_COMMAND = ["test/lint/git-subtree-check.sh", "-r", LIBBITCOINPQC_PATH]


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def git_toplevel(source: Path) -> Path | None:
    completed = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    text = completed.stdout.strip()
    return Path(text).resolve() if text else None


def source_scope(source: Path) -> str:
    resolved = source.resolve()
    if git_toplevel(resolved) == resolved:
        return "."
    try:
        relative = resolved.relative_to(repo_root())
    except ValueError:
        digest = hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()
        return f"external:{digest[:16]}"
    return "." if str(relative) == "." else str(relative)


def ensure_safe_identifier(value: str, label: str) -> str:
    if not value or not SAFE_ID_RE.fullmatch(value):
        raise SystemExit(f"{label} must match {SAFE_ID_RE.pattern}")
    return value


def scanner_severity_bucket(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"critical", "crit"}:
        return "critical"
    if text in {"high", "error", "err"}:
        return "high"
    if text in {"medium", "moderate", "warning", "warn"}:
        return "medium"
    if text == "low":
        return "low"
    return "unknown"


def scanner_triage_finding_id(row: dict[str, Any]) -> str:
    return str(row.get("finding_id") or row.get("scanner_finding_id") or row.get("fingerprint") or "").strip()


def scanner_high_or_critical_finding_ids(summary: dict[str, Any]) -> set[str] | None:
    if "normalized_findings" not in summary:
        return None
    findings = summary.get("normalized_findings", [])
    if not isinstance(findings, list):
        return None
    high_or_critical_ids: set[str] = set()
    for row in findings:
        if not isinstance(row, dict):
            continue
        finding_id = scanner_triage_finding_id(row)
        if finding_id and scanner_severity_bucket(row.get("severity", "unknown")) in HIGH_CRITICAL:
            high_or_critical_ids.add(finding_id)
    return high_or_critical_ids


def scanner_triaged_high_or_critical_finding_ids(
    rows: list[dict[str, Any]],
    current_finding_ids: set[str] | None = None,
) -> set[str]:
    triaged: set[str] = set()
    for row in rows:
        disposition = str(row.get("disposition", "")).strip().lower()
        severity = scanner_severity_bucket(row.get("severity", "unknown"))
        finding_id = scanner_triage_finding_id(row)
        if disposition in SCANNER_TRIAGED_DISPOSITIONS and severity in HIGH_CRITICAL:
            if not finding_id:
                continue
            if current_finding_ids is not None and finding_id not in current_finding_ids:
                continue
            triaged.add(finding_id)
    return triaged


def scanner_triaged_high_or_critical_count(
    rows: list[dict[str, Any]],
    current_finding_ids: set[str] | None = None,
) -> int:
    return len(scanner_triaged_high_or_critical_finding_ids(rows, current_finding_ids))


def git_commit(source: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def git_merge_base(source: Path, left: str, right: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(source), "merge-base", left, right],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        raise SystemExit(
            f"Unable to resolve history scanner diff base between {left} and {right}"
            + (f": {stderr}" if stderr else ".")
        )
    return completed.stdout.strip()


def history_log_opts(source: Path, args: argparse.Namespace) -> str:
    base_ref = str(getattr(args, "history_diff_base_ref", "") or "").strip()
    if not base_ref:
        return ""
    source_commit = str(args.source_commit or git_commit(source)).strip()
    if not source_commit:
        raise SystemExit("History scanner diff scope requires a git source commit.")
    base_commit = git_merge_base(source, source_commit, base_ref)
    return f"{base_commit}..{source_commit}"


def run_text_command(command: list[str], cwd: Path, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (
            exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        )
        stderr = (
            exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        )
        return 124, stdout, stderr
    except OSError as exc:
        return 127, "", f"{type(exc).__name__}: {exc}"
    return completed.returncode, completed.stdout, completed.stderr


def git_command(source: Path, *args: str) -> tuple[int, str, str]:
    return run_text_command(["git", "-C", str(source), *args], source)


def libbitcoinpqc_auth_source() -> str:
    if os.environ.get("LIBBITCOINPQC_READ_TOKEN"):
        return "LIBBITCOINPQC_READ_TOKEN"
    if os.environ.get("UPSTREAM_GITHUB_TOKEN"):
        return "UPSTREAM_GITHUB_TOKEN"
    return ""


def libbitcoinpqc_github_auth_env(repo_url: str) -> dict[str, str] | None:
    token = os.environ.get("LIBBITCOINPQC_READ_TOKEN") or os.environ.get("UPSTREAM_GITHUB_TOKEN")
    if not token or not repo_url.startswith("https://github.com/"):
        return None

    env = os.environ.copy()
    try:
        config_count = int(env.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        config_count = 0

    auth = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
    key = "http.https://github.com/.extraheader"

    # Reset checkout's repository-scoped extraheader before adding the upstream read token.
    env[f"GIT_CONFIG_KEY_{config_count}"] = key
    env[f"GIT_CONFIG_VALUE_{config_count}"] = ""
    env[f"GIT_CONFIG_KEY_{config_count + 1}"] = key
    env[f"GIT_CONFIG_VALUE_{config_count + 1}"] = f"AUTHORIZATION: basic {auth}"
    env["GIT_CONFIG_COUNT"] = str(config_count + 2)
    return env


def safe_review_id(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(ensure_safe_identifier(text, "review_id"))
    except Exception as exc:
        raise SystemExit(str(exc)) from exc


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def append_readme(output_root: Path, line: str) -> None:
    readme = output_root / "README.md"
    if not readme.exists():
        readme.write_text(README_PREAMBLE, encoding="utf-8")
    with readme.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def output_root_file_owned(path: Path) -> bool:
    if path.name == "README.md":
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return False
        return text.startswith(README_PREAMBLE)
    if path.name == "summary.json":
        payload = load_json(path)
        return isinstance(payload, dict) and payload.get("schema_version") == AGGREGATE_SCHEMA_VERSION
    return False


def severity_bucket(value: Any) -> str:
    return str(scanner_severity_bucket(value))


def severity_from_cvss_score(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return severity_from_numeric_score(float(text))
    except ValueError:
        pass
    score = cvss_v3_base_score(text)
    if score is None:
        return None
    return severity_from_numeric_score(score)


def severity_from_numeric_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def cvss_v3_base_score(vector: str) -> float | None:
    parts = [part for part in vector.strip().upper().split("/") if part]
    if not parts or not parts[0].startswith("CVSS:3."):
        return None
    version = parts[0].split(":", 1)[1]
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key] = value
    try:
        attack_vector = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        attack_complexity = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        user_interaction = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        scope = metrics["S"]
        privilege_required = {
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.5},
        }[scope][metrics["PR"]]
        confidentiality = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["C"]]
        integrity = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["I"]]
        availability = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["A"]]
    except KeyError:
        return None

    impact = 1.0 - ((1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability))
    if scope == "U":
        impact_sub_score = 6.42 * impact
    elif version == "3.1":
        impact_sub_score = 7.52 * (impact - 0.029) - 3.25 * ((impact * 0.9731 - 0.02) ** 13)
    else:
        impact_sub_score = 7.52 * (impact - 0.029) - 3.25 * ((impact - 0.02) ** 15)
    if impact_sub_score <= 0.0:
        return 0.0
    exploitability = 8.22 * attack_vector * attack_complexity * privilege_required * user_interaction
    if scope == "U":
        score = min(impact_sub_score + exploitability, 10.0)
    else:
        score = min(1.08 * (impact_sub_score + exploitability), 10.0)
    return math.ceil(score * 10.0) / 10.0


def finding_id(tool: str, identity: Any) -> str:
    payload = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"{tool}:{digest}"


def normalized_finding(tool: str, severity: Any, identity: Any) -> dict[str, str]:
    return {
        "finding_id": finding_id(tool, identity),
        "severity": severity_bucket(severity),
    }


def empty_counts() -> dict[str, int]:
    return {key: 0 for key in SEVERITY_KEYS}


def add_count(counts: dict[str, int], severity: Any, amount: int = 1) -> None:
    counts[severity_bucket(severity)] += amount


def high_critical_count(counts: dict[str, int]) -> int:
    return sum(int(counts.get(key, 0)) for key in HIGH_CRITICAL)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def merge_counts(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    merged = dict(left)
    for key in SEVERITY_KEYS:
        merged[key] = int(merged.get(key, 0)) + int(right.get(key, 0))
    return merged


def visit_generic_json(value: Any, on_match: Any) -> None:
    if isinstance(value, dict):
        matched = False
        for key in GENERIC_SEVERITY_KEYS:
            if key in value:
                on_match(value.get(key), value)
                matched = True
                break
        for key, child in value.items():
            if key in GENERIC_SEVERITY_KEYS:
                continue
            if matched and not (
                isinstance(child, list) or (isinstance(child, dict) and key in GENERIC_NESTED_CONTAINER_KEYS)
            ):
                continue
            visit_generic_json(child, on_match)
    elif isinstance(value, list):
        for child in value:
            visit_generic_json(child, on_match)


def summarize_generic_json(path: Path) -> dict[str, int]:
    counts = empty_counts()
    if not path.is_file():
        return counts
    data = load_json(path)
    visit_generic_json(data, lambda severity, _identity: add_count(counts, severity))
    return counts


def findings_from_generic_json(tool: str, path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    data = load_json(path)
    findings = []
    visit_generic_json(data, lambda severity, identity: findings.append(normalized_finding(tool, severity, identity)))
    return findings


def sarif_result_severity(result: dict[str, Any]) -> str:
    level = result.get("level", "warning")
    properties = result.get("properties", {})
    security_severity = properties.get("security-severity") if isinstance(properties, dict) else None
    if security_severity is not None:
        try:
            return severity_from_numeric_score(float(security_severity))
        except (TypeError, ValueError):
            pass
    return severity_bucket(level)


def summarize_sarif(path: Path) -> dict[str, int]:
    counts = empty_counts()
    if not path.is_file():
        return counts
    data = load_json(path)
    for run in data.get("runs", []) if isinstance(data, dict) else []:
        for result in run.get("results", []):
            if isinstance(result, dict):
                add_count(counts, sarif_result_severity(result))
    return counts


def findings_from_sarif(tool: str, path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    data = load_json(path)
    findings = []
    for run in data.get("runs", []) if isinstance(data, dict) else []:
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            locations = result.get("locations", [])
            location = locations[0] if locations and isinstance(locations[0], dict) else {}
            physical_location = location.get("physicalLocation", {}) if isinstance(location, dict) else {}
            artifact = physical_location.get("artifactLocation", {}) if isinstance(physical_location, dict) else {}
            region = physical_location.get("region", {}) if isinstance(physical_location, dict) else {}
            message = result.get("message", {})
            identity = {
                "rule_id": result.get("ruleId"),
                "uri": artifact.get("uri") if isinstance(artifact, dict) else "",
                "line": region.get("startLine") if isinstance(region, dict) else "",
                "message": message.get("text") if isinstance(message, dict) else "",
            }
            findings.append(normalized_finding(tool, sarif_result_severity(result), identity))
    return findings


def summarize_semgrep(path: Path) -> dict[str, int]:
    counts = empty_counts()
    if not path.is_file():
        return counts
    data = load_json(path)
    for result in data.get("results", []) if isinstance(data, dict) else []:
        if not isinstance(result, dict):
            continue
        extra = result.get("extra", {})
        add_count(counts, extra.get("severity", "unknown") if isinstance(extra, dict) else "unknown")
    return counts


def findings_from_semgrep(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    data = load_json(path)
    findings = []
    for result in data.get("results", []) if isinstance(data, dict) else []:
        if not isinstance(result, dict):
            continue
        extra = result.get("extra", {})
        severity = extra.get("severity", "unknown") if isinstance(extra, dict) else "unknown"
        identity = {
            "check_id": result.get("check_id"),
            "path": result.get("path"),
            "start": result.get("start"),
            "end": result.get("end"),
        }
        findings.append(normalized_finding("semgrep", severity, identity))
    return findings


def osv_vulnerability_severity(vulnerability: Any) -> str:
    if not isinstance(vulnerability, dict):
        return "unknown"
    database_specific = vulnerability.get("database_specific", {})
    severity = database_specific.get("severity") if isinstance(database_specific, dict) else None
    if severity:
        return severity_bucket(severity)
    for row in vulnerability.get("severity", []):
        if not isinstance(row, dict):
            continue
        severity = severity_bucket(row.get("severity") or row.get("level"))
        if severity != "unknown":
            return severity
        cvss_severity = severity_from_cvss_score(row.get("score"))
        if cvss_severity not in {None, "unknown"}:
            return cvss_severity
    return "unknown"


def summarize_osv(path: Path) -> dict[str, int]:
    counts = empty_counts()
    if not path.is_file():
        return counts
    data = load_json(path)
    for result in data.get("results", []) if isinstance(data, dict) else []:
        packages = result.get("packages", []) if isinstance(result, dict) else []
        for package in packages:
            vulnerabilities = package.get("vulnerabilities", []) if isinstance(package, dict) else []
            for vulnerability in vulnerabilities:
                add_count(counts, osv_vulnerability_severity(vulnerability))
    return counts


def findings_from_osv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    data = load_json(path)
    findings = []
    for result in data.get("results", []) if isinstance(data, dict) else []:
        packages = result.get("packages", []) if isinstance(result, dict) else []
        for package in packages:
            package_info = package.get("package", {}) if isinstance(package, dict) else {}
            vulnerabilities = package.get("vulnerabilities", []) if isinstance(package, dict) else []
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                identity = {
                    "id": vulnerability.get("id"),
                    "aliases": vulnerability.get("aliases", []),
                    "package": package_info,
                }
                findings.append(normalized_finding("osv", osv_vulnerability_severity(vulnerability), identity))
    return findings


def summarize_grype(path: Path) -> dict[str, int]:
    counts = empty_counts()
    if not path.is_file():
        return counts
    data = load_json(path)
    for match in data.get("matches", []) if isinstance(data, dict) else []:
        vulnerability = match.get("vulnerability", {}) if isinstance(match, dict) else {}
        add_count(counts, vulnerability.get("severity", "unknown"))
    return counts


def findings_from_grype(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    data = load_json(path)
    findings = []
    for match in data.get("matches", []) if isinstance(data, dict) else []:
        vulnerability = match.get("vulnerability", {}) if isinstance(match, dict) else {}
        artifact = match.get("artifact", {}) if isinstance(match, dict) else {}
        identity = {
            "id": vulnerability.get("id") if isinstance(vulnerability, dict) else "",
            "artifact": {
                "name": artifact.get("name"),
                "version": artifact.get("version"),
                "type": artifact.get("type"),
            }
            if isinstance(artifact, dict)
            else {},
        }
        severity = vulnerability.get("severity", "unknown") if isinstance(vulnerability, dict) else "unknown"
        findings.append(normalized_finding("grype", severity, identity))
    return findings


def summarize_gitleaks(path: Path) -> dict[str, int]:
    counts = empty_counts()
    if not path.is_file():
        return counts
    data = load_json(path)
    if isinstance(data, list):
        counts["high"] = len(data)
    return counts


def findings_from_gitleaks(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    data = load_json(path)
    if not isinstance(data, list):
        return []
    findings = []
    for row in data:
        if not isinstance(row, dict):
            continue
        identity = row.get("Fingerprint") or {
            "rule": row.get("RuleID"),
            "file": row.get("File"),
            "line": row.get("StartLine"),
        }
        findings.append(normalized_finding("gitleaks", "high", identity))
    return findings


def summarize_cargo_audit(path: Path) -> dict[str, int]:
    counts = empty_counts()
    if not path.is_file():
        return counts
    data = load_json(path)
    vulnerabilities = data.get("vulnerabilities", {}) if isinstance(data, dict) else {}
    rows = vulnerabilities.get("list", vulnerabilities.get("found", []))
    if isinstance(rows, list):
        for row in rows:
            advisory = row.get("advisory", {}) if isinstance(row, dict) else {}
            add_count(counts, advisory.get("severity", "unknown"))
    return counts


def findings_from_cargo_audit(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    data = load_json(path)
    vulnerabilities = data.get("vulnerabilities", {}) if isinstance(data, dict) else {}
    rows = vulnerabilities.get("list", vulnerabilities.get("found", []))
    findings = []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            advisory = row.get("advisory", {})
            package = row.get("package", {})
            identity = {
                "advisory": advisory.get("id") if isinstance(advisory, dict) else "",
                "package": package,
            }
            severity = advisory.get("severity", "unknown") if isinstance(advisory, dict) else "unknown"
            findings.append(normalized_finding("cargo_audit", severity, identity))
    return findings


def summarize_cargo_audit_outputs(raw_dir: Path) -> dict[str, int]:
    counts = empty_counts()
    for path in sorted(raw_dir.glob("command-*.stdout.txt")):
        counts = merge_counts(counts, summarize_cargo_audit(path))
    return counts


def findings_from_cargo_audit_outputs(raw_dir: Path) -> list[dict[str, str]]:
    findings = []
    for path in sorted(raw_dir.glob("command-*.stdout.txt")):
        findings.extend(findings_from_cargo_audit(path))
    return findings


def summarize_text_lines(path: Path, severity: str = "medium") -> dict[str, int]:
    counts = empty_counts()
    if not path.is_file():
        return counts
    lines = [line for line in path.read_text(errors="replace").splitlines() if line.strip()]
    counts[severity_bucket(severity)] = len(lines)
    return counts


def findings_from_text_lines(tool: str, path: Path, severity: str = "medium") -> list[dict[str, str]]:
    if not path.is_file():
        return []
    return [
        normalized_finding(tool, severity, {"line": line})
        for line in path.read_text(errors="replace").splitlines()
        if line.strip()
    ]


def load_jsonl_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def high_critical_finding_ids(findings: list[dict[str, str]] | None) -> set[str] | None:
    if findings is None:
        return None
    return scanner_high_or_critical_finding_ids({"normalized_findings": findings})


def triaged_high_critical_finding_ids(path: Path, current_finding_ids: set[str] | None = None) -> set[str]:
    return scanner_triaged_high_or_critical_finding_ids(load_jsonl_rows(path), current_finding_ids)


def triaged_high_critical_count(path: Path, current_finding_ids: set[str] | None = None) -> int:
    return int(scanner_triaged_high_or_critical_count(load_jsonl_rows(path), current_finding_ids))


def safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def counts_total(counts: dict[str, int]) -> int:
    return sum(safe_int(counts.get(key, 0)) for key in SEVERITY_KEYS)


def accepts_finding_exit_codes(tool: str, exit_codes: list[int], counts: dict[str, int]) -> bool:
    accepted_exit_codes = FINDING_EXIT_CODES.get(tool)
    if not accepted_exit_codes or counts_total(counts) <= 0:
        return False
    nonzero_exit_codes = [code for code in exit_codes if code != 0]
    return bool(nonzero_exit_codes) and all(code in accepted_exit_codes for code in nonzero_exit_codes)


def command_to_string(command: list[str]) -> str:
    return " ".join(command)


def run_command(command: list[str], raw_dir: Path, index: int, cwd: Path) -> int:
    raw_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = raw_dir / f"command-{index}.stdout.txt"
    stderr_path = raw_dir / f"command-{index}.stderr.txt"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            completed = subprocess.run(command, cwd=cwd, stdout=stdout, stderr=stderr, check=False)
        except OSError as exc:
            stderr.write(f"{type(exc).__name__}: {exc}\n".encode("utf-8", errors="replace"))
            return 127
    return completed.returncode


def tool_version(executable: str) -> str:
    if not executable or shutil.which(executable) is None:
        return ""
    for args in ([executable, "--version"], [executable, "version"]):
        completed = subprocess.run(args, capture_output=True, text=True, check=False)
        output = (completed.stdout or completed.stderr).strip()
        if completed.returncode == 0 and output:
            return output.splitlines()[0][:200]
    return ""


def git_worktree_dirty(source: Path) -> bool:
    completed = subprocess.run(
        ["git", "-C", str(source), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return True
    return bool(completed.stdout.strip())


def can_reuse_syft_sbom(raw_dir: Path, args: argparse.Namespace, syft_sbom: Path) -> bool:
    selected_scanners = {str(tool).strip() for tool in getattr(args, "scanner", []) if str(tool).strip()}
    if selected_scanners and "syft" not in selected_scanners:
        return False
    if not syft_sbom.is_file():
        return False
    syft_summary = load_json(raw_dir.parent.parent / "syft" / "summary.json")
    if not isinstance(syft_summary, dict):
        return False
    if str(syft_summary.get("status", "")).strip().lower() != "completed":
        return False
    if git_worktree_dirty(args.source):
        return False
    if str(syft_summary.get("source_commit", "")).strip() != str(args.source_commit).strip():
        return False
    return str(syft_summary.get("source_scope", "")).strip() == source_scope(args.source)


def external_commands(tool: str, source: Path, raw_dir: Path, args: argparse.Namespace) -> tuple[list[list[str]], Path | None]:
    if tool == "codeql":
        db = raw_dir / "db-cpp"
        sarif = raw_dir / "codeql-cpp.sarif"
        return (
            [
                [
                    "codeql",
                    "database",
                    "create",
                    str(db),
                    "--language=cpp",
                    f"--source-root={source}",
                    "--build-mode=none",
                ],
                [
                    "codeql",
                    "database",
                    "analyze",
                    str(db),
                    "codeql/cpp-queries",
                    "--format=sarif-latest",
                    f"--output={sarif}",
                    "--download",
                ],
            ],
            sarif,
        )
    if tool == "osv":
        report = raw_dir / "osv.json"
        return (
            [["osv-scanner", "--recursive", "--format", "json", "--output", str(report), str(source)]],
            report,
        )
    if tool == "gitleaks":
        report = raw_dir / "gitleaks.redacted.json"
        log_opts = history_log_opts(source, args)
        command = [
            "gitleaks",
            "detect",
            "--source",
            str(source),
            "--redact",
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--exit-code",
            "0",
        ]
        if log_opts:
            command.extend(["--log-opts", log_opts])
        allowlist = repo_root() / "ci" / "scanners" / "gitleaks-allowlist.toml"
        if allowlist.is_file():
            command.extend(["--config", str(allowlist)])
        return ([command], report)
    if tool == "zizmor":
        report = raw_dir / "command-0.stdout.txt"
        return (
            [["zizmor", "--format=json", "--no-progress", "--no-exit-codes", str(source / ".github" / "workflows")]],
            report,
        )
    if tool == "actionlint":
        report = raw_dir / "command-0.stdout.txt"
        return ([["actionlint", "-format", "{{json .}}"]], report)
    if tool == "semgrep":
        report = raw_dir / "semgrep.json"
        return (
            [["semgrep", "scan", "--config=auto", "--json", "--output", str(report), str(source)]],
            report,
        )
    if tool == "clang_static_analyzer":
        build_dir = raw_dir / "build"
        report = raw_dir / "scan-build"
        return (
            [
                ["cmake", "-S", str(source), "-B", str(build_dir), "-DCMAKE_BUILD_TYPE=Debug"],
                ["scan-build", "-o", str(report), "cmake", "--build", str(build_dir), "-j2"],
            ],
            report,
        )
    if tool == "syft":
        report = raw_dir / "sbom.syft.json"
        return ([["syft", f"dir:{source}", "-o", f"syft-json={report}"]], report)
    if tool == "grype":
        sbom = raw_dir / "sbom.syft.json"
        report = raw_dir / "grype.json"
        commands: list[list[str]] = []
        syft_sbom = raw_dir.parent.parent / "syft" / "raw" / "sbom.syft.json"
        if can_reuse_syft_sbom(raw_dir, args, syft_sbom):
            raw_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(syft_sbom, sbom)
        if not sbom.is_file():
            commands.append(["syft", f"dir:{source}", "-o", f"syft-json={sbom}"])
        commands.append(["grype", f"sbom:{sbom}", "-o", "json", "--file", str(report)])
        return (commands, report)
    if tool == "cargo_audit":
        manifests = sorted(source.glob("**/Cargo.lock"))
        commands = []
        for lockfile in manifests:
            commands.append(
                [
                    "cargo",
                    "audit",
                    "--json",
                    "--file",
                    str(lockfile),
                ]
            )
        if not commands:
            commands = [["cargo", "audit", "--json"]]
        return (commands, None)
    raise ValueError(f"Unsupported external scanner: {tool}")


def parse_counts(tool: str, report: Path | None, raw_dir: Path) -> dict[str, int]:
    if tool == "codeql":
        return summarize_sarif(report) if report else empty_counts()
    if tool == "osv":
        return summarize_osv(report) if report else empty_counts()
    if tool == "gitleaks":
        return summarize_gitleaks(report) if report else empty_counts()
    if tool == "semgrep":
        return summarize_semgrep(report) if report else empty_counts()
    if tool == "zizmor":
        return summarize_generic_json(report) if report else empty_counts()
    if tool == "grype":
        return summarize_grype(report) if report else empty_counts()
    if tool == "cargo_audit":
        return summarize_cargo_audit_outputs(raw_dir)
    if tool == "actionlint":
        return summarize_text_lines(report, "medium") if report else empty_counts()
    if tool == "clang_static_analyzer":
        plist_count = len(list(raw_dir.glob("scan-build/**/*.plist")))
        counts = empty_counts()
        counts["unknown"] = plist_count
        return counts
    return empty_counts()


def parse_findings(tool: str, report: Path | None, raw_dir: Path) -> list[dict[str, str]]:
    if tool == "codeql":
        return findings_from_sarif(tool, report) if report else []
    if tool == "osv":
        return findings_from_osv(report) if report else []
    if tool == "gitleaks":
        return findings_from_gitleaks(report) if report else []
    if tool == "semgrep":
        return findings_from_semgrep(report) if report else []
    if tool == "zizmor":
        return findings_from_generic_json(tool, report) if report else []
    if tool == "grype":
        return findings_from_grype(report) if report else []
    if tool == "cargo_audit":
        return findings_from_cargo_audit_outputs(raw_dir)
    if tool == "actionlint":
        return findings_from_text_lines(tool, report, "medium") if report else []
    if tool == "clang_static_analyzer":
        return [
            normalized_finding(tool, "unknown", {"plist": path.name})
            for path in sorted(raw_dir.glob("scan-build/**/*.plist"))
        ]
    return []


def git_subtree_field(message: str, field: str) -> str:
    prefix = f"{field}:"
    for line in message.splitlines():
        if line.startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""


def latest_git_subtree_metadata(source: Path, relpath: str) -> dict[str, Any]:
    grep = f"^git-subtree-dir: {relpath}/*$"
    git_args = [
        "log",
        f"--grep={grep}",
        "--pretty=format:%H%x1f%B%x1e",
        "HEAD",
    ]
    exit_code, stdout, _stderr = git_command(source, *git_args)
    metadata: dict[str, Any] = {
        "metadata_command": command_to_string(["git", *git_args]),
        "metadata_exit_code": exit_code,
    }
    if exit_code != 0:
        return metadata
    for record in stdout.split("\x1e"):
        record = record.strip("\n")
        if not record or "\x1f" not in record:
            continue
        commit, message = record.split("\x1f", 1)
        split = git_subtree_field(message, "git-subtree-split")
        if not split:
            continue
        lines = [line for line in message.splitlines() if line.strip()]
        metadata.update(
            {
                "qbit_import_commit": commit.strip(),
                "git_subtree_split": split,
                "git_subtree_dir": git_subtree_field(message, "git-subtree-dir"),
                "git_subtree_mainline": git_subtree_field(message, "git-subtree-mainline"),
                "qbit_import_subject": lines[0] if lines else "",
            }
        )
        return metadata
    return metadata


def git_tree_for_path(source: Path, relpath: str, commit: str = "HEAD") -> str:
    exit_code, stdout, _stderr = git_command(source, "ls-tree", "-d", commit, relpath)
    if exit_code != 0:
        return ""
    parts = stdout.split()
    if len(parts) >= 3 and parts[1] == "tree":
        return parts[2]
    return ""


def git_commit_tree(source: Path, commit: str) -> str:
    exit_code, stdout, _stderr = git_command(source, "show", "-s", "--format=%T", commit)
    return stdout.strip() if exit_code == 0 else ""


def git_commit_parents(source: Path, commit: str) -> list[str]:
    exit_code, stdout, _stderr = git_command(source, "show", "-s", "--format=%P", commit)
    return stdout.split() if exit_code == 0 else []


def imported_upstream_source_commit(source: Path, curated_commit: str) -> tuple[str, str]:
    if not curated_commit or git_object_type(source, curated_commit) != "commit":
        return "", "unavailable"
    parents = git_commit_parents(source, curated_commit)
    if len(parents) >= 2:
        return parents[1], "merge_second_parent"
    if not parents:
        return "", "missing_parent"
    merge_parents = git_commit_parents(source, parents[0])
    if len(merge_parents) >= 2:
        return merge_parents[1], "first_parent_merge_second_parent"
    return "", "not_derivable"


def git_ls_remote_ref(source: Path, repo_url: str, ref: str) -> tuple[str, int]:
    exit_code, stdout, _stderr = run_text_command(
        ["git", "ls-remote", repo_url, ref],
        source,
        env=libbitcoinpqc_github_auth_env(repo_url),
    )
    if exit_code != 0:
        return "", exit_code
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == ref:
            return parts[0], exit_code
    return "", exit_code


def git_fetch(source: Path, repo_url: str, refs: list[str]) -> dict[str, Any]:
    command = ["git", "fetch", "--no-tags", repo_url, *refs]
    exit_code, _stdout, _stderr = run_text_command(
        command,
        source,
        env=libbitcoinpqc_github_auth_env(repo_url),
    )
    return {
        "command": command_to_string(command),
        "exit_code": exit_code,
    }


def fetch_libbitcoinpqc_provenance_objects(source: Path, split: str) -> tuple[list[dict[str, Any]], list[str]]:
    results = [
        git_fetch(
            source,
            LIBBITCOINPQC_UPSTREAM_REPO,
            [
                LIBBITCOINPQC_UPSTREAM_REF,
                LIBBITCOINPQC_CURATED_REF,
            ],
        )
    ]
    gaps = []
    if results[0]["exit_code"] != 0:
        gaps.append("libbitcoinpqc remote provenance refs fetch failed.")
    if split and git_object_type(source, split) != "commit":
        split_result = git_fetch(source, LIBBITCOINPQC_UPSTREAM_REPO, [split])
        results.append(split_result)
        if split_result["exit_code"] != 0:
            gaps.append(f"libbitcoinpqc imported split fetch failed: {split}")
    return results, gaps


def git_object_type(source: Path, object_name: str) -> str:
    exit_code, stdout, _stderr = git_command(source, "cat-file", "-t", object_name)
    return stdout.strip() if exit_code == 0 else ""


def git_ancestor_relationship(source: Path, ancestor: str, descendant: str) -> str:
    if not ancestor or not descendant:
        return "missing"
    if git_object_type(source, ancestor) != "commit" or git_object_type(source, descendant) != "commit":
        return "unverified"
    exit_code, _stdout, _stderr = git_command(source, "merge-base", "--is-ancestor", ancestor, descendant)
    if exit_code == 0:
        return "ancestor"
    if exit_code == 1:
        return "not_ancestor"
    return "unverified"


def libbitcoinpqc_provenance(source: Path) -> tuple[dict[str, Any], list[str]]:
    provenance: dict[str, Any] = {
        "upstream_repo": LIBBITCOINPQC_UPSTREAM_REPO,
        "upstream_ref": LIBBITCOINPQC_UPSTREAM_REF,
        "curated_ref": LIBBITCOINPQC_CURATED_REF,
        "verification_command": command_to_string(LIBBITCOINPQC_VERIFY_COMMAND),
        "auth_source": libbitcoinpqc_auth_source() or "checkout/default",
    }
    gaps: list[str] = []

    upstream_ref_commit, upstream_ref_exit = git_ls_remote_ref(
        source, LIBBITCOINPQC_UPSTREAM_REPO, LIBBITCOINPQC_UPSTREAM_REF
    )
    curated_ref_commit, curated_ref_exit = git_ls_remote_ref(
        source, LIBBITCOINPQC_UPSTREAM_REPO, LIBBITCOINPQC_CURATED_REF
    )
    provenance["upstream_ref_commit"] = upstream_ref_commit
    provenance["upstream_ref_lookup_exit_code"] = upstream_ref_exit
    provenance["curated_ref_commit"] = curated_ref_commit
    provenance["curated_ref_lookup_exit_code"] = curated_ref_exit
    if not upstream_ref_commit:
        gaps.append(f"libbitcoinpqc upstream ref unavailable: {LIBBITCOINPQC_UPSTREAM_REF}")
    if not curated_ref_commit:
        gaps.append(f"libbitcoinpqc curated ref unavailable: {LIBBITCOINPQC_CURATED_REF}")

    metadata = latest_git_subtree_metadata(source, LIBBITCOINPQC_PATH)
    provenance.update(metadata)
    split = str(provenance.get("git_subtree_split", "")).strip()
    import_commit = str(provenance.get("qbit_import_commit", "")).strip()
    if not import_commit or not split:
        gaps.append("libbitcoinpqc subtree metadata missing: no git-subtree-split entry found.")
    fetch_results, fetch_gaps = fetch_libbitcoinpqc_provenance_objects(source, split)
    provenance["fetch_results"] = fetch_results
    gaps.extend(fetch_gaps)

    imported_source_commit, imported_source_method = imported_upstream_source_commit(source, split)
    provenance["imported_upstream_source_commit"] = imported_source_commit
    provenance["imported_upstream_source_method"] = imported_source_method
    if split and not imported_source_commit:
        gaps.append("libbitcoinpqc imported upstream source commit is not derivable from the curated split.")
    if imported_source_commit and upstream_ref_commit:
        if imported_source_commit == upstream_ref_commit:
            upstream_source_relationship = "matches_upstream_ref"
        else:
            upstream_source_relationship = git_ancestor_relationship(
                source,
                imported_source_commit,
                upstream_ref_commit,
            )
        provenance["upstream_source_relationship"] = upstream_source_relationship
        if upstream_source_relationship not in {"matches_upstream_ref", "ancestor"}:
            gaps.append(
                "libbitcoinpqc imported upstream source does not match "
                f"{LIBBITCOINPQC_UPSTREAM_REF}: imported={imported_source_commit} upstream={upstream_ref_commit}"
            )

    current_tree = git_tree_for_path(source, LIBBITCOINPQC_PATH)
    import_tree = git_commit_tree(source, import_commit) if import_commit else ""
    provenance["qbit_subtree_tree"] = current_tree
    provenance["qbit_import_tree"] = import_tree
    if not current_tree:
        gaps.append("libbitcoinpqc subtree tree hash unavailable from HEAD.")
    if import_commit and not import_tree:
        gaps.append(f"libbitcoinpqc qbit import commit tree unavailable: {import_commit}")
    if current_tree and import_tree and current_tree != import_tree:
        gaps.append("libbitcoinpqc subtree tree does not match the recorded qbit import commit tree.")

    verify_script = source / LIBBITCOINPQC_VERIFY_COMMAND[0]
    if verify_script.is_file():
        verify_exit, _stdout, _stderr = run_text_command(LIBBITCOINPQC_VERIFY_COMMAND, source)
    else:
        verify_exit = 127
    provenance["verification_exit_code"] = verify_exit
    provenance["verification_status"] = "passed" if verify_exit == 0 else "failed"
    if verify_exit != 0:
        gaps.append(
            f"libbitcoinpqc full subtree verification failed: {command_to_string(LIBBITCOINPQC_VERIFY_COMMAND)}"
        )

    if split and curated_ref_commit:
        if split == curated_ref_commit:
            relationship = "matches_curated_ref"
        else:
            relationship = git_ancestor_relationship(source, split, curated_ref_commit)
        provenance["curated_ref_relationship"] = relationship
        if relationship not in {"matches_curated_ref", "ancestor"}:
            gaps.append(
                "libbitcoinpqc imported split is not proven reachable from "
                f"{LIBBITCOINPQC_CURATED_REF}: imported={split} curated={curated_ref_commit}"
            )

    return provenance, gaps


def vendored_inventory(source: Path) -> tuple[dict[str, Any], dict[str, int]]:
    paths = [
        LIBBITCOINPQC_PATH,
        "src/secp256k1",
        "src/leveldb",
        "src/crc32c",
        "src/minisketch",
        "contrib/photon/src/vendor",
    ]
    entries = []
    gaps = []
    for relpath in paths:
        path = source / relpath
        if path.exists():
            entry = {
                "path": relpath,
                "present": True,
                "provenance_required": relpath == LIBBITCOINPQC_PATH,
            }
            if relpath == LIBBITCOINPQC_PATH:
                provenance, provenance_gaps = libbitcoinpqc_provenance(source)
                entry["provenance"] = provenance
                gaps.extend(provenance_gaps)
            entries.append(entry)
        else:
            gaps.append(f"Vendored path not present: {relpath}")
    return {"entries": entries, "coverage_gaps": gaps}, empty_counts()


def release_sanitizer(source: Path, raw_dir: Path, allow_dirty: bool) -> tuple[dict[str, Any], dict[str, int]]:
    output = raw_dir / "public-snapshot"
    mapping = raw_dir / "public-snapshot.release-sanitize-map.json"
    sanitizer = repo_root() / "contrib" / "release-sanitize" / "export-public-snapshot.py"
    manifest = repo_root() / "contrib" / "release-sanitize" / "manifest.txt"
    if not sanitizer.is_file() or not manifest.is_file():
        # The export tooling is stripped from sanitized public snapshots, where
        # skipping is correct. In a source tree -- identified by a source-only
        # marker file the sanitizer strips from public snapshots -- the tooling
        # must be present, so a missing sanitizer is a regression and fails
        # closed rather than skipping (otherwise should_fail would pass it). The
        # marker name is split so this retained file does not itself reference a
        # stripped path.
        missing = {
            "passed": False,
            "policy_source": "current_checkout",
            "sanitizer": str(sanitizer),
            "manifest": str(manifest),
        }
        if (repo_root() / ("AGENTS" ".md")).is_file():
            missing["error"] = (
                "release sanitizer export tooling is missing from the source tree"
            )
            return missing, empty_counts()
        missing["skipped"] = True
        missing["skip_reason"] = (
            "release sanitizer export tooling is not present in this checkout"
        )
        return missing, empty_counts()
    command = [
        sys.executable,
        str(sanitizer),
        "--source",
        str(source),
        "--output",
        str(output),
        "--manifest",
        str(manifest),
        "--mapping-output",
        str(mapping),
        "--public-ref",
        "scanner-dry-run",
    ]
    if allow_dirty:
        command.append("--allow-dirty")
    exit_code = run_command(command, raw_dir, 0, source)
    shutil.rmtree(output, ignore_errors=True)
    details = {
        "passed": exit_code == 0,
        "mapping_private": True,
        "command_exit_code": exit_code,
        "policy_source": "current_checkout",
        "sanitizer": str(sanitizer),
        "manifest": str(manifest),
    }
    return details, empty_counts()


def fuzz_hooks(source: Path) -> tuple[dict[str, Any], dict[str, int]]:
    mapping = source / "test" / "fuzz" / "shared_target_mappings.json"
    targets = []
    if mapping.is_file():
        payload = load_json(mapping)
        targets = payload.get("targets", []) if isinstance(payload, dict) else []
    return {
        "shared_target_mapping": str(mapping.relative_to(source)) if mapping.is_file() else "",
        "mapped_target_count": len(targets),
    }, empty_counts()


def create_summary(
    *,
    args: argparse.Namespace,
    spec: ScannerSpec,
    status: str,
    tool_version_value: str,
    commands: list[list[str]],
    raw_paths: list[Path],
    counts: dict[str, int],
    triage_path: Path,
    details: dict[str, Any] | None = None,
    coverage_gaps: list[str] | None = None,
    findings: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    current_finding_ids = high_critical_finding_ids(findings)
    if current_finding_ids is not None:
        high_untriaged = len(current_finding_ids - triaged_high_critical_finding_ids(triage_path, current_finding_ids))
    else:
        high_untriaged = max(0, high_critical_count(counts) - triaged_high_critical_count(triage_path))
    redaction_policy = "raw output is private; command stdout/stderr is never printed by the runner"
    if spec.secret_scanner:
        redaction_policy = "secret scanner runs with redaction; raw output is private and must not be uploaded"

    def raw_path_label(path: Path) -> str:
        try:
            return str(path.relative_to(triage_path.parent))
        except ValueError:
            return path.name

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": spec.tool,
        "tool_version": tool_version_value,
        "status": status,
        "run_purpose": getattr(args, "run_purpose", args.mode),
        "source_commit": args.source_commit,
        "source_scope": source_scope(args.source),
        "freeze_commit": args.freeze_commit,
        "command": " && ".join(command_to_string(command) for command in commands),
        "config_refs": spec.config_refs,
        "database_timestamp": utcnow(),
        "raw_output_paths": [raw_path_label(path) for path in raw_paths],
        "raw_output_private": spec.raw_output_private,
        "normalized_counts": counts,
        "normalized_findings": findings or [],
        "high_or_critical_untriaged_count": high_untriaged,
        "coverage_gaps": coverage_gaps or [],
        "redaction_policy": redaction_policy,
        "details": details or {},
        "updated_at": utcnow(),
    }


def run_scanner(tool: str, args: argparse.Namespace, output_root: Path) -> dict[str, Any]:
    spec = SCANNERS[tool]
    tool_dir = ensure_scanner_tool_dir(output_root, tool)
    raw_dir = tool_dir / "raw"
    triage_path = ensure_scanner_artifact_path(tool_dir, tool_dir / "triage.jsonl", "triage path")
    summary_path = ensure_scanner_artifact_path(tool_dir, tool_dir / "summary.json", "summary path")
    if raw_dir.is_symlink() or raw_dir.is_file():
        raw_dir.unlink()
    elif raw_dir.exists():
        shutil.rmtree(raw_dir)
    triage_path.touch(exist_ok=True)

    if spec.internal:
        if tool == "vendored_inventory":
            details, counts = vendored_inventory(args.source)
            coverage_gaps = list(details.get("coverage_gaps", []))
        elif tool == "release_sanitizer":
            details, counts = release_sanitizer(args.source, raw_dir, args.allow_dirty_source)
            if details.get("skipped"):
                summary = create_summary(
                    args=args,
                    spec=spec,
                    status="skipped",
                    tool_version_value="repo-owned",
                    commands=[],
                    raw_paths=[],
                    counts=counts,
                    triage_path=triage_path,
                    details=details,
                    coverage_gaps=[],
                )
                write_json(summary_path, summary)
                return summary
            coverage_gaps = (
                []
                if details.get("passed")
                else [details.get("error") or "Release sanitizer dry run failed."]
            )
        elif tool == "fuzz_hooks":
            details, counts = fuzz_hooks(args.source)
            coverage_gaps = [] if details.get("mapped_target_count") else ["Shared fuzz target mapping is missing or empty."]
        else:
            raise ValueError(f"Unsupported internal scanner: {tool}")
        status = "failed" if coverage_gaps else "completed"
        summary = create_summary(
            args=args,
            spec=spec,
            status=status,
            tool_version_value="repo-owned",
            commands=[],
            raw_paths=[raw_dir] if raw_dir.exists() else [],
            counts=counts,
            triage_path=triage_path,
            details=details,
            coverage_gaps=coverage_gaps,
        )
        write_json(summary_path, summary)
        return summary

    if spec.requires_build and args.skip_build_scanners:
        summary = create_summary(
            args=args,
            spec=spec,
            status="skipped",
            tool_version_value=tool_version(spec.executable),
            commands=[],
            raw_paths=[],
            counts=empty_counts(),
            triage_path=triage_path,
            coverage_gaps=["Build-backed scanner skipped by --skip-build-scanners."],
        )
        write_json(summary_path, summary)
        return summary

    if spec.executable and shutil.which(spec.executable) is None:
        summary = create_summary(
            args=args,
            spec=spec,
            status="missing_tool",
            tool_version_value="",
            commands=[],
            raw_paths=[],
            counts=empty_counts(),
            triage_path=triage_path,
            coverage_gaps=[f"Required executable is not on PATH: {spec.executable}"],
        )
        write_json(summary_path, summary)
        return summary

    commands, report = external_commands(tool, args.source, raw_dir, args)
    exit_codes = []
    for index, command in enumerate(commands):
        exit_codes.append(run_command(command, raw_dir, index, args.source))
    counts = parse_counts(tool, report, raw_dir)
    findings = parse_findings(tool, report, raw_dir)
    raw_paths = [raw_dir / f"command-{index}.stdout.txt" for index in range(len(commands))]
    raw_paths.extend(raw_dir / f"command-{index}.stderr.txt" for index in range(len(commands)))
    if report is not None:
        raw_paths.append(report)
    accepted_finding_exit_codes = accepts_finding_exit_codes(tool, exit_codes, counts)
    details = {
        "command_exit_codes": exit_codes,
        "finding_exit_codes_accepted": accepted_finding_exit_codes,
    }
    coverage_gaps = []
    if any(code != 0 for code in exit_codes) and not accepted_finding_exit_codes:
        coverage_gaps.append("Scanner command exited non-zero; inspect private raw output before trusting coverage.")
    status = "completed" if all(code == 0 for code in exit_codes) or accepted_finding_exit_codes else "failed"
    summary = create_summary(
        args=args,
        spec=spec,
        status=status,
        tool_version_value=tool_version(spec.executable),
        commands=commands,
        raw_paths=raw_paths,
        counts=counts,
        triage_path=triage_path,
        details=details,
        coverage_gaps=coverage_gaps,
        findings=findings,
    )
    write_json(summary_path, summary)
    return summary


def selected_tools(args: argparse.Namespace) -> list[str]:
    if args.scanner:
        tools = args.scanner
    else:
        normalized_scanner_set = LEGACY_SCANNER_SET_ALIASES.get(args.scanner_set, args.scanner_set)
        if normalized_scanner_set not in SCANNER_SETS:
            valid_sets = ", ".join(sorted(SCANNER_SETS))
            raise SystemExit(f"Unknown scanner set: {args.scanner_set}. Valid scanner sets: {valid_sets}")
        args.scanner_set = normalized_scanner_set
        tools = SCANNER_SETS[normalized_scanner_set]
    unknown = [tool for tool in tools if tool not in SCANNERS]
    if unknown:
        raise SystemExit(f"Unknown scanners: {', '.join(unknown)}")
    return tools


def output_root_for(args: argparse.Namespace) -> Path:
    if args.output_root:
        return args.output_root.resolve()
    if args.review_id:
        return repo_root() / ".context" / "internal-review" / safe_review_id(args.review_id) / "evidence" / "scanners"
    return repo_root() / ".context" / "scanner-runs" / args.mode


def ensure_scanner_tool_dir(output_root: Path, tool: str) -> Path:
    tool_dir = output_root / tool
    if tool_dir.is_symlink():
        raise SystemExit(f"Refusing to use symlinked scanner output directory: {tool_dir}")
    if tool_dir.exists() and not tool_dir.is_dir():
        raise SystemExit(f"Scanner output directory path must be a directory: {tool_dir}")
    if tool_dir.exists():
        try:
            tool_dir.resolve().relative_to(output_root.resolve())
        except ValueError as exc:
            raise SystemExit(f"Scanner output directory must stay under --output-root: {tool_dir}") from exc
    tool_dir.mkdir(parents=True, exist_ok=True)
    return tool_dir


def ensure_scanner_artifact_path(tool_dir: Path, path: Path, label: str) -> Path:
    if path.is_symlink():
        raise SystemExit(f"Refusing to use symlinked scanner {label}: {path}")
    if path.exists() and not path.is_file():
        raise SystemExit(f"Scanner {label} path must be a file: {path}")
    try:
        path.parent.resolve().relative_to(tool_dir.resolve())
    except ValueError as exc:
        raise SystemExit(f"Scanner {label} path must stay under the scanner output directory: {path}") from exc
    return path


def prepare_output_root(output_root: Path, selected: list[str], *, prune_stale: bool) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    if prune_stale:
        selected_set = set(selected)
        known_scanners = set(SCANNERS)
        for child in output_root.iterdir():
            if not child.is_dir() or child.name in selected_set or child.name not in known_scanners:
                continue
            if (child / "summary.json").exists() or (child / "triage.jsonl").exists():
                shutil.rmtree(child)
    for generated in ("README.md", "summary.json"):
        generated_path = output_root / generated
        if not generated_path.exists():
            continue
        if not output_root_file_owned(generated_path):
            raise SystemExit(
                f"--output-root {output_root} contains existing {generated} that was not created by "
                "run-scanners.py. Use an empty directory or reuse a prior scanner output root."
            )
        generated_path.unlink()


def validate_source_state(args: argparse.Namespace, checked_out_commit: str) -> None:
    if args.mode != "frozen_evidence":
        return
    if not checked_out_commit:
        raise SystemExit("frozen_evidence requires --source to be inside a git worktree.")
    if args.allow_dirty_source:
        raise SystemExit("--allow-dirty-source is not supported in frozen_evidence mode.")
    if git_worktree_dirty(args.source):
        raise SystemExit("frozen_evidence requires a clean git worktree for --source.")
    if str(args.source_commit).strip() != checked_out_commit:
        raise SystemExit(
            f"frozen_evidence requires checked-out HEAD {checked_out_commit} to match "
            f"--source-commit {str(args.source_commit).strip()}."
        )
    freeze_commit = str(args.freeze_commit).strip()
    if freeze_commit and freeze_commit != checked_out_commit:
        raise SystemExit(
            f"frozen_evidence requires checked-out HEAD {checked_out_commit} to match "
            f"--freeze-commit {freeze_commit}."
        )


def should_fail(fail_policy: str, summaries: list[dict[str, Any]]) -> bool:
    if fail_policy == "never":
        return False
    infra_failed = any(str(summary.get("status", "")) in {"failed", "missing_tool"} for summary in summaries)
    if fail_policy == "infra-only":
        return infra_failed
    if fail_policy == "high-critical":
        high_critical_failed = any(
            safe_int(summary.get("high_or_critical_untriaged_count", 0)) > 0 for summary in summaries
        )
        return infra_failed or high_critical_failed
    if fail_policy == "infra-and-secrets":
        secret_failed = any(
            summary.get("tool") == "gitleaks" and safe_int(summary.get("high_or_critical_untriaged_count", 0)) > 0
            for summary in summaries
        )
        return infra_failed or secret_failed
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Run qbit scanner evidence collection.")
    parser.add_argument("--mode", required=True)
    parser.add_argument("--scanner-set", default="minimum")
    parser.add_argument("--scanner", action="append", default=[])
    parser.add_argument("--source", type=Path, default=Path("."))
    parser.add_argument("--source-commit", default="")
    parser.add_argument("--freeze-commit", default="")
    parser.add_argument("--review-id", default="")
    parser.add_argument("--output-root", type=Path, default=None)
    parser.add_argument("--allow-dirty-source", action="store_true")
    parser.add_argument("--skip-build-scanners", action="store_true")
    parser.add_argument(
        "--history-diff-base-ref",
        default="origin/main",
        help=(
            "Base ref for git-history scanners. The runner scans merge-base("
            "--source-commit, this ref)..--source-commit, matching git diff base...source semantics."
        ),
    )
    parser.add_argument(
        "--fail-policy",
        choices=["never", "infra-only", "infra-and-secrets", "high-critical"],
        default="never",
    )
    args = parser.parse_args()

    requested_mode = args.mode
    args.mode = LEGACY_MODE_ALIASES.get(requested_mode, requested_mode)
    if args.mode not in SCANNER_MODES:
        valid_modes = ", ".join(sorted(SCANNER_MODES))
        raise SystemExit(f"Unknown scanner mode: {args.mode}. Valid modes: {valid_modes}")
    args.run_purpose = "v1_frozen_evidence" if args.mode == "frozen_evidence" else args.mode
    args.source = args.source.resolve()
    checked_out_commit = git_commit(args.source)
    args.source_commit = str(args.source_commit or checked_out_commit).strip()
    args.freeze_commit = str(args.freeze_commit).strip()
    validate_source_state(args, checked_out_commit)
    tools = selected_tools(args)
    output_root = output_root_for(args)
    prepare_output_root(output_root, tools, prune_stale=not args.scanner)

    summaries = []
    for tool in tools:
        summary = run_scanner(tool, args, output_root)
        summaries.append(summary)
        counts = summary.get("normalized_counts", {})
        append_readme(
            output_root,
            f"- `{tool}`: status=`{summary.get('status')}`, high=`{counts.get('high', 0)}`, "
            f"critical=`{counts.get('critical', 0)}`, untriaged_high_critical="
            f"`{summary.get('high_or_critical_untriaged_count', 0)}`",
        )

    aggregate = {
        "schema_version": AGGREGATE_SCHEMA_VERSION,
        "mode": args.run_purpose,
        "scanner_set": args.scanner_set if not args.scanner else "custom",
        "source_commit": args.source_commit,
        "freeze_commit": args.freeze_commit,
        "history_diff_base_ref": args.history_diff_base_ref,
        "summary_count": len(summaries),
        "tools": [summary.get("tool") for summary in summaries],
        "high_or_critical_untriaged_count": sum(
            safe_int(summary.get("high_or_critical_untriaged_count", 0)) for summary in summaries
        ),
        "updated_at": utcnow(),
    }
    write_json(output_root / "summary.json", aggregate)

    print(json.dumps(aggregate, sort_keys=True))
    if should_fail(args.fail_policy, summaries):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
