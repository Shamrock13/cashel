"""CI policy gate — deterministic pass/fail evaluation of audit findings.

Pure logic, no Flask dependency. Designed for pipeline use:
`cashel gate --file fw.cfg --fail-on high --min-score 70 --json`

Every gate result carries provenance (config SHA256, engine version,
timestamp) so a verdict can be reproduced bit-for-bit from the same input.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .audit_engine import _build_summary
from .export import TOOL_NAME, TOOL_VERSION

# Severity ranks: higher number = more severe. "info" never trips a gate.
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Legacy string-finding tags mapped to normalized severities, checked in order.
_LEGACY_TAGS = [
    ("[CRITICAL]", "critical"),
    ("[HIGH]", "high"),
    ("[MEDIUM]", "medium"),
    ("[LOW]", "low"),
    ("STIG-CAT-I]", "high"),
    ("STIG-CAT-II]", "medium"),
    ("STIG-CAT-III]", "low"),
    ("-HIGH]", "high"),
    ("-MEDIUM]", "medium"),
    ("-LOW]", "low"),
]


def finding_severity(finding) -> str:
    """Normalized severity for either enriched dict or legacy string findings."""
    if isinstance(finding, dict):
        sev = str(finding.get("severity") or "").strip().lower()
        if sev in SEVERITY_ORDER:
            return sev
        finding = str(finding.get("message") or "")
    msg = str(finding)
    for tag, sev in _LEGACY_TAGS:
        if tag in msg:
            return sev
    return "info"


def config_provenance(path: str | Path) -> dict:
    """Content hash + size for the audited config — the reproducibility anchor."""
    data = Path(path).read_bytes()
    return {
        "config_sha256": hashlib.sha256(data).hexdigest(),
        "config_bytes": len(data),
        "engine_version": TOOL_VERSION,
    }


def evaluate_gate(
    findings: list,
    *,
    fail_on: str = "high",
    min_score: int | None = None,
) -> dict:
    """Evaluate findings against a gate policy.

    Returns a dict with: passed, score, counts (per severity), violations
    (each with a machine-readable rule and human message), and the policy
    that was applied. Deterministic: same findings + policy => same result.
    """
    fail_on = fail_on.strip().lower()
    if fail_on not in SEVERITY_ORDER or fail_on == "info":
        raise ValueError(
            f"Invalid fail-on severity: {fail_on!r}. Use: critical, high, medium, low"
        )
    if min_score is not None and not 0 <= min_score <= 100:
        raise ValueError(f"min-score must be 0-100, got {min_score}")

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[finding_severity(f)] += 1

    score = _build_summary(findings)["score"]
    threshold = SEVERITY_ORDER[fail_on]
    violations = []

    tripped = {
        sev: n for sev, n in counts.items() if n and SEVERITY_ORDER[sev] >= threshold
    }
    if tripped:
        breakdown = ", ".join(
            f"{tripped[s]} {s}"
            for s in sorted(tripped, key=SEVERITY_ORDER.get, reverse=True)
        )
        violations.append(
            {
                "rule": "fail_on",
                "message": (
                    f"{sum(tripped.values())} finding(s) at or above "
                    f"{fail_on.upper()} severity ({breakdown})"
                ),
            }
        )
    if min_score is not None and score < min_score:
        violations.append(
            {
                "rule": "min_score",
                "message": f"Score {score} is below required minimum {min_score}",
            }
        )

    return {
        "passed": not violations,
        "score": score,
        "counts": counts,
        "violations": violations,
        "policy": {"fail_on": fail_on, "min_score": min_score},
    }


def build_gate_document(
    result: dict,
    findings: list,
    *,
    file: str,
    vendor: str,
    compliance: str | None,
) -> dict:
    """Full machine-readable gate document for --json output and CI artifacts."""
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "command": "gate",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file": file,
        "vendor": vendor,
        "compliance": compliance,
        "provenance": config_provenance(file),
        **result,
        "findings": findings,
    }
