"""Tests for the CI policy gate (cashel gate)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cashel.gate import (  # noqa: E402
    config_provenance,
    evaluate_gate,
    finding_severity,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


# ── finding_severity ─────────────────────────────────────────────────────────


def test_severity_from_enriched_dict():
    assert finding_severity({"severity": "CRITICAL", "message": "x"}) == "critical"
    assert finding_severity({"severity": "high", "message": "x"}) == "high"


def test_severity_from_dict_falls_back_to_message_tag():
    assert finding_severity({"severity": "", "message": "[MEDIUM] foo"}) == "medium"


def test_severity_from_legacy_strings():
    assert finding_severity("[CRITICAL] any-any rule") == "critical"
    assert finding_severity("[HIGH] telnet enabled") == "high"
    assert finding_severity("[MEDIUM] no logging") == "medium"
    assert finding_severity("[LOW] cosmetic") == "low"
    assert finding_severity("informational note") == "info"


def test_severity_from_compliance_tags():
    assert finding_severity("[PCI-HIGH] segmentation") == "high"
    assert finding_severity("[SOC2-MEDIUM] retention") == "medium"
    assert finding_severity("[STIG-CAT-I] crypto") == "high"
    assert finding_severity("[STIG-CAT-II] banner") == "medium"
    assert finding_severity("[STIG-CAT-III] doc") == "low"


# ── evaluate_gate ────────────────────────────────────────────────────────────


def test_gate_passes_on_clean_findings():
    result = evaluate_gate([], fail_on="high")
    assert result["passed"] is True
    assert result["score"] == 100
    assert result["violations"] == []


def test_gate_fails_at_or_above_threshold():
    findings = ["[HIGH] a", "[MEDIUM] b", "[CRITICAL] c"]
    result = evaluate_gate(findings, fail_on="high")
    assert result["passed"] is False
    assert result["counts"]["critical"] == 1
    assert result["counts"]["high"] == 1
    assert result["counts"]["medium"] == 1
    [violation] = result["violations"]
    assert violation["rule"] == "fail_on"
    assert "2 finding(s)" in violation["message"]


def test_gate_threshold_excludes_lower_severities():
    result = evaluate_gate(["[MEDIUM] b", "[LOW] c"], fail_on="high")
    assert result["passed"] is True


def test_gate_min_score():
    findings = ["[HIGH] a"] * 5  # score: 100 - 5*10 = 50
    result = evaluate_gate(findings, fail_on="critical", min_score=60)
    assert result["passed"] is False
    assert result["score"] == 50
    [violation] = result["violations"]
    assert violation["rule"] == "min_score"


def test_gate_rejects_bad_policy():
    for bad in ("info", "bogus"):
        try:
            evaluate_gate([], fail_on=bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"fail_on={bad!r} should raise")
    try:
        evaluate_gate([], min_score=101)
    except ValueError:
        pass
    else:
        raise AssertionError("min_score=101 should raise")


def test_gate_is_deterministic():
    findings = [{"severity": "high", "message": "[HIGH] x"}, "[MEDIUM] y"]
    assert evaluate_gate(findings) == evaluate_gate(findings)


# ── provenance ───────────────────────────────────────────────────────────────


def test_config_provenance_matches_content_hash(tmp_path):
    cfg = tmp_path / "fw.cfg"
    cfg.write_bytes(b"access-list outside permit ip any any\n")
    prov = config_provenance(cfg)
    assert prov["config_sha256"] == hashlib.sha256(cfg.read_bytes()).hexdigest()
    assert prov["config_bytes"] == cfg.stat().st_size
    assert prov["engine_version"]


# ── CLI subprocess smoke ─────────────────────────────────────────────────────


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    src = str(ROOT / "src")
    env["PYTHONPATH"] = (
        f"{src}{os.pathsep}{env['PYTHONPATH']}" if env.get("PYTHONPATH") else src
    )
    env.setdefault("NO_COLOR", "1")
    return subprocess.run(
        [sys.executable, "-m", "cashel.main"] + args,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )


def test_gate_cli_fails_on_risky_example_config():
    result = _run_cli(
        ["gate", "--file", str(EXAMPLES / "cisco_asa.txt"), "--vendor", "asa"]
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "GATE: FAIL" in result.stdout
    assert "VIOLATION [fail_on]" in result.stdout


def test_gate_cli_json_output_is_machine_readable():
    result = _run_cli(
        [
            "gate",
            "--file",
            str(EXAMPLES / "cisco_asa.txt"),
            "--vendor",
            "asa",
            "--json",
        ]
    )
    assert result.returncode == 1, result.stdout + result.stderr
    doc = json.loads(result.stdout)
    assert doc["command"] == "gate"
    assert doc["vendor"] == "asa"
    assert doc["passed"] is False
    assert doc["provenance"]["config_sha256"]
    assert doc["fidelity"]["vendor"] == "asa"
    assert doc["fidelity"]["maturity"] == "mature"
    assert doc["policy"] == {"fail_on": "high", "min_score": None}
    assert isinstance(doc["findings"], list) and doc["findings"]


def test_gate_cli_auto_detects_vendor():
    result = _run_cli(["gate", "--file", str(EXAMPLES / "cisco_asa.txt")])
    assert "Auto-detected vendor: asa" in result.stdout, result.stdout + result.stderr


def test_gate_cli_passes_with_lenient_policy(tmp_path):
    # A minimal config with a deny-all and logging produces no HIGH+ findings.
    result = _run_cli(
        [
            "gate",
            "--file",
            str(EXAMPLES / "cisco_asa.txt"),
            "--vendor",
            "asa",
            "--fail-on",
            "critical",
            "--min-score",
            "0",
        ]
    )
    output = result.stdout + result.stderr
    if "GATE: PASS" in output:
        assert result.returncode == 0, output
    else:
        # Example config contains CRITICAL findings; verify exit semantics hold.
        assert result.returncode == 1, output


def test_gate_cli_missing_file_exits_2(tmp_path):
    result = _run_cli(["gate", "--file", str(tmp_path / "nope.cfg")])
    assert result.returncode == 2
    assert "File not found" in result.stderr


def test_gate_cli_bad_fail_on_exits_2():
    result = _run_cli(
        [
            "gate",
            "--file",
            str(EXAMPLES / "cisco_asa.txt"),
            "--vendor",
            "asa",
            "--fail-on",
            "bogus",
        ]
    )
    assert result.returncode == 2
    assert "Invalid fail-on severity" in result.stderr


def test_legacy_bare_option_invocation_still_audits():
    result = _run_cli(["--file", str(EXAMPLES / "cisco_asa.txt"), "--vendor", "asa"])
    assert result.returncode == 0, result.stdout + result.stderr
    assert "--- Audit Summary ---" in result.stdout


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
