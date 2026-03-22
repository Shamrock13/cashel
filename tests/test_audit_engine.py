"""Tests for audit_engine.py — shared utilities used across all vendors.

Run with:  python3 tests/test_audit_engine.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import flintlock.audit_engine as engine

TESTS_DIR = os.path.dirname(__file__)


def _write_tmp(content, suffix=".txt"):
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    tf.write(content)
    tf.flush()
    tf.close()
    return tf.name


def _msgs(findings):
    return [engine._finding_msg(f) for f in findings]


# ── _f helper tests ───────────────────────────────────────────────────────────

def test_f_returns_dict():
    f = engine._f("HIGH", "exposure", "Test message", "Fix it")
    assert isinstance(f, dict), f"Expected dict: {f}"
    assert f["severity"]    == "HIGH"
    assert f["category"]    == "exposure"
    assert f["message"]     == "Test message"
    assert f["remediation"] == "Fix it"
    print("  PASS  test_f_returns_dict")


def test_f_default_remediation():
    f = engine._f("MEDIUM", "hygiene", "No remediation")
    assert f["remediation"] == ""
    print("  PASS  test_f_default_remediation")


# ── _finding_msg tests ────────────────────────────────────────────────────────

def test_finding_msg_dict():
    f = engine._f("HIGH", "exposure", "A message", "Remediation")
    assert engine._finding_msg(f) == "A message"
    print("  PASS  test_finding_msg_dict")


def test_finding_msg_string():
    assert engine._finding_msg("plain string") == "plain string"
    print("  PASS  test_finding_msg_string")


# ── _findings_to_strings tests ────────────────────────────────────────────────

def test_findings_to_strings_mixed():
    findings = [
        engine._f("HIGH", "exposure", "msg one"),
        "msg two",
        engine._f("MEDIUM", "logging", "msg three"),
    ]
    result = engine._findings_to_strings(findings)
    assert result == ["msg one", "msg two", "msg three"], f"Unexpected: {result}"
    print("  PASS  test_findings_to_strings_mixed")


# ── _build_summary tests ──────────────────────────────────────────────────────

def test_build_summary_counts():
    findings = [
        engine._f("HIGH", "exposure", "[HIGH] Bad rule 1"),
        engine._f("HIGH", "exposure", "[HIGH] Bad rule 2"),
        engine._f("MEDIUM", "logging", "[MEDIUM] Missing log"),
        engine._f("HIGH", "compliance", "[SOC2-HIGH] Compliance finding"),
    ]
    s = engine._build_summary(findings)
    assert s["high"]   == 2, f"Expected 2 high (compliance excluded): {s['high']}"
    assert s["medium"] == 1, f"Expected 1 medium: {s['medium']}"
    assert s["total"]  == 4, f"Expected 4 total: {s['total']}"
    assert s["soc2_high"] == 1, f"Expected 1 soc2_high: {s['soc2_high']}"
    print("  PASS  test_build_summary_counts")


def test_build_summary_score_perfect():
    s = engine._build_summary([])
    assert s["score"] == 100, f"Empty findings should yield score 100: {s['score']}"
    print("  PASS  test_build_summary_score_perfect")


def test_build_summary_score_deductions():
    """Score = 100 - HIGH*10 - MEDIUM*3, min 0."""
    findings = [
        engine._f("HIGH", "e", "[HIGH] H1"),
        engine._f("HIGH", "e", "[HIGH] H2"),
        engine._f("MEDIUM", "l", "[MEDIUM] M1"),
    ]
    s = engine._build_summary(findings)
    expected = max(0, 100 - 2*10 - 1*3)  # 77
    assert s["score"] == expected, f"Expected score {expected}: {s['score']}"
    print(f"  PASS  test_build_summary_score_deductions — score={s['score']}")


def test_build_summary_score_minimum_zero():
    """Score should never go below 0."""
    findings = [engine._f("HIGH", "e", f"[HIGH] H{i}") for i in range(20)]
    s = engine._build_summary(findings)
    assert s["score"] == 0, f"Score should be floored at 0: {s['score']}"
    print("  PASS  test_build_summary_score_minimum_zero")


def test_build_summary_compliance_not_in_main_counts():
    """Compliance findings should not count toward high/medium."""
    findings = [
        engine._f("HIGH", "compliance", "[PCI-HIGH] PCI finding"),
        engine._f("MEDIUM", "compliance", "[NIST-MEDIUM] NIST finding"),
        engine._f("HIGH", "compliance", "[STIG-CAT-I] STIG finding"),
    ]
    s = engine._build_summary(findings)
    assert s["high"]   == 0, f"Compliance HIGH should not count toward high: {s['high']}"
    assert s["medium"] == 0, f"Compliance MEDIUM should not count toward medium: {s['medium']}"
    assert s["pci_high"]  == 1
    assert s["nist_medium"] == 1
    assert s["stig_cat_i"] == 1
    print("  PASS  test_build_summary_compliance_not_in_main_counts")


def test_build_summary_all_fields_present():
    s = engine._build_summary([])
    expected_keys = {
        "high", "medium", "pci_high", "pci_medium", "cis_high", "cis_medium",
        "nist_high", "nist_medium", "hipaa_high", "hipaa_medium",
        "soc2_high", "soc2_medium", "stig_cat_i", "stig_cat_ii", "stig_cat_iii",
        "total", "score",
    }
    for key in expected_keys:
        assert key in s, f"Summary missing key '{key}'"
    print("  PASS  test_build_summary_all_fields_present")


# ── _sort_findings tests ──────────────────────────────────────────────────────

def test_sort_findings_high_before_medium():
    findings = [
        engine._f("MEDIUM", "l", "[MEDIUM] Medium first"),
        engine._f("HIGH",   "e", "[HIGH] High second"),
    ]
    result = engine._sort_findings(findings)
    assert result[0]["severity"] == "HIGH", f"HIGH should sort before MEDIUM: {result}"
    print("  PASS  test_sort_findings_high_before_medium")


def test_sort_findings_compliance_after_core():
    """Core HIGH/MEDIUM findings should sort before compliance findings."""
    findings = [
        engine._f("HIGH", "compliance", "[SOC2-HIGH] Compliance first in list"),
        engine._f("HIGH", "exposure",   "[HIGH] Core finding"),
    ]
    result = engine._sort_findings(findings)
    assert "[HIGH] Core finding" in result[0]["message"], \
        f"Core HIGH should sort before compliance HIGH: {result[0]['message']}"
    print("  PASS  test_sort_findings_compliance_after_core")


def test_sort_findings_stable_empty():
    assert engine._sort_findings([]) == []
    print("  PASS  test_sort_findings_stable_empty")


# ── _wrap_compliance tests ────────────────────────────────────────────────────

def test_wrap_compliance_string_high():
    result = engine._wrap_compliance("[HIGH] something bad")
    assert result["severity"] == "HIGH"
    assert result["category"] == "compliance"
    assert result["message"] == "[HIGH] something bad"
    print("  PASS  test_wrap_compliance_string_high")


def test_wrap_compliance_string_medium():
    result = engine._wrap_compliance("[MEDIUM] something medium")
    assert result["severity"] == "MEDIUM"
    print("  PASS  test_wrap_compliance_string_medium")


def test_wrap_compliance_dict_passthrough():
    d = engine._f("HIGH", "exposure", "already a dict")
    result = engine._wrap_compliance(d)
    assert result is d, "Dict should be returned as-is"
    print("  PASS  test_wrap_compliance_dict_passthrough")


# ── _audit_asa tests ──────────────────────────────────────────────────────────

CLEAN_ASA = """\
hostname asa-clean
ssh version 2
logging host management 10.0.1.100
access-list OUTSIDE_IN extended permit tcp any host 10.0.0.10 eq 443 log
access-list OUTSIDE_IN extended deny ip any any log
"""

RISKY_ASA = """\
hostname asa-risky
telnet 0.0.0.0 0.0.0.0 outside
access-list OUTSIDE_IN extended permit ip any any
access-list OUTSIDE_IN extended permit icmp any any
"""


def test_audit_asa_returns_tuple():
    path = _write_tmp(RISKY_ASA)
    result = engine._audit_asa(path)
    assert isinstance(result, tuple), f"Expected tuple: {type(result)}"
    assert len(result) == 2, f"Expected 2-tuple: {len(result)}"
    findings, parse = result
    assert isinstance(findings, list)
    print("  PASS  test_audit_asa_returns_tuple")


def test_audit_asa_risky_findings():
    path = _write_tmp(RISKY_ASA)
    findings, _ = engine._audit_asa(path)
    msgs = [engine._finding_msg(f) for f in findings]
    assert len(findings) >= 3, f"Expected ≥3 findings on risky ASA: {msgs}"
    severities = {f["severity"] for f in findings}
    assert "HIGH" in severities
    print(f"  PASS  test_audit_asa_risky_findings — {len(findings)} findings")


def test_audit_asa_clean_no_high():
    path = _write_tmp(CLEAN_ASA)
    findings, _ = engine._audit_asa(path)
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) == 0, f"Clean ASA config should not have HIGH findings: {high}"
    print(f"  PASS  test_audit_asa_clean_no_high — {len(findings)} findings total")


def test_audit_asa_fixture():
    """Audit the shared ASA fixture file."""
    path = os.path.join(TESTS_DIR, "test_asa.txt")
    findings, parse = engine._audit_asa(path)
    assert len(findings) >= 1
    msgs = [engine._finding_msg(f) for f in findings]
    # Fixture has telnet, ssh version 1, snmp community, permit ip any any, icmp any any
    assert any("telnet" in m.lower() or "Telnet" in m for m in msgs)
    print(f"  PASS  test_audit_asa_fixture — {len(findings)} findings")


# ── run_vendor_audit dispatch tests ──────────────────────────────────────────

def test_run_vendor_audit_asa():
    path = _write_tmp(RISKY_ASA)
    findings, parse, extra = engine.run_vendor_audit("asa", path)
    assert isinstance(findings, list)
    assert extra is None
    print(f"  PASS  test_run_vendor_audit_asa — {len(findings)} findings")


def test_run_vendor_audit_unknown_vendor():
    try:
        engine.run_vendor_audit("vendor-does-not-exist", "/tmp/fake")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Unknown vendor" in str(e)
    print("  PASS  test_run_vendor_audit_unknown_vendor")


def test_run_vendor_audit_iptables():
    config = """\
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -j DROP
COMMIT
"""
    path = _write_tmp(config)
    findings, parse, extra = engine.run_vendor_audit("iptables", path)
    assert isinstance(findings, list)
    print(f"  PASS  test_run_vendor_audit_iptables — {len(findings)} findings")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n── Audit Engine Tests ──\n")
    failures = 0
    tests = [
        test_f_returns_dict, test_f_default_remediation,
        test_finding_msg_dict, test_finding_msg_string,
        test_findings_to_strings_mixed,
        test_build_summary_counts, test_build_summary_score_perfect,
        test_build_summary_score_deductions, test_build_summary_score_minimum_zero,
        test_build_summary_compliance_not_in_main_counts,
        test_build_summary_all_fields_present,
        test_sort_findings_high_before_medium, test_sort_findings_compliance_after_core,
        test_sort_findings_stable_empty,
        test_wrap_compliance_string_high, test_wrap_compliance_string_medium,
        test_wrap_compliance_dict_passthrough,
        test_audit_asa_returns_tuple, test_audit_asa_risky_findings,
        test_audit_asa_clean_no_high, test_audit_asa_fixture,
        test_run_vendor_audit_asa, test_run_vendor_audit_unknown_vendor,
        test_run_vendor_audit_iptables,
    ]
    for fn in tests:
        try:
            fn()
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
            failures += 1
        except Exception as e:
            print(f"  ERROR {fn.__name__}: {type(e).__name__}: {e}")
            failures += 1

    print(f"\n{'All tests passed.' if failures == 0 else f'{failures} test(s) failed.'}\n")
    sys.exit(failures)
