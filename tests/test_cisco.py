"""Tests for Cisco ASA and FTD parser/auditor.

Both the ASA and FTD are Cisco products.  The ASA audit helpers live in
audit_engine.py; FTD-specific checks (ACP, IPS, threat-detection, SSL) live in
ftd.py.  The LINA CLI syntax (access-list, ssh, telnet, snmp-server …) is
shared between them.

Run with:  python3 tests/test_cisco.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ciscoconfparse import CiscoConfParse
import flintlock.audit_engine as asa_engine
import flintlock.ftd as ftd_module

TESTS_DIR = os.path.dirname(__file__)

# ── helpers ───────────────────────────────────────────────────────────────────

def _msgs(findings):
    return [f["message"] for f in findings]


def _write_tmp(content):
    """Write content to a temp file and return its path."""
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tf.write(content)
    tf.flush()
    tf.close()
    return tf.name


def _parse(content):
    path = _write_tmp(content)
    return CiscoConfParse(path, ignore_blank_lines=False)


# ── Cisco ASA config samples ──────────────────────────────────────────────────

CLEAN_ASA = """\
hostname asa-fw-prod
domain-name corp.example.com
ssh version 2
ssh 10.0.0.0 255.255.0.0 management
logging enable
logging host management 10.0.1.100
logging trap informational
access-list OUTSIDE_IN extended permit tcp any host 10.0.0.10 eq 443 log
access-list OUTSIDE_IN extended permit tcp 192.168.1.0 255.255.255.0 host 10.0.0.20 eq 22 log
access-list OUTSIDE_IN extended deny ip any any log
access-list INSIDE_OUT extended permit ip 10.0.0.0 255.255.0.0 any log
access-list INSIDE_OUT extended deny ip any any log
"""

RISKY_ASA = """\
hostname asa-risky
telnet 0.0.0.0 0.0.0.0 outside
ssh version 1
snmp-server community public
access-list OUTSIDE_IN extended permit ip any any
access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 80
access-list OUTSIDE_IN extended permit icmp any any
access-list INSIDE_OUT extended permit ip any any
access-list INSIDE_OUT extended permit ip any any
"""

REDUNDANT_ASA = """\
hostname asa-redundant
ssh version 2
logging host management 10.0.1.100
access-list OUTSIDE_IN extended permit tcp 10.0.0.0 255.255.255.0 host 10.0.0.50 eq 443 log
access-list OUTSIDE_IN extended permit tcp 10.0.0.0 255.255.255.0 host 10.0.0.50 eq 443 log
access-list OUTSIDE_IN extended deny ip any any log
"""

# ── Cisco FTD config samples ──────────────────────────────────────────────────

CLEAN_FTD = """\
hostname ftd-fw-prod
access-control-policy Default_ACP
threat-detection basic-threat
threat-detection statistics
intrusion-policy Balanced_Security_and_Connectivity
ssl trust-point OUTSIDE_CERT
ssh version 2
logging host management 10.0.1.100
access-list OUTSIDE_IN extended permit tcp any host 10.0.0.10 eq 443 log
access-list OUTSIDE_IN extended deny ip any any log
"""

RISKY_FTD = """\
hostname ftd-risky
telnet 0.0.0.0 0.0.0.0 outside
snmp-server community public
http server enable
access-list OUTSIDE_IN extended permit ip any any
access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 80
access-list OUTSIDE_IN extended permit icmp any any
"""

FTD_MARKER_PRESENT = """\
hostname ftd-detect
firepower threat defense
access-control-policy Default_ACP
"""

FTD_MARKER_ABSENT = """\
hostname asa-plain
access-list OUTSIDE_IN extended permit ip any any
"""

FTD_SNORT = """\
hostname ftd-snort
snort enabled
threat-detection basic-threat
access-control-policy Default_ACP
ssh version 2
logging host management 10.0.1.100
access-list OUTSIDE_IN extended permit tcp any host 10.0.0.10 eq 443 log
access-list OUTSIDE_IN extended deny ip any any log
"""

# ── ASA check tests ───────────────────────────────────────────────────────────

def test_asa_any_any_detects():
    parse = _parse(RISKY_ASA)
    findings = asa_engine._check_any_any(parse)
    msgs = _msgs(findings)
    assert len(findings) >= 2, f"Expected ≥2 any-any findings, got {len(findings)}: {msgs}"
    assert all("[HIGH]" in m for m in msgs)
    assert all("Overly permissive" in m for m in msgs)
    print(f"  PASS  test_asa_any_any_detects — {len(findings)} findings")


def test_asa_any_any_clean():
    parse = _parse(CLEAN_ASA)
    findings = asa_engine._check_any_any(parse)
    assert findings == [], f"Expected no any-any findings on clean config, got: {findings}"
    print("  PASS  test_asa_any_any_clean")


def test_asa_missing_logging_detects():
    parse = _parse(RISKY_ASA)
    findings = asa_engine._check_missing_logging(parse)
    msgs = _msgs(findings)
    assert len(findings) >= 1, f"Expected ≥1 missing-log findings: {msgs}"
    assert all("[MEDIUM]" in m for m in msgs)
    print(f"  PASS  test_asa_missing_logging_detects — {len(findings)} findings")


def test_asa_missing_logging_clean():
    parse = _parse(CLEAN_ASA)
    findings = asa_engine._check_missing_logging(parse)
    assert findings == [], f"Expected no missing-log findings: {findings}"
    print("  PASS  test_asa_missing_logging_clean")


def test_asa_deny_all_missing():
    parse = _parse(RISKY_ASA)
    findings = asa_engine._check_deny_all(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 deny-all finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    assert "deny-all" in msgs[0]
    print("  PASS  test_asa_deny_all_missing")


def test_asa_deny_all_present():
    parse = _parse(CLEAN_ASA)
    findings = asa_engine._check_deny_all(parse)
    assert findings == [], f"Expected no deny-all finding on clean config: {findings}"
    print("  PASS  test_asa_deny_all_present")


def test_asa_redundant_rules_detects():
    parse = _parse(REDUNDANT_ASA)
    findings = asa_engine._check_redundant_rules(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 redundant rule finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    assert "Redundant" in msgs[0]
    print("  PASS  test_asa_redundant_rules_detects")


def test_asa_redundant_rules_clean():
    parse = _parse(CLEAN_ASA)
    findings = asa_engine._check_redundant_rules(parse)
    assert findings == [], f"Expected no redundant findings on clean config: {findings}"
    print("  PASS  test_asa_redundant_rules_clean")


def test_asa_telnet_detects():
    parse = _parse(RISKY_ASA)
    findings = asa_engine._check_telnet_asa(parse)
    msgs = _msgs(findings)
    assert len(findings) >= 1, f"Expected ≥1 telnet finding: {msgs}"
    assert all("[MEDIUM]" in m for m in msgs)
    assert all("Telnet" in m for m in msgs)
    print(f"  PASS  test_asa_telnet_detects — {len(findings)} findings")


def test_asa_telnet_clean():
    parse = _parse(CLEAN_ASA)
    findings = asa_engine._check_telnet_asa(parse)
    assert findings == [], f"Expected no telnet findings on clean config: {findings}"
    print("  PASS  test_asa_telnet_clean")


def test_asa_icmp_any_detects():
    parse = _parse(RISKY_ASA)
    findings = asa_engine._check_icmp_any_asa(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 ICMP finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    assert "ICMP" in msgs[0] or "icmp" in msgs[0]
    print("  PASS  test_asa_icmp_any_detects")


def test_asa_icmp_any_clean():
    parse = _parse(CLEAN_ASA)
    findings = asa_engine._check_icmp_any_asa(parse)
    assert findings == [], f"Expected no ICMP findings on clean config: {findings}"
    print("  PASS  test_asa_icmp_any_clean")


def test_asa_full_audit_risky():
    path = _write_tmp(RISKY_ASA)
    findings, parse = asa_engine._audit_asa(path)
    msgs = _msgs(findings)
    assert len(findings) >= 5, f"Expected ≥5 findings on risky ASA config, got {len(findings)}: {msgs}"
    severities = {f["severity"] for f in findings}
    assert "HIGH" in severities, "Risky config should have at least one HIGH finding"
    print(f"  PASS  test_asa_full_audit_risky — {len(findings)} findings")


def test_asa_full_audit_clean():
    path = _write_tmp(CLEAN_ASA)
    findings, parse = asa_engine._audit_asa(path)
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) == 0, f"Clean ASA config should have no HIGH findings: {_msgs(high)}"
    print(f"  PASS  test_asa_full_audit_clean — {len(findings)} findings (no HIGH)")


def test_asa_fixture_file():
    """Audit the shared fixture file used for shadow-rule tests."""
    path = os.path.join(TESTS_DIR, "test_asa.txt")
    findings, parse = asa_engine._audit_asa(path)
    msgs = _msgs(findings)
    assert len(findings) >= 1, f"Expected findings from ASA fixture: {msgs}"
    # The fixture has: telnet, ssh version 1, snmp community, permit ip any any, icmp any any
    assert any("Telnet" in m or "telnet" in m for m in msgs), "Should detect telnet"
    print(f"  PASS  test_asa_fixture_file — {len(findings)} findings")


# ── FTD detection tests ───────────────────────────────────────────────────────

def test_ftd_is_ftd_config_true():
    assert ftd_module.is_ftd_config(FTD_MARKER_PRESENT), "Should detect FTD markers"
    assert ftd_module.is_ftd_config(FTD_SNORT), "Should detect snort marker"
    print("  PASS  test_ftd_is_ftd_config_true")


def test_ftd_is_ftd_config_false():
    assert not ftd_module.is_ftd_config(FTD_MARKER_ABSENT), "Should not detect FTD markers in plain ASA config"
    assert not ftd_module.is_ftd_config(CLEAN_ASA), "Should not detect FTD markers in clean ASA"
    print("  PASS  test_ftd_is_ftd_config_false")


# ── FTD check tests ───────────────────────────────────────────────────────────

def test_ftd_no_access_control_policy():
    path = _write_tmp(RISKY_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_access_control_policy(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 ACP finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    assert "access-control-policy" in msgs[0]
    print("  PASS  test_ftd_no_access_control_policy")


def test_ftd_access_control_policy_present():
    path = _write_tmp(CLEAN_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_access_control_policy(parse)
    assert findings == [], f"Expected no ACP finding: {findings}"
    print("  PASS  test_ftd_access_control_policy_present")


def test_ftd_no_threat_detection():
    path = _write_tmp(RISKY_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_threat_detection(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 threat-detection finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    assert "Threat detection" in msgs[0]
    print("  PASS  test_ftd_no_threat_detection")


def test_ftd_threat_detection_present():
    path = _write_tmp(CLEAN_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_threat_detection(parse)
    assert findings == [], f"Expected no threat-detection finding: {findings}"
    print("  PASS  test_ftd_threat_detection_present")


def test_ftd_no_intrusion_policy():
    path = _write_tmp(RISKY_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_intrusion_policy(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 IPS finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    print("  PASS  test_ftd_no_intrusion_policy")


def test_ftd_intrusion_policy_present():
    path = _write_tmp(CLEAN_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_intrusion_policy(parse)
    assert findings == [], f"Expected no IPS finding: {findings}"
    print("  PASS  test_ftd_intrusion_policy_present")


def test_ftd_intrusion_policy_via_snort():
    """snort keyword counts as IPS reference."""
    path = _write_tmp(FTD_SNORT)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_intrusion_policy(parse)
    assert findings == [], f"Expected no IPS finding when snort is present: {findings}"
    print("  PASS  test_ftd_intrusion_policy_via_snort")


def test_ftd_no_ssl_inspection():
    path = _write_tmp(RISKY_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_ssl_inspection(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 SSL finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    assert "SSL" in msgs[0] or "TLS" in msgs[0]
    print("  PASS  test_ftd_no_ssl_inspection")


def test_ftd_ssl_inspection_present():
    path = _write_tmp(CLEAN_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_ssl_inspection(parse)
    assert findings == [], f"Expected no SSL finding: {findings}"
    print("  PASS  test_ftd_ssl_inspection_present")


def test_ftd_snmp_community_detects():
    path = _write_tmp(RISKY_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_snmp_community(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 SNMP finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    assert "SNMP" in msgs[0] or "snmp" in msgs[0]
    print("  PASS  test_ftd_snmp_community_detects")


def test_ftd_snmp_community_clean():
    path = _write_tmp(CLEAN_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_snmp_community(parse)
    assert findings == [], f"Expected no SNMP finding on clean config: {findings}"
    print("  PASS  test_ftd_snmp_community_clean")


def test_ftd_no_syslog():
    path = _write_tmp(RISKY_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_syslog_server(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 syslog finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    assert "syslog" in msgs[0].lower()
    print("  PASS  test_ftd_no_syslog")


def test_ftd_syslog_present():
    path = _write_tmp(CLEAN_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_syslog_server(parse)
    assert findings == [], f"Expected no syslog finding: {findings}"
    print("  PASS  test_ftd_syslog_present")


def test_ftd_ssh_version_not_set():
    config = """\
hostname ftd-nossh
access-control-policy Default_ACP
threat-detection basic-threat
intrusion-policy Balanced
logging host mgmt 10.0.1.100
access-list OUTSIDE_IN extended deny ip any any log
"""
    path = _write_tmp(config)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_ssh_version(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 SSH version finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    print("  PASS  test_ftd_ssh_version_not_set")


def test_ftd_ssh_version_1():
    config = """\
hostname ftd-sshv1
ssh version 1
access-control-policy Default_ACP
threat-detection basic-threat
intrusion-policy Balanced
"""
    path = _write_tmp(config)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_ssh_version(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 SSHv1 finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    assert "SSHv1" in msgs[0]
    print("  PASS  test_ftd_ssh_version_1")


def test_ftd_ssh_version_2_clean():
    path = _write_tmp(CLEAN_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_ssh_version(parse)
    assert findings == [], f"Expected no SSH version finding with 'ssh version 2': {findings}"
    print("  PASS  test_ftd_ssh_version_2_clean")


def test_ftd_http_server_unrestricted():
    path = _write_tmp(RISKY_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_http_server(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 HTTP server finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    assert "HTTP" in msgs[0] or "ASDM" in msgs[0]
    print("  PASS  test_ftd_http_server_unrestricted")


def test_ftd_http_server_restricted():
    config = """\
hostname ftd-asdm
http server enable
http 10.0.0.0 255.255.0.0 management
"""
    path = _write_tmp(config)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_http_server(parse)
    assert findings == [], f"Expected no HTTP finding when restricted: {findings}"
    print("  PASS  test_ftd_http_server_restricted")


def test_ftd_http_server_disabled():
    path = _write_tmp(CLEAN_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_http_server(parse)
    assert findings == [], f"Expected no HTTP finding when server not enabled: {findings}"
    print("  PASS  test_ftd_http_server_disabled")


def test_ftd_telnet_detects():
    path = _write_tmp(RISKY_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_telnet(parse)
    msgs = _msgs(findings)
    assert len(findings) >= 1, f"Expected ≥1 telnet finding: {msgs}"
    assert all("[MEDIUM]" in m for m in msgs)
    print(f"  PASS  test_ftd_telnet_detects — {len(findings)} findings")


def test_ftd_icmp_any_detects():
    path = _write_tmp(RISKY_FTD)
    parse = ftd_module.parse_ftd(path)
    findings = ftd_module._check_icmp_any(parse)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 ICMP finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    print("  PASS  test_ftd_icmp_any_detects")


def test_ftd_full_audit_risky():
    path = _write_tmp(RISKY_FTD)
    findings, parse = ftd_module.audit_ftd(path)
    msgs = _msgs(findings)
    assert len(findings) >= 7, f"Expected ≥7 findings on risky FTD: got {len(findings)}: {msgs}"
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) >= 3, f"Expected ≥3 HIGH findings: {_msgs(high)}"
    # FTD-specific checks should fire
    assert any("access-control-policy" in m for m in msgs), "Should flag missing ACP"
    assert any("Threat detection" in m for m in msgs), "Should flag missing threat-detection"
    print(f"  PASS  test_ftd_full_audit_risky — {len(findings)} findings")


def test_ftd_full_audit_clean():
    path = _write_tmp(CLEAN_FTD)
    findings, parse = ftd_module.audit_ftd(path)
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) == 0, f"Clean FTD config should have no HIGH findings: {_msgs(high)}"
    print(f"  PASS  test_ftd_full_audit_clean — {len(findings)} findings (no HIGH)")


def test_ftd_finding_structure():
    """All findings from audit_ftd must have required keys."""
    path = _write_tmp(RISKY_FTD)
    findings, _ = ftd_module.audit_ftd(path)
    for f in findings:
        assert isinstance(f, dict), f"Finding must be dict: {f}"
        assert "severity" in f, f"Missing 'severity': {f}"
        assert "category" in f, f"Missing 'category': {f}"
        assert "message"  in f, f"Missing 'message': {f}"
        assert f["severity"] in ("HIGH", "MEDIUM", "LOW", "INFO"), f"Bad severity: {f}"
    print(f"  PASS  test_ftd_finding_structure — {len(findings)} findings validated")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n── Cisco ASA + FTD Tests ──\n")
    failures = 0
    tests = [
        test_asa_any_any_detects, test_asa_any_any_clean,
        test_asa_missing_logging_detects, test_asa_missing_logging_clean,
        test_asa_deny_all_missing, test_asa_deny_all_present,
        test_asa_redundant_rules_detects, test_asa_redundant_rules_clean,
        test_asa_telnet_detects, test_asa_telnet_clean,
        test_asa_icmp_any_detects, test_asa_icmp_any_clean,
        test_asa_full_audit_risky, test_asa_full_audit_clean, test_asa_fixture_file,
        test_ftd_is_ftd_config_true, test_ftd_is_ftd_config_false,
        test_ftd_no_access_control_policy, test_ftd_access_control_policy_present,
        test_ftd_no_threat_detection, test_ftd_threat_detection_present,
        test_ftd_no_intrusion_policy, test_ftd_intrusion_policy_present,
        test_ftd_intrusion_policy_via_snort,
        test_ftd_no_ssl_inspection, test_ftd_ssl_inspection_present,
        test_ftd_snmp_community_detects, test_ftd_snmp_community_clean,
        test_ftd_no_syslog, test_ftd_syslog_present,
        test_ftd_ssh_version_not_set, test_ftd_ssh_version_1, test_ftd_ssh_version_2_clean,
        test_ftd_http_server_unrestricted, test_ftd_http_server_restricted,
        test_ftd_http_server_disabled,
        test_ftd_telnet_detects, test_ftd_icmp_any_detects,
        test_ftd_full_audit_risky, test_ftd_full_audit_clean, test_ftd_finding_structure,
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
