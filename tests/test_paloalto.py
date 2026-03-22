"""Tests for Palo Alto Networks parser and auditor (paloalto.py).

Run with:  python3 tests/test_paloalto.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from flintlock.paloalto import (
    parse_paloalto,
    check_any_any_pa,
    check_missing_logging_pa,
    check_deny_all_pa,
    check_redundant_rules_pa,
    check_any_application_pa,
    check_no_security_profile_pa,
    check_missing_description_pa,
    audit_paloalto,
)

TESTS_DIR = os.path.dirname(__file__)


def _msgs(findings):
    return [f["message"] for f in findings]


def _write_tmp(content):
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False)
    tf.write(content)
    tf.flush()
    tf.close()
    return tf.name


# ── Config samples ────────────────────────────────────────────────────────────

CLEAN_PA = """\
<?xml version="1.0"?>
<config>
  <devices><entry><vsys><entry>
    <security><rules>
      <entry name="Allow-Corp-HTTPS">
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>10.0.0.0/8</member></source>
        <destination><member>any</member></destination>
        <application><member>ssl</member></application>
        <service><member>application-default</member></service>
        <action>allow</action>
        <log-end>yes</log-end>
        <description>Allow corporate HTTPS outbound</description>
        <profile-setting><group><member>default-security-profile</member></group></profile-setting>
      </entry>
      <entry name="Allow-DNS">
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>10.0.0.0/8</member></source>
        <destination><member>8.8.8.8</member></destination>
        <application><member>dns</member></application>
        <service><member>application-default</member></service>
        <action>allow</action>
        <log-end>yes</log-end>
        <description>Allow DNS to Google</description>
        <profile-setting><group><member>default-security-profile</member></group></profile-setting>
      </entry>
      <entry name="Deny-All">
        <from><member>any</member></from>
        <to><member>any</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>deny</action>
        <log-end>yes</log-end>
        <description>Catch-all deny rule</description>
      </entry>
    </rules></security>
  </entry></vsys></entry></devices>
</config>
"""

RISKY_PA = """\
<?xml version="1.0"?>
<config>
  <devices><entry><vsys><entry>
    <security><rules>
      <entry name="Allow-Any-Any">
        <from><member>any</member></from>
        <to><member>any</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>allow</action>
      </entry>
      <entry name="Allow-Web-No-Log">
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>any</member></source>
        <destination><member>10.0.0.1</member></destination>
        <application><member>web-browsing</member></application>
        <service><member>application-default</member></service>
        <action>allow</action>
      </entry>
      <entry name="Allow-Any-App">
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>10.0.0.0/24</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>application-default</member></service>
        <action>allow</action>
        <log-end>yes</log-end>
      </entry>
      <entry name="Dup-Allow-Web">
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>any</member></source>
        <destination><member>10.0.0.1</member></destination>
        <application><member>web-browsing</member></application>
        <service><member>application-default</member></service>
        <action>allow</action>
      </entry>
    </rules></security>
  </entry></vsys></entry></devices>
</config>
"""

DISABLED_RULE_PA = """\
<?xml version="1.0"?>
<config>
  <devices><entry><vsys><entry>
    <security><rules>
      <entry name="Disabled-Any-Any">
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>allow</action>
        <disabled>yes</disabled>
      </entry>
      <entry name="Deny-All">
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>deny</action>
        <log-end>yes</log-end>
        <description>Deny all</description>
        <profile-setting><group><member>sg</member></group></profile-setting>
      </entry>
    </rules></security>
  </entry></vsys></entry></devices>
</config>
"""

# ── parse_paloalto tests ──────────────────────────────────────────────────────

def test_parse_paloalto_clean():
    path = _write_tmp(CLEAN_PA)
    rules, err = parse_paloalto(path)
    assert err is None, f"Parse error: {err}"
    assert len(rules) == 3, f"Expected 3 rules: {len(rules)}"
    names = [r.get("name") for r in rules]
    assert "Allow-Corp-HTTPS" in names
    assert "Deny-All" in names
    print(f"  PASS  test_parse_paloalto_clean — {len(rules)} rules parsed")


def test_parse_paloalto_fixture():
    path = os.path.join(TESTS_DIR, "test_pa.xml")
    rules, err = parse_paloalto(path)
    assert err is None, f"Parse error: {err}"
    assert len(rules) == 5, f"Expected 5 rules from fixture: {len(rules)}"
    print(f"  PASS  test_parse_paloalto_fixture — {len(rules)} rules")


def test_parse_paloalto_bad_file():
    rules, err = parse_paloalto("/nonexistent/config.xml")
    assert rules is None
    assert err is not None
    print("  PASS  test_parse_paloalto_bad_file")


def test_parse_paloalto_bad_xml():
    path = _write_tmp("this is not xml at all <<<")
    rules, err = parse_paloalto(path)
    assert rules is None
    assert err is not None
    assert "Failed to parse" in err
    print("  PASS  test_parse_paloalto_bad_xml")


# ── check_any_any_pa tests ────────────────────────────────────────────────────

def test_any_any_detects():
    path = _write_tmp(RISKY_PA)
    rules, _ = parse_paloalto(path)
    findings = check_any_any_pa(rules)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 any-any finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    assert "Allow-Any-Any" in msgs[0]
    assert "source=any destination=any" in msgs[0]
    print("  PASS  test_any_any_detects")


def test_any_any_clean():
    path = _write_tmp(CLEAN_PA)
    rules, _ = parse_paloalto(path)
    findings = check_any_any_pa(rules)
    assert findings == [], f"Expected no any-any findings: {findings}"
    print("  PASS  test_any_any_clean")


# ── check_missing_logging_pa tests ────────────────────────────────────────────

def test_missing_logging_detects():
    path = _write_tmp(RISKY_PA)
    rules, _ = parse_paloalto(path)
    findings = check_missing_logging_pa(rules)
    msgs = _msgs(findings)
    assert len(findings) >= 1, f"Expected ≥1 missing-log finding: {msgs}"
    assert all("[MEDIUM]" in m for m in msgs)
    # Rules without log-end or log-start should be flagged
    flagged = [m for m in msgs if "Allow-Any-Any" in m or "Allow-Web-No-Log" in m or "Dup-Allow-Web" in m]
    assert len(flagged) >= 1, f"Expected at least one named rule flagged: {msgs}"
    print(f"  PASS  test_missing_logging_detects — {len(findings)} findings")


def test_missing_logging_clean():
    path = _write_tmp(CLEAN_PA)
    rules, _ = parse_paloalto(path)
    findings = check_missing_logging_pa(rules)
    assert findings == [], f"Expected no missing-log findings: {findings}"
    print("  PASS  test_missing_logging_clean")


def test_log_start_satisfies_logging():
    xml = """\
<?xml version="1.0"?>
<config><devices><entry><vsys><entry><security><rules>
  <entry name="Allow-Log-Start">
    <source><member>10.0.0.0/24</member></source>
    <destination><member>any</member></destination>
    <application><member>ssl</member></application>
    <service><member>application-default</member></service>
    <action>allow</action>
    <log-start>yes</log-start>
  </entry>
  <entry name="Deny-All">
    <source><member>any</member></source>
    <destination><member>any</member></destination>
    <application><member>any</member></application>
    <service><member>any</member></service>
    <action>deny</action>
    <log-end>yes</log-end>
    <description>deny all</description>
    <profile-setting><group><member>sg</member></group></profile-setting>
  </entry>
</rules></security></entry></vsys></entry></devices></config>
"""
    path = _write_tmp(xml)
    rules, _ = parse_paloalto(path)
    findings = check_missing_logging_pa(rules)
    assert findings == [], f"log-start=yes should satisfy logging: {findings}"
    print("  PASS  test_log_start_satisfies_logging")


# ── check_deny_all_pa tests ───────────────────────────────────────────────────

def test_deny_all_missing():
    path = _write_tmp(RISKY_PA)
    rules, _ = parse_paloalto(path)
    findings = check_deny_all_pa(rules)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 deny-all finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    print("  PASS  test_deny_all_missing")


def test_deny_all_present():
    path = _write_tmp(CLEAN_PA)
    rules, _ = parse_paloalto(path)
    findings = check_deny_all_pa(rules)
    assert findings == [], f"Expected no deny-all finding when deny-all present: {findings}"
    print("  PASS  test_deny_all_present")


# ── check_redundant_rules_pa tests ────────────────────────────────────────────

def test_redundant_rules_detects():
    path = _write_tmp(RISKY_PA)
    rules, _ = parse_paloalto(path)
    findings = check_redundant_rules_pa(rules)
    msgs = _msgs(findings)
    # Allow-Web-No-Log and Dup-Allow-Web have same src/dst/app/action
    assert len(findings) >= 1, f"Expected ≥1 redundant rule finding: {msgs}"
    assert all("[MEDIUM]" in m for m in msgs)
    assert all("Redundant" in m for m in msgs)
    print(f"  PASS  test_redundant_rules_detects — {len(findings)} findings")


def test_redundant_rules_clean():
    path = _write_tmp(CLEAN_PA)
    rules, _ = parse_paloalto(path)
    findings = check_redundant_rules_pa(rules)
    assert findings == [], f"Expected no redundant findings: {findings}"
    print("  PASS  test_redundant_rules_clean")


# ── check_any_application_pa tests ───────────────────────────────────────────

def test_any_application_detects():
    path = _write_tmp(RISKY_PA)
    rules, _ = parse_paloalto(path)
    findings = check_any_application_pa(rules)
    msgs = _msgs(findings)
    assert len(findings) >= 1, f"Expected ≥1 any-application finding: {msgs}"
    assert all("[MEDIUM]" in m for m in msgs)
    assert all("any application" in m for m in msgs)
    print(f"  PASS  test_any_application_detects — {len(findings)} findings")


def test_any_application_clean():
    path = _write_tmp(CLEAN_PA)
    rules, _ = parse_paloalto(path)
    # Deny-All has application=any but action=deny, so it should NOT be flagged
    findings = check_any_application_pa(rules)
    assert findings == [], f"Expected no any-application findings (deny rules exempt): {findings}"
    print("  PASS  test_any_application_clean")


# ── check_no_security_profile_pa tests ───────────────────────────────────────

def test_no_security_profile_detects():
    path = _write_tmp(RISKY_PA)
    rules, _ = parse_paloalto(path)
    findings = check_no_security_profile_pa(rules)
    msgs = _msgs(findings)
    assert len(findings) >= 1, f"Expected ≥1 missing-profile finding: {msgs}"
    assert all("[MEDIUM]" in m for m in msgs)
    assert all("security profile" in m for m in msgs)
    print(f"  PASS  test_no_security_profile_detects — {len(findings)} findings")


def test_no_security_profile_clean():
    path = _write_tmp(CLEAN_PA)
    rules, _ = parse_paloalto(path)
    # Allow-Corp-HTTPS and Allow-DNS have profiles; Deny-All is deny (exempt)
    findings = check_no_security_profile_pa(rules)
    assert findings == [], f"Expected no missing-profile findings: {findings}"
    print("  PASS  test_no_security_profile_clean")


# ── check_missing_description_pa tests ───────────────────────────────────────

def test_missing_description_detects():
    path = _write_tmp(RISKY_PA)
    rules, _ = parse_paloalto(path)
    findings = check_missing_description_pa(rules)
    msgs = _msgs(findings)
    assert len(findings) >= 1, f"Expected ≥1 missing-description finding: {msgs}"
    assert all("[MEDIUM]" in m for m in msgs)
    assert all("description" in m for m in msgs)
    print(f"  PASS  test_missing_description_detects — {len(findings)} findings")


def test_missing_description_clean():
    path = _write_tmp(CLEAN_PA)
    rules, _ = parse_paloalto(path)
    findings = check_missing_description_pa(rules)
    assert findings == [], f"Expected no missing-description findings: {findings}"
    print("  PASS  test_missing_description_clean")


# ── audit_paloalto full audit tests ──────────────────────────────────────────

def test_audit_paloalto_risky():
    path = _write_tmp(RISKY_PA)
    findings, rules = audit_paloalto(path)
    msgs = _msgs(findings)
    assert isinstance(rules, list), "Expected rules list"
    assert len(findings) >= 5, f"Expected ≥5 findings on risky config: {msgs}"
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) >= 2, f"Expected ≥2 HIGH findings: {_msgs(high)}"
    print(f"  PASS  test_audit_paloalto_risky — {len(findings)} findings")


def test_audit_paloalto_clean():
    path = _write_tmp(CLEAN_PA)
    findings, rules = audit_paloalto(path)
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) == 0, f"Clean config should have no HIGH findings: {_msgs(high)}"
    print(f"  PASS  test_audit_paloalto_clean — {len(findings)} findings (no HIGH)")


def test_audit_paloalto_fixture():
    path = os.path.join(TESTS_DIR, "test_pa.xml")
    findings, rules = audit_paloalto(path)
    msgs = _msgs(findings)
    assert len(rules) == 5, f"Expected 5 rules from fixture: {len(rules)}"
    assert any("Allow-Any-Any" in m for m in msgs), "Should flag Allow-Any-Any"
    print(f"  PASS  test_audit_paloalto_fixture — {len(findings)} findings")


def test_audit_paloalto_finding_structure():
    path = _write_tmp(RISKY_PA)
    findings, _ = audit_paloalto(path)
    for f in findings:
        assert isinstance(f, dict), f"Finding must be dict: {f}"
        for key in ("severity", "category", "message", "remediation"):
            assert key in f, f"Finding missing key '{key}': {f}"
        assert f["severity"] in ("HIGH", "MEDIUM", "LOW", "INFO"), f"Bad severity: {f}"
    print(f"  PASS  test_audit_paloalto_finding_structure — {len(findings)} validated")


def test_audit_paloalto_bad_file():
    findings, rules = audit_paloalto("/nonexistent/config.xml")
    assert rules == []
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "[ERROR]" in findings[0]["message"]
    print("  PASS  test_audit_paloalto_bad_file")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n── Palo Alto Networks Tests ──\n")
    failures = 0
    tests = [
        test_parse_paloalto_clean, test_parse_paloalto_fixture,
        test_parse_paloalto_bad_file, test_parse_paloalto_bad_xml,
        test_any_any_detects, test_any_any_clean,
        test_missing_logging_detects, test_missing_logging_clean,
        test_log_start_satisfies_logging,
        test_deny_all_missing, test_deny_all_present,
        test_redundant_rules_detects, test_redundant_rules_clean,
        test_any_application_detects, test_any_application_clean,
        test_no_security_profile_detects, test_no_security_profile_clean,
        test_missing_description_detects, test_missing_description_clean,
        test_audit_paloalto_risky, test_audit_paloalto_clean,
        test_audit_paloalto_fixture, test_audit_paloalto_finding_structure,
        test_audit_paloalto_bad_file,
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
