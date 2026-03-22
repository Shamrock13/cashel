"""Tests for pfSense XML parser and auditor (pfsense.py).

Run with:  python3 tests/test_pfsense.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from flintlock.pfsense import (
    parse_pfsense,
    check_any_any_pf,
    check_missing_logging_pf,
    check_deny_all_pf,
    check_redundant_rules_pf,
    check_missing_description_pf,
    check_wan_any_source_pf,
    audit_pfsense,
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

CLEAN_PF = """\
<?xml version="1.0"?>
<pfsense>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <source><address>192.168.1.0/24</address></source>
      <destination><address>10.0.0.50</address></destination>
      <protocol>tcp</protocol>
      <log/>
      <descr>Allow LAN to App Server</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <source><address>192.168.1.0/24</address></source>
      <destination><address>8.8.8.8</address></destination>
      <protocol>udp</protocol>
      <log/>
      <descr>Allow LAN DNS Outbound</descr>
    </rule>
    <rule>
      <type>block</type>
      <interface>wan</interface>
      <source><any/></source>
      <destination><any/></destination>
      <protocol>any</protocol>
      <log/>
      <descr>Default Block All</descr>
    </rule>
  </filter>
</pfsense>
"""

RISKY_PF = """\
<?xml version="1.0"?>
<pfsense>
  <filter>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <source><any/></source>
      <destination><any/></destination>
      <protocol>any</protocol>
      <descr>Allow All From Internet</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <source><any/></source>
      <destination><address>10.0.0.1</address></destination>
      <protocol>tcp</protocol>
      <descr>Allow Web</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <source><any/></source>
      <destination><address>10.0.0.1</address></destination>
      <protocol>tcp</protocol>
      <descr>Allow Web Dup</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <source><any/></source>
      <destination><any/></destination>
      <protocol>any</protocol>
    </rule>
  </filter>
</pfsense>
"""

WAN_ANY_PF = """\
<?xml version="1.0"?>
<pfsense>
  <filter>
    <rule>
      <type>pass</type>
      <interface>wan</interface>
      <source><any/></source>
      <destination><address>10.0.0.10</address></destination>
      <protocol>tcp</protocol>
      <log/>
      <descr>WAN Any-Source Pass</descr>
    </rule>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <source><any/></source>
      <destination><address>10.0.0.20</address></destination>
      <protocol>tcp</protocol>
      <log/>
      <descr>LAN Any-Source Pass (not WAN, should not fire)</descr>
    </rule>
    <rule>
      <type>block</type>
      <interface>wan</interface>
      <source><any/></source>
      <destination><any/></destination>
      <protocol>any</protocol>
      <log/>
      <descr>WAN Block All</descr>
    </rule>
    <rule>
      <type>block</type>
      <interface>lan</interface>
      <source><any/></source>
      <destination><any/></destination>
      <protocol>any</protocol>
      <log/>
      <descr>LAN Block All</descr>
    </rule>
  </filter>
</pfsense>
"""

# ── parse_pfsense tests ───────────────────────────────────────────────────────

def test_parse_pfsense_clean():
    path = _write_tmp(CLEAN_PF)
    rules, err = parse_pfsense(path)
    assert err is None, f"Parse error: {err}"
    assert len(rules) == 3, f"Expected 3 rules: {len(rules)}"
    r0 = rules[0]
    assert r0["type"] == "pass"
    assert r0["interface"] == "lan"
    assert r0["protocol"] == "tcp"
    assert r0["log"] is True
    assert r0["descr"] == "Allow LAN to App Server"
    print(f"  PASS  test_parse_pfsense_clean — {len(rules)} rules parsed")


def test_parse_pfsense_any_source():
    """Rules with <source><any/> should be parsed as source='1'."""
    path = _write_tmp(RISKY_PF)
    rules, err = parse_pfsense(path)
    assert err is None
    # First rule is WAN any→any
    assert rules[0]["source"] == "1", f"Expected source=1 for any: {rules[0]['source']}"
    assert rules[0]["destination"] == "1", f"Expected dst=1 for any: {rules[0]['destination']}"
    print("  PASS  test_parse_pfsense_any_source")


def test_parse_pfsense_specific_destination():
    """Rules with <destination><address> should be parsed as the address string."""
    path = _write_tmp(RISKY_PF)
    rules, err = parse_pfsense(path)
    assert err is None
    # Second rule has specific destination
    assert rules[1]["destination"] == "10.0.0.1", f"Expected specific dst: {rules[1]['destination']}"
    print("  PASS  test_parse_pfsense_specific_destination")


def test_parse_pfsense_no_log():
    """Rules without <log/> should have log=False."""
    path = _write_tmp(RISKY_PF)
    rules, err = parse_pfsense(path)
    assert err is None
    no_log = [r for r in rules if not r["log"]]
    assert len(no_log) >= 1, "Expected at least one unlogged rule"
    print(f"  PASS  test_parse_pfsense_no_log — {len(no_log)} unlogged rules")


def test_parse_pfsense_fixture():
    path = os.path.join(TESTS_DIR, "test_pfsense.xml")
    rules, err = parse_pfsense(path)
    assert err is None, f"Parse error: {err}"
    assert len(rules) == 7, f"Expected 7 rules from fixture: {len(rules)}"
    print(f"  PASS  test_parse_pfsense_fixture — {len(rules)} rules")


def test_parse_pfsense_bad_file():
    rules, err = parse_pfsense("/nonexistent/pfsense.xml")
    assert rules is None
    assert err is not None
    assert "Failed to parse" in err
    print("  PASS  test_parse_pfsense_bad_file")


def test_parse_pfsense_bad_xml():
    path = _write_tmp("<<not valid xml>>")
    rules, err = parse_pfsense(path)
    assert rules is None
    assert err is not None
    print("  PASS  test_parse_pfsense_bad_xml")


# ── check_any_any_pf tests ────────────────────────────────────────────────────

def test_any_any_detects():
    path = _write_tmp(RISKY_PF)
    rules, _ = parse_pfsense(path)
    findings = check_any_any_pf(rules)
    msgs = _msgs(findings)
    assert len(findings) >= 1, f"Expected ≥1 any-any finding: {msgs}"
    assert all("[HIGH]" in m for m in msgs)
    assert all("source=any destination=any" in m for m in msgs)
    print(f"  PASS  test_any_any_detects — {len(findings)} findings")


def test_any_any_clean():
    path = _write_tmp(CLEAN_PF)
    rules, _ = parse_pfsense(path)
    findings = check_any_any_pf(rules)
    assert findings == [], f"Expected no any-any findings: {findings}"
    print("  PASS  test_any_any_clean")


def test_any_any_block_not_flagged():
    """block rules with any/any should not be flagged (check is only for pass)."""
    path = _write_tmp(CLEAN_PF)
    rules, _ = parse_pfsense(path)
    # Block-All rules have source=1/destination=1 but type=block
    pass_any = [r for r in rules if r["type"] == "pass" and r["source"] == "1" and r["destination"] == "1"]
    assert len(pass_any) == 0, f"Clean config should have no pass any-any rules: {pass_any}"
    print("  PASS  test_any_any_block_not_flagged")


# ── check_missing_logging_pf tests ────────────────────────────────────────────

def test_missing_logging_detects():
    path = _write_tmp(RISKY_PF)
    rules, _ = parse_pfsense(path)
    findings = check_missing_logging_pf(rules)
    msgs = _msgs(findings)
    assert len(findings) >= 1, f"Expected ≥1 missing-log finding: {msgs}"
    assert all("[MEDIUM]" in m for m in msgs)
    print(f"  PASS  test_missing_logging_detects — {len(findings)} findings")


def test_missing_logging_clean():
    path = _write_tmp(CLEAN_PF)
    rules, _ = parse_pfsense(path)
    findings = check_missing_logging_pf(rules)
    assert findings == [], f"Expected no missing-log findings: {findings}"
    print("  PASS  test_missing_logging_clean")


# ── check_deny_all_pf tests ───────────────────────────────────────────────────

def test_deny_all_missing():
    path = _write_tmp(RISKY_PF)
    rules, _ = parse_pfsense(path)
    findings = check_deny_all_pf(rules)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 deny-all finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    assert "deny-all" in msgs[0]
    print("  PASS  test_deny_all_missing")


def test_deny_all_present():
    path = _write_tmp(CLEAN_PF)
    rules, _ = parse_pfsense(path)
    findings = check_deny_all_pf(rules)
    assert findings == [], f"Expected no deny-all finding when block-all present: {findings}"
    print("  PASS  test_deny_all_present")


# ── check_redundant_rules_pf tests ───────────────────────────────────────────

def test_redundant_rules_detects():
    path = _write_tmp(RISKY_PF)
    rules, _ = parse_pfsense(path)
    findings = check_redundant_rules_pf(rules)
    msgs = _msgs(findings)
    # Allow Web and Allow Web Dup are identical (same type/source/destination/protocol)
    assert len(findings) >= 1, f"Expected ≥1 redundant rule finding: {msgs}"
    assert all("[MEDIUM]" in m for m in msgs)
    print(f"  PASS  test_redundant_rules_detects — {len(findings)} findings")


def test_redundant_rules_clean():
    path = _write_tmp(CLEAN_PF)
    rules, _ = parse_pfsense(path)
    findings = check_redundant_rules_pf(rules)
    assert findings == [], f"Expected no redundant findings: {findings}"
    print("  PASS  test_redundant_rules_clean")


# ── check_missing_description_pf tests ───────────────────────────────────────

def test_missing_description_detects():
    """Rules with no descr or generic descr should be flagged."""
    path = _write_tmp(RISKY_PF)
    rules, _ = parse_pfsense(path)
    findings = check_missing_description_pf(rules)
    msgs = _msgs(findings)
    # The unnamed rule (no <descr>) should be flagged
    assert len(findings) >= 1, f"Expected ≥1 missing-description finding: {msgs}"
    assert all("[MEDIUM]" in m for m in msgs)
    print(f"  PASS  test_missing_description_detects — {len(findings)} findings")


def test_missing_description_clean():
    path = _write_tmp(CLEAN_PF)
    rules, _ = parse_pfsense(path)
    findings = check_missing_description_pf(rules)
    assert findings == [], f"Expected no missing-description findings: {findings}"
    print("  PASS  test_missing_description_clean")


# ── check_wan_any_source_pf tests ─────────────────────────────────────────────

def test_wan_any_source_detects():
    path = _write_tmp(WAN_ANY_PF)
    rules, _ = parse_pfsense(path)
    findings = check_wan_any_source_pf(rules)
    msgs = _msgs(findings)
    # WAN Any-Source Pass should fire; LAN rule should not
    assert len(findings) == 1, f"Expected 1 WAN any-source finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    assert "WAN" in msgs[0]
    assert "WAN Any-Source Pass" in msgs[0]
    print("  PASS  test_wan_any_source_detects")


def test_wan_any_source_clean():
    path = _write_tmp(CLEAN_PF)
    rules, _ = parse_pfsense(path)
    findings = check_wan_any_source_pf(rules)
    assert findings == [], f"Expected no WAN any-source findings: {findings}"
    print("  PASS  test_wan_any_source_clean")


def test_wan_block_not_flagged():
    """WAN block rules with any source should not be flagged."""
    path = _write_tmp(WAN_ANY_PF)
    rules, _ = parse_pfsense(path)
    # Filter to WAN block rules
    # Manually call check — should not include block rules
    findings = check_wan_any_source_pf(rules)
    # Only the pass rule fires, not the block rules
    assert len(findings) == 1
    print("  PASS  test_wan_block_not_flagged")


# ── audit_pfsense full audit tests ────────────────────────────────────────────

def test_audit_pfsense_risky():
    path = _write_tmp(RISKY_PF)
    findings, rules = audit_pfsense(path)
    msgs = _msgs(findings)
    assert isinstance(rules, list)
    assert len(findings) >= 4, f"Expected ≥4 findings on risky config: {msgs}"
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) >= 2, f"Expected ≥2 HIGH findings: {_msgs(high)}"
    print(f"  PASS  test_audit_pfsense_risky — {len(findings)} findings")


def test_audit_pfsense_clean():
    path = _write_tmp(CLEAN_PF)
    findings, rules = audit_pfsense(path)
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) == 0, f"Clean config should have no HIGH findings: {_msgs(high)}"
    print(f"  PASS  test_audit_pfsense_clean — {len(findings)} findings (no HIGH)")


def test_audit_pfsense_fixture():
    path = os.path.join(TESTS_DIR, "test_pfsense.xml")
    findings, rules = audit_pfsense(path)
    msgs = _msgs(findings)
    assert len(rules) == 7, f"Expected 7 rules from fixture: {len(rules)}"
    assert any("source=any destination=any" in m for m in msgs), "Should detect any-any"
    print(f"  PASS  test_audit_pfsense_fixture — {len(findings)} findings")


def test_audit_pfsense_finding_structure():
    path = _write_tmp(RISKY_PF)
    findings, _ = audit_pfsense(path)
    for f in findings:
        assert isinstance(f, dict)
        for key in ("severity", "category", "message", "remediation"):
            assert key in f, f"Finding missing key '{key}': {f}"
        assert f["severity"] in ("HIGH", "MEDIUM", "LOW", "INFO")
    print(f"  PASS  test_audit_pfsense_finding_structure — {len(findings)} validated")


def test_audit_pfsense_bad_file():
    findings, rules = audit_pfsense("/nonexistent/pfsense.xml")
    assert rules == []
    assert len(findings) == 1
    assert "[ERROR]" in findings[0]["message"]
    print("  PASS  test_audit_pfsense_bad_file")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n── pfSense Tests ──\n")
    failures = 0
    tests = [
        test_parse_pfsense_clean, test_parse_pfsense_any_source,
        test_parse_pfsense_specific_destination, test_parse_pfsense_no_log,
        test_parse_pfsense_fixture, test_parse_pfsense_bad_file, test_parse_pfsense_bad_xml,
        test_any_any_detects, test_any_any_clean, test_any_any_block_not_flagged,
        test_missing_logging_detects, test_missing_logging_clean,
        test_deny_all_missing, test_deny_all_present,
        test_redundant_rules_detects, test_redundant_rules_clean,
        test_missing_description_detects, test_missing_description_clean,
        test_wan_any_source_detects, test_wan_any_source_clean, test_wan_block_not_flagged,
        test_audit_pfsense_risky, test_audit_pfsense_clean,
        test_audit_pfsense_fixture, test_audit_pfsense_finding_structure,
        test_audit_pfsense_bad_file,
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
