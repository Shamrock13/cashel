"""Tests for Azure NSG parser and auditor (azure.py).

Run with:  python3 tests/test_azure.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from flintlock.azure import (
    parse_azure_nsg,
    check_inbound_any,
    check_missing_flow_logs,
    check_high_priority_allow_all,
    check_broad_port_ranges,
    audit_azure_nsg,
)


def _msgs(findings):
    return [f["message"] for f in findings]


def _write_tmp(data):
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(data, tf)
    tf.flush()
    tf.close()
    return tf.name


# ── Sample NSG data ───────────────────────────────────────────────────────────

CLEAN_NSG = [{
    "name": "web-tier-nsg",
    "flowLogs": [{"enabled": True}],
    "securityRules": [
        {
            "name": "Allow-HTTPS-Inbound",
            "properties": {
                "priority": 100,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "sourceAddressPrefix": "203.0.113.0/24",
                "destinationPortRange": "443",
            },
        },
        {
            "name": "Deny-All-Inbound",
            "properties": {
                "priority": 4096,
                "direction": "Inbound",
                "access": "Deny",
                "protocol": "*",
                "sourceAddressPrefix": "*",
                "destinationPortRange": "*",
            },
        },
    ],
    "defaultSecurityRules": [],
}]

ANY_SOURCE_NSG = [{
    "name": "risky-nsg",
    "securityRules": [
        {
            "name": "Allow-All-Inbound",
            "properties": {
                "priority": 100,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "*",
                "sourceAddressPrefix": "*",
                "destinationPortRange": "*",
            },
        },
        {
            "name": "Allow-SSH-Any",
            "properties": {
                "priority": 200,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "sourceAddressPrefix": "Internet",
                "destinationPortRange": "22",
            },
        },
        {
            "name": "Allow-HTTP-Any",
            "properties": {
                "priority": 300,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "sourceAddressPrefix": "Any",
                "destinationPortRange": "80",
            },
        },
    ],
    "defaultSecurityRules": [],
}]

HIGH_PRIORITY_NSG = [{
    "name": "high-prio-nsg",
    "flowLogs": [{"enabled": True}],
    "securityRules": [
        {
            "name": "Critical-Allow-All",
            "properties": {
                "priority": 100,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "*",
                "sourceAddressPrefix": "*",
                "destinationPortRange": "*",
            },
        }
    ],
    "defaultSecurityRules": [],
}]

WIDE_PORT_NSG = [{
    "name": "wide-port-nsg",
    "flowLogs": [{"enabled": True}],
    "securityRules": [
        {
            "name": "Allow-Wide-Range",
            "properties": {
                "priority": 100,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "sourceAddressPrefix": "10.0.0.0/8",
                "destinationPortRange": "8000-9500",
            },
        }
    ],
    "defaultSecurityRules": [],
}]

FLAT_FORMAT_NSG = [{
    "name": "flat-nsg",
    "securityRules": [
        {
            "name": "Flat-Allow-RDP",
            # Flat format (no nested "properties")
            "priority": 200,
            "direction": "Inbound",
            "access": "Allow",
            "protocol": "Tcp",
            "sourceAddressPrefix": "0.0.0.0/0",
            "destinationPortRange": "3389",
        }
    ],
    "defaultSecurityRules": [],
}]

# ── parse_azure_nsg tests ─────────────────────────────────────────────────────

def test_parse_azure_nsg_list():
    path = _write_tmp(CLEAN_NSG)
    nsgs, err = parse_azure_nsg(path)
    assert err is None, f"Parse error: {err}"
    assert len(nsgs) == 1
    assert nsgs[0]["name"] == "web-tier-nsg"
    print("  PASS  test_parse_azure_nsg_list")


def test_parse_azure_nsg_single_dict():
    """Parse a single NSG dict (not a list)."""
    path = _write_tmp(CLEAN_NSG[0])
    nsgs, err = parse_azure_nsg(path)
    assert err is None
    assert len(nsgs) == 1
    print("  PASS  test_parse_azure_nsg_single_dict")


def test_parse_azure_nsg_value_wrapper():
    """Parse {value: [...]} format from az cli."""
    data = {"value": CLEAN_NSG}
    path = _write_tmp(data)
    nsgs, err = parse_azure_nsg(path)
    assert err is None
    assert len(nsgs) == 1
    print("  PASS  test_parse_azure_nsg_value_wrapper")


def test_parse_azure_nsg_bad_format():
    path = _write_tmp({"unknown": "data"})
    nsgs, err = parse_azure_nsg(path)
    assert nsgs is None
    assert err is not None
    print("  PASS  test_parse_azure_nsg_bad_format")


def test_parse_azure_nsg_bad_file():
    nsgs, err = parse_azure_nsg("/nonexistent/nsg.json")
    assert nsgs is None
    assert err is not None
    print("  PASS  test_parse_azure_nsg_bad_file")


# ── check_inbound_any tests ───────────────────────────────────────────────────

def test_inbound_any_all_traffic():
    findings = check_inbound_any(ANY_SOURCE_NSG)
    msgs = _msgs(findings)
    # Allow-All-Inbound (source=*, port=*) → HIGH all-traffic
    assert any("[HIGH]" in m and "ALL inbound" in m for m in msgs), f"Should detect all-traffic: {msgs}"
    print(f"  PASS  test_inbound_any_all_traffic — {len(findings)} findings")


def test_inbound_any_ssh_sensitive():
    """SSH from Internet source should be HIGH."""
    findings = check_inbound_any(ANY_SOURCE_NSG)
    msgs = _msgs(findings)
    assert any("[HIGH]" in m and "SSH" in m for m in msgs), f"Should flag SSH from Internet: {msgs}"
    print("  PASS  test_inbound_any_ssh_sensitive")


def test_inbound_any_http_medium():
    """Port 80 from Any source should be MEDIUM (not sensitive port)."""
    findings = check_inbound_any(ANY_SOURCE_NSG)
    msgs = _msgs(findings)
    assert any("[MEDIUM]" in m and "80" in m for m in msgs), f"Should flag HTTP as MEDIUM: {msgs}"
    print("  PASS  test_inbound_any_http_medium")


def test_inbound_any_rdp_flat_format():
    """Flat format (no properties nesting) should also be detected."""
    findings = check_inbound_any(FLAT_FORMAT_NSG)
    msgs = _msgs(findings)
    assert any("RDP" in m or "3389" in m for m in msgs), f"Should flag RDP: {msgs}"
    print(f"  PASS  test_inbound_any_rdp_flat_format — {len(findings)} findings")


def test_inbound_any_clean():
    findings = check_inbound_any(CLEAN_NSG)
    # CLEAN_NSG restricts to specific CIDR — should not fire for inbound_any
    any_source_findings = [f for f in findings if "[HIGH]" in f["message"] and "ALL inbound" in f["message"]]
    assert len(any_source_findings) == 0, f"Restricted CIDR should not trigger all-traffic: {findings}"
    print("  PASS  test_inbound_any_clean")


def test_inbound_any_deny_not_flagged():
    """Deny rules should never be flagged regardless of source."""
    nsg = [{
        "name": "deny-nsg",
        "flowLogs": [{"enabled": True}],
        "securityRules": [{
            "name": "Deny-All",
            "properties": {
                "priority": 4096,
                "direction": "Inbound",
                "access": "Deny",
                "protocol": "*",
                "sourceAddressPrefix": "*",
                "destinationPortRange": "*",
            },
        }],
        "defaultSecurityRules": [],
    }]
    findings = check_inbound_any(nsg)
    assert findings == [], f"Deny rules should not be flagged: {findings}"
    print("  PASS  test_inbound_any_deny_not_flagged")


# ── check_missing_flow_logs tests ─────────────────────────────────────────────

def test_missing_flow_logs_detects():
    findings = check_missing_flow_logs(ANY_SOURCE_NSG)
    msgs = _msgs(findings)
    # ANY_SOURCE_NSG has no flowLogs or diagnosticSettings
    assert len(findings) == 1, f"Expected 1 flow-log finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    assert "flow log" in msgs[0].lower() or "Flow log" in msgs[0]
    print("  PASS  test_missing_flow_logs_detects")


def test_missing_flow_logs_clean():
    findings = check_missing_flow_logs(CLEAN_NSG)
    assert findings == [], f"Expected no flow-log finding when flowLogs present: {findings}"
    print("  PASS  test_missing_flow_logs_clean")


def test_diagnostic_settings_satisfies():
    """diagnosticSettings key should also satisfy the flow-log check."""
    nsg = [{"name": "diag-nsg", "diagnosticSettings": [{"enabled": True}], "securityRules": [], "defaultSecurityRules": []}]
    findings = check_missing_flow_logs(nsg)
    assert findings == [], f"diagnosticSettings should satisfy flow-log check: {findings}"
    print("  PASS  test_diagnostic_settings_satisfies")


# ── check_high_priority_allow_all tests ───────────────────────────────────────

def test_high_priority_allow_all_detects():
    findings = check_high_priority_allow_all(HIGH_PRIORITY_NSG)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 high-priority finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    assert "priority 100" in msgs[0] or "priority" in msgs[0]
    print("  PASS  test_high_priority_allow_all_detects")


def test_high_priority_allow_all_clean():
    findings = check_high_priority_allow_all(CLEAN_NSG)
    # CLEAN_NSG has specific source CIDR, not any source
    assert findings == [], f"Restricted source should not trigger high-priority: {findings}"
    print("  PASS  test_high_priority_allow_all_clean")


def test_high_priority_threshold():
    """Priority >= 500 should not trigger the high-priority check."""
    nsg = [{
        "name": "medium-prio-nsg",
        "flowLogs": [{"enabled": True}],
        "securityRules": [{
            "name": "Allow-All-Low-Priority",
            "properties": {
                "priority": 500,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "*",
                "sourceAddressPrefix": "*",
                "destinationPortRange": "*",
            },
        }],
        "defaultSecurityRules": [],
    }]
    findings = check_high_priority_allow_all(nsg)
    assert findings == [], f"Priority 500 should not trigger high-priority check: {findings}"
    print("  PASS  test_high_priority_threshold")


# ── check_broad_port_ranges tests ─────────────────────────────────────────────

def test_broad_port_range_detects():
    findings = check_broad_port_ranges(WIDE_PORT_NSG)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 wide-port finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    assert "8000-9500" in msgs[0]
    print("  PASS  test_broad_port_range_detects")


def test_broad_port_range_clean():
    findings = check_broad_port_ranges(CLEAN_NSG)
    # port 443 is a single port, not a range
    assert findings == [], f"Single port should not be flagged: {findings}"
    print("  PASS  test_broad_port_range_clean")


def test_broad_port_range_threshold():
    """Threshold is hi-lo > 100. 8080-8181 (hi-lo=101) fires; 8080-8180 (hi-lo=100) does not."""
    # hi-lo = 101 → should be flagged
    nsg_over = [{
        "name": "over-nsg",
        "flowLogs": [{"enabled": True}],
        "securityRules": [{
            "name": "Allow-Over-Threshold",
            "properties": {
                "priority": 100,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "sourceAddressPrefix": "10.0.0.0/8",
                "destinationPortRange": "8080-8181",
            },
        }],
        "defaultSecurityRules": [],
    }]
    assert len(check_broad_port_ranges(nsg_over)) == 1, "8080-8181 (hi-lo=101) should be flagged"
    # hi-lo = 100 → should NOT be flagged
    nsg_at = [{
        "name": "at-nsg",
        "flowLogs": [{"enabled": True}],
        "securityRules": [{
            "name": "Allow-At-Threshold",
            "properties": {
                "priority": 100,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "sourceAddressPrefix": "10.0.0.0/8",
                "destinationPortRange": "8080-8180",
            },
        }],
        "defaultSecurityRules": [],
    }]
    assert len(check_broad_port_ranges(nsg_at)) == 0, "8080-8180 (hi-lo=100) should not be flagged"
    print("  PASS  test_broad_port_range_threshold")


# ── audit_azure_nsg full audit tests ──────────────────────────────────────────

def test_audit_azure_nsg_risky():
    path = _write_tmp(ANY_SOURCE_NSG)
    findings, nsgs = audit_azure_nsg(path)
    msgs = _msgs(findings)
    assert isinstance(nsgs, list)
    assert len(findings) >= 3, f"Expected ≥3 findings on risky NSG: {msgs}"
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) >= 1, f"Expected ≥1 HIGH findings: {_msgs(high)}"
    print(f"  PASS  test_audit_azure_nsg_risky — {len(findings)} findings")


def test_audit_azure_nsg_clean():
    path = _write_tmp(CLEAN_NSG)
    findings, nsgs = audit_azure_nsg(path)
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) == 0, f"Clean NSG should have no HIGH findings: {_msgs(high)}"
    print(f"  PASS  test_audit_azure_nsg_clean — {len(findings)} findings (no HIGH)")


def test_audit_azure_nsg_multiple():
    """Multiple NSGs in one file should all be audited."""
    data = CLEAN_NSG + ANY_SOURCE_NSG
    path = _write_tmp(data)
    findings, nsgs = audit_azure_nsg(path)
    assert len(nsgs) == 2
    assert len(findings) >= 3
    print(f"  PASS  test_audit_azure_nsg_multiple — {len(findings)} findings across 2 NSGs")


def test_audit_azure_nsg_finding_structure():
    path = _write_tmp(ANY_SOURCE_NSG)
    findings, _ = audit_azure_nsg(path)
    for f in findings:
        assert isinstance(f, dict)
        for key in ("severity", "category", "message", "remediation"):
            assert key in f, f"Finding missing '{key}': {f}"
        assert f["severity"] in ("HIGH", "MEDIUM", "LOW", "INFO")
    print(f"  PASS  test_audit_azure_nsg_finding_structure — {len(findings)} validated")


def test_audit_azure_nsg_bad_file():
    findings, nsgs = audit_azure_nsg("/nonexistent/nsg.json")
    assert nsgs == []
    assert len(findings) == 1
    assert "[ERROR]" in findings[0]["message"]
    print("  PASS  test_audit_azure_nsg_bad_file")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n── Azure NSG Tests ──\n")
    failures = 0
    tests = [
        test_parse_azure_nsg_list, test_parse_azure_nsg_single_dict,
        test_parse_azure_nsg_value_wrapper, test_parse_azure_nsg_bad_format,
        test_parse_azure_nsg_bad_file,
        test_inbound_any_all_traffic, test_inbound_any_ssh_sensitive,
        test_inbound_any_http_medium, test_inbound_any_rdp_flat_format,
        test_inbound_any_clean, test_inbound_any_deny_not_flagged,
        test_missing_flow_logs_detects, test_missing_flow_logs_clean,
        test_diagnostic_settings_satisfies,
        test_high_priority_allow_all_detects, test_high_priority_allow_all_clean,
        test_high_priority_threshold,
        test_broad_port_range_detects, test_broad_port_range_clean,
        test_broad_port_range_threshold,
        test_audit_azure_nsg_risky, test_audit_azure_nsg_clean,
        test_audit_azure_nsg_multiple, test_audit_azure_nsg_finding_structure,
        test_audit_azure_nsg_bad_file,
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
