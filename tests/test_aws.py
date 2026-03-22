"""Tests for AWS Security Group parser and auditor (aws.py).

Run with:  python3 tests/test_aws.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from flintlock.aws import (
    parse_aws_sg,
    check_wide_open_ingress,
    check_wide_open_egress,
    check_missing_descriptions,
    check_default_sg_has_rules,
    check_large_port_ranges,
    audit_aws_sg,
)


def _msgs(findings):
    return [f["message"] for f in findings]


def _write_tmp(data):
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(data, tf)
    tf.flush()
    tf.close()
    return tf.name


# ── Sample Security Group data ────────────────────────────────────────────────

CLEAN_SG = [{
    "GroupId": "sg-clean001",
    "GroupName": "web-tier",
    "Description": "Web tier SG — allows HTTPS from trusted CIDR only",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "203.0.113.0/24", "Description": "Office egress"}],
        }
    ],
    "IpPermissionsEgress": [
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Egress HTTPS"}],
        }
    ],
}]

ALL_TRAFFIC_SG = [{
    "GroupId": "sg-bad001",
    "GroupName": "allow-all",
    "Description": "Overly permissive SG",
    "IpPermissions": [
        {
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ],
    "IpPermissionsEgress": [
        {
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ],
}]

SENSITIVE_PORT_SG = [{
    "GroupId": "sg-ssh001",
    "GroupName": "bastion-exposed",
    "Description": "Bastion host — SSH exposed to world",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        },
        {
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        },
    ],
    "IpPermissionsEgress": [],
}]

ALL_PORTS_SG = [{
    "GroupId": "sg-allports",
    "GroupName": "all-ports",
    "Description": "All ports open",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 0,
            "ToPort": 65535,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ],
    "IpPermissionsEgress": [],
}]

LARGE_RANGE_SG = [{
    "GroupId": "sg-wideport",
    "GroupName": "wide-range",
    "Description": "Wide port range SG",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 8000,
            "ToPort": 9000,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ],
    "IpPermissionsEgress": [],
}]

DEFAULT_SG_WITH_RULES = [{
    "GroupId": "sg-default",
    "GroupName": "default",
    "Description": "default VPC security group",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "Internal HTTPS"}],
        }
    ],
    "IpPermissionsEgress": [],
}]

DEFAULT_SG_EMPTY = [{
    "GroupId": "sg-default-empty",
    "GroupName": "default",
    "Description": "default VPC security group",
    "IpPermissions": [],
    "IpPermissionsEgress": [],
}]

NO_DESC_SG = [{
    "GroupId": "sg-nodesc",
    "GroupName": "launch-wizard-1",
    "Description": "launch-wizard",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }
    ],
    "IpPermissionsEgress": [],
}]

IPV6_SG = [{
    "GroupId": "sg-ipv6",
    "GroupName": "ipv6-exposed",
    "Description": "SG with IPv6 exposure",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
    ],
    "IpPermissionsEgress": [],
}]

# ── parse_aws_sg tests ────────────────────────────────────────────────────────

def test_parse_aws_sg_list():
    """Parse a bare list of SG dicts."""
    path = _write_tmp(CLEAN_SG)
    groups, err = parse_aws_sg(path)
    assert err is None, f"Parse error: {err}"
    assert len(groups) == 1
    assert groups[0]["GroupId"] == "sg-clean001"
    print("  PASS  test_parse_aws_sg_list")


def test_parse_aws_sg_wrapper():
    """Parse AWS CLI output format with SecurityGroups key."""
    data = {"SecurityGroups": CLEAN_SG}
    path = _write_tmp(data)
    groups, err = parse_aws_sg(path)
    assert err is None
    assert len(groups) == 1
    print("  PASS  test_parse_aws_sg_wrapper")


def test_parse_aws_sg_single():
    """Parse a single SG dict (not a list)."""
    data = CLEAN_SG[0]
    path = _write_tmp(data)
    groups, err = parse_aws_sg(path)
    assert err is None
    assert len(groups) == 1
    print("  PASS  test_parse_aws_sg_single")


def test_parse_aws_sg_bad_format():
    path = _write_tmp({"unknown_key": "value"})
    groups, err = parse_aws_sg(path)
    assert groups is None
    assert err is not None
    assert "Unrecognized" in err
    print("  PASS  test_parse_aws_sg_bad_format")


def test_parse_aws_sg_bad_file():
    groups, err = parse_aws_sg("/nonexistent/sg.json")
    assert groups is None
    assert err is not None
    print("  PASS  test_parse_aws_sg_bad_file")


# ── check_wide_open_ingress tests ─────────────────────────────────────────────

def test_wide_open_all_traffic():
    findings = check_wide_open_ingress(ALL_TRAFFIC_SG)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 all-traffic finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    assert "ALL traffic" in msgs[0]
    print("  PASS  test_wide_open_all_traffic")


def test_wide_open_ssh():
    findings = check_wide_open_ingress(SENSITIVE_PORT_SG)
    msgs = _msgs(findings)
    assert len(findings) == 2, f"Expected 2 findings (SSH + RDP): {msgs}"
    assert all("[HIGH]" in m for m in msgs)
    assert any("SSH" in m for m in msgs)
    assert any("RDP" in m for m in msgs)
    print("  PASS  test_wide_open_ssh")


def test_wide_open_all_ports():
    findings = check_wide_open_ingress(ALL_PORTS_SG)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 all-ports finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    assert "All ports" in msgs[0]
    print("  PASS  test_wide_open_all_ports")


def test_wide_open_medium_port():
    """Non-sensitive port open to 0.0.0.0/0 should be MEDIUM."""
    sg = [{
        "GroupId": "sg-web",
        "GroupName": "web-public",
        "Description": "Public web",
        "IpPermissions": [{
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
        "IpPermissionsEgress": [],
    }]
    findings = check_wide_open_ingress(sg)
    msgs = _msgs(findings)
    assert len(findings) == 1
    assert "[MEDIUM]" in msgs[0]
    assert "Port 80" in msgs[0]
    print("  PASS  test_wide_open_medium_port")


def test_wide_open_ipv6():
    """SSH open via IPv6 ::/0 should be detected."""
    findings = check_wide_open_ingress(IPV6_SG)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 IPv6 finding: {msgs}"
    assert "[HIGH]" in msgs[0]
    assert "SSH" in msgs[0]
    assert "::/0" in msgs[0]
    print("  PASS  test_wide_open_ipv6")


def test_wide_open_restricted_cidr_clean():
    findings = check_wide_open_ingress(CLEAN_SG)
    assert findings == [], f"Expected no wide-open findings for restricted CIDR: {findings}"
    print("  PASS  test_wide_open_restricted_cidr_clean")


# ── check_wide_open_egress tests ──────────────────────────────────────────────

def test_wide_open_egress_detects():
    findings = check_wide_open_egress(ALL_TRAFFIC_SG)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 egress finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    assert "outbound" in msgs[0].lower() or "egress" in msgs[0].lower()
    print("  PASS  test_wide_open_egress_detects")


def test_wide_open_egress_clean():
    """HTTPS-only egress should not be flagged."""
    findings = check_wide_open_egress(CLEAN_SG)
    assert findings == [], f"Expected no egress findings for restricted egress: {findings}"
    print("  PASS  test_wide_open_egress_clean")


# ── check_missing_descriptions tests ─────────────────────────────────────────

def test_missing_description_group():
    findings = check_missing_descriptions(NO_DESC_SG)
    msgs = _msgs(findings)
    # launch-wizard is a generic description
    assert len(findings) >= 1, f"Expected ≥1 description finding: {msgs}"
    assert any("launch-wizard" in m or "generic" in m.lower() or "Missing" in m for m in msgs)
    print(f"  PASS  test_missing_description_group — {len(findings)} findings")


def test_missing_description_rule():
    """Rules without a description on IpRanges entries should also be flagged."""
    sg = [{
        "GroupId": "sg-norule-desc",
        "GroupName": "app-tier",
        "Description": "App tier security group",
        "IpPermissions": [{
            "IpProtocol": "tcp",
            "FromPort": 8080,
            "ToPort": 8080,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],  # No Description key
        }],
        "IpPermissionsEgress": [],
    }]
    findings = check_missing_descriptions(sg)
    msgs = _msgs(findings)
    assert len(findings) >= 1, f"Expected ≥1 rule description finding: {msgs}"
    assert any("Inbound rule" in m or "rule" in m.lower() for m in msgs)
    print(f"  PASS  test_missing_description_rule — {len(findings)} findings")


def test_missing_description_clean():
    findings = check_missing_descriptions(CLEAN_SG)
    assert findings == [], f"Expected no description findings for well-described SG: {findings}"
    print("  PASS  test_missing_description_clean")


# ── check_default_sg_has_rules tests ─────────────────────────────────────────

def test_default_sg_with_rules():
    findings = check_default_sg_has_rules(DEFAULT_SG_WITH_RULES)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 default-SG finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    assert "default" in msgs[0].lower()
    print("  PASS  test_default_sg_with_rules")


def test_default_sg_empty():
    findings = check_default_sg_has_rules(DEFAULT_SG_EMPTY)
    assert findings == [], f"Expected no finding for empty default SG: {findings}"
    print("  PASS  test_default_sg_empty")


def test_non_default_sg_ignored():
    """Non-default SGs should never be flagged by this check."""
    findings = check_default_sg_has_rules(CLEAN_SG)
    assert findings == [], f"Expected no finding for non-default SG: {findings}"
    print("  PASS  test_non_default_sg_ignored")


# ── check_large_port_ranges tests ─────────────────────────────────────────────

def test_large_port_range_detects():
    findings = check_large_port_ranges(LARGE_RANGE_SG)
    msgs = _msgs(findings)
    assert len(findings) == 1, f"Expected 1 large-port-range finding: {msgs}"
    assert "[MEDIUM]" in msgs[0]
    assert "8000-9000" in msgs[0] or "1001 ports" in msgs[0]
    print("  PASS  test_large_port_range_detects")


def test_large_port_range_clean():
    findings = check_large_port_ranges(CLEAN_SG)
    assert findings == [], f"Expected no large-port-range findings: {findings}"
    print("  PASS  test_large_port_range_clean")


def test_all_traffic_proto_excluded():
    """Proto=-1 (all traffic) should not trigger the port-range check."""
    findings = check_large_port_ranges(ALL_TRAFFIC_SG)
    assert findings == [], f"Proto -1 should be excluded from port-range check: {findings}"
    print("  PASS  test_all_traffic_proto_excluded")


# ── audit_aws_sg full audit tests ─────────────────────────────────────────────

def test_audit_aws_sg_risky():
    path = _write_tmp(ALL_TRAFFIC_SG)
    findings, groups = audit_aws_sg(path)
    msgs = _msgs(findings)
    assert isinstance(groups, list)
    assert len(findings) >= 2, f"Expected ≥2 findings on all-traffic SG: {msgs}"
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) >= 1, f"Expected ≥1 HIGH finding: {_msgs(high)}"
    print(f"  PASS  test_audit_aws_sg_risky — {len(findings)} findings")


def test_audit_aws_sg_sensitive_ports():
    path = _write_tmp(SENSITIVE_PORT_SG)
    findings, groups = audit_aws_sg(path)
    msgs = _msgs(findings)
    assert len(findings) >= 2, f"Expected ≥2 findings (SSH + RDP + desc): {msgs}"
    assert any("SSH" in m for m in msgs), "Should flag SSH open to world"
    assert any("RDP" in m for m in msgs), "Should flag RDP open to world"
    print(f"  PASS  test_audit_aws_sg_sensitive_ports — {len(findings)} findings")


def test_audit_aws_sg_clean():
    path = _write_tmp(CLEAN_SG)
    findings, groups = audit_aws_sg(path)
    high = [f for f in findings if f["severity"] == "HIGH"]
    assert len(high) == 0, f"Clean SG should have no HIGH findings: {_msgs(high)}"
    print(f"  PASS  test_audit_aws_sg_clean — {len(findings)} findings (no HIGH)")


def test_audit_aws_sg_multiple_groups():
    """Test that multiple SGs in one file are all audited."""
    data = CLEAN_SG + SENSITIVE_PORT_SG
    path = _write_tmp(data)
    findings, groups = audit_aws_sg(path)
    assert len(groups) == 2
    # At least the SSH/RDP findings from the sensitive SG
    assert len(findings) >= 2
    print(f"  PASS  test_audit_aws_sg_multiple_groups — {len(findings)} findings across 2 SGs")


def test_audit_aws_sg_wrapper_format():
    """AWS CLI output format should be parsed correctly."""
    data = {"SecurityGroups": ALL_TRAFFIC_SG}
    path = _write_tmp(data)
    findings, groups = audit_aws_sg(path)
    assert len(groups) == 1
    assert len(findings) >= 1
    print(f"  PASS  test_audit_aws_sg_wrapper_format — {len(findings)} findings")


def test_audit_aws_sg_finding_structure():
    path = _write_tmp(ALL_TRAFFIC_SG)
    findings, _ = audit_aws_sg(path)
    for f in findings:
        assert isinstance(f, dict)
        for key in ("severity", "category", "message", "remediation"):
            assert key in f, f"Finding missing '{key}': {f}"
        assert f["severity"] in ("HIGH", "MEDIUM", "LOW", "INFO")
    print(f"  PASS  test_audit_aws_sg_finding_structure — {len(findings)} validated")


def test_audit_aws_sg_bad_file():
    findings, groups = audit_aws_sg("/nonexistent/sg.json")
    assert groups == []
    assert len(findings) == 1
    assert "[ERROR]" in findings[0]["message"]
    print("  PASS  test_audit_aws_sg_bad_file")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n── AWS Security Group Tests ──\n")
    failures = 0
    tests = [
        test_parse_aws_sg_list, test_parse_aws_sg_wrapper, test_parse_aws_sg_single,
        test_parse_aws_sg_bad_format, test_parse_aws_sg_bad_file,
        test_wide_open_all_traffic, test_wide_open_ssh, test_wide_open_all_ports,
        test_wide_open_medium_port, test_wide_open_ipv6, test_wide_open_restricted_cidr_clean,
        test_wide_open_egress_detects, test_wide_open_egress_clean,
        test_missing_description_group, test_missing_description_rule,
        test_missing_description_clean,
        test_default_sg_with_rules, test_default_sg_empty, test_non_default_sg_ignored,
        test_large_port_range_detects, test_large_port_range_clean,
        test_all_traffic_proto_excluded,
        test_audit_aws_sg_risky, test_audit_aws_sg_sensitive_ports, test_audit_aws_sg_clean,
        test_audit_aws_sg_multiple_groups, test_audit_aws_sg_wrapper_format,
        test_audit_aws_sg_finding_structure, test_audit_aws_sg_bad_file,
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
