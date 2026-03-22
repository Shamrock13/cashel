"""Tests for diff.py — rule diff engine comparing two firewall configs.

Run with:  python3 tests/test_diff.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from flintlock.diff import (
    diff_asa,
    diff_fortinet,
    diff_paloalto,
    diff_pfsense,
    diff_aws,
    diff_azure,
    diff_configs,
)


def _write_tmp(content, suffix=".txt"):
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    tf.write(content)
    tf.flush()
    tf.close()
    return tf.name


def _write_json(data):
    return _write_tmp(json.dumps(data), suffix=".json")


def _write_xml(content):
    return _write_tmp(content, suffix=".xml")


# ── diff_asa tests ────────────────────────────────────────────────────────────

ASA_V1 = """\
access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 443 log
access-list OUTSIDE_IN extended permit tcp any host 10.0.0.2 eq 80 log
access-list OUTSIDE_IN extended deny ip any any log
"""

ASA_V2 = """\
access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 443 log
access-list OUTSIDE_IN extended permit tcp any host 10.0.0.3 eq 8443 log
access-list OUTSIDE_IN extended deny ip any any log
"""

ASA_IDENTICAL = """\
access-list OUTSIDE_IN extended permit tcp any host 10.0.0.1 eq 443 log
access-list OUTSIDE_IN extended deny ip any any log
"""


def test_diff_asa_added():
    path_a = _write_tmp(ASA_V1)
    path_b = _write_tmp(ASA_V2)
    result = diff_asa(path_a, path_b)
    assert "added" in result and "removed" in result and "unchanged" in result
    assert len(result["added"]) >= 1, f"Expected ≥1 added rule: {result['added']}"
    assert any("10.0.0.3" in r or "8443" in r for r in result["added"]), \
        f"Added rule should reference new host: {result['added']}"
    print(f"  PASS  test_diff_asa_added — {len(result['added'])} added")


def test_diff_asa_removed():
    path_a = _write_tmp(ASA_V1)
    path_b = _write_tmp(ASA_V2)
    result = diff_asa(path_a, path_b)
    assert len(result["removed"]) >= 1, f"Expected ≥1 removed rule: {result['removed']}"
    assert any("10.0.0.2" in r or "eq 80" in r for r in result["removed"]), \
        f"Removed rule should reference old host: {result['removed']}"
    print(f"  PASS  test_diff_asa_removed — {len(result['removed'])} removed")


def test_diff_asa_unchanged():
    path_a = _write_tmp(ASA_V1)
    path_b = _write_tmp(ASA_V2)
    result = diff_asa(path_a, path_b)
    unchanged_flat = " ".join(result["unchanged"])
    assert "10.0.0.1" in unchanged_flat and "443" in unchanged_flat, \
        f"Common rule should be unchanged: {result['unchanged']}"
    print(f"  PASS  test_diff_asa_unchanged — {len(result['unchanged'])} unchanged")


def test_diff_asa_identical():
    path = _write_tmp(ASA_IDENTICAL)
    result = diff_asa(path, path)
    assert result["added"] == []
    assert result["removed"] == []
    assert len(result["unchanged"]) >= 1
    print(f"  PASS  test_diff_asa_identical — {len(result['unchanged'])} unchanged")


def test_diff_asa_log_normalization():
    """'log' variants should be treated as the same rule."""
    a = _write_tmp("access-list TEST extended permit tcp any host 10.0.0.1 eq 443 log\n")
    b = _write_tmp("access-list TEST extended permit tcp any host 10.0.0.1 eq 443\n")
    result = diff_asa(a, b)
    # Should be unchanged (same rule, log is stripped during normalization)
    assert result["added"] == [] and result["removed"] == [], \
        f"Log-stripped rules should match: added={result['added']}, removed={result['removed']}"
    print("  PASS  test_diff_asa_log_normalization")


def test_diff_configs_asa_dispatch():
    """diff_configs should dispatch to diff_asa for asa vendor."""
    path_a = _write_tmp(ASA_V1)
    path_b = _write_tmp(ASA_V2)
    result = diff_configs("asa", path_a, path_b)
    assert "added" in result
    print("  PASS  test_diff_configs_asa_dispatch")


def test_diff_configs_ftd_dispatch():
    """diff_configs should use diff_asa for ftd (same syntax)."""
    path_a = _write_tmp(ASA_V1)
    path_b = _write_tmp(ASA_V2)
    result = diff_configs("ftd", path_a, path_b)
    assert "added" in result
    print("  PASS  test_diff_configs_ftd_dispatch")


# ── diff_fortinet tests ───────────────────────────────────────────────────────

FORTI_V1 = """\
config firewall policy
    edit 1
        set name "Allow-HTTPS"
        set srcaddr "all"
        set dstaddr "WebServer"
        set action accept
        set service "HTTPS"
    next
    edit 2
        set name "Allow-SSH"
        set srcaddr "CorpNet"
        set dstaddr "Bastion"
        set action accept
        set service "SSH"
    next
    edit 3
        set name "Block-All"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
    next
end
"""

FORTI_V2 = """\
config firewall policy
    edit 1
        set name "Allow-HTTPS"
        set srcaddr "all"
        set dstaddr "WebServer"
        set action accept
        set service "HTTPS"
    next
    edit 2
        set name "Allow-DB"
        set srcaddr "AppServer"
        set dstaddr "DBServer"
        set action accept
        set service "MySQL"
    next
    edit 3
        set name "Block-All"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
    next
end
"""


def test_diff_fortinet_added():
    path_a = _write_tmp(FORTI_V1)
    path_b = _write_tmp(FORTI_V2)
    result = diff_fortinet(path_a, path_b)
    assert len(result["added"]) >= 1, f"Expected ≥1 added policy: {result['added']}"
    assert any("Allow-DB" in r for r in result["added"]), f"Allow-DB should be added: {result['added']}"
    print(f"  PASS  test_diff_fortinet_added — {len(result['added'])} added")


def test_diff_fortinet_removed():
    path_a = _write_tmp(FORTI_V1)
    path_b = _write_tmp(FORTI_V2)
    result = diff_fortinet(path_a, path_b)
    assert len(result["removed"]) >= 1, f"Expected ≥1 removed policy: {result['removed']}"
    assert any("Allow-SSH" in r for r in result["removed"]), f"Allow-SSH should be removed: {result['removed']}"
    print(f"  PASS  test_diff_fortinet_removed — {len(result['removed'])} removed")


def test_diff_fortinet_unchanged():
    path_a = _write_tmp(FORTI_V1)
    path_b = _write_tmp(FORTI_V2)
    result = diff_fortinet(path_a, path_b)
    unchanged_flat = " ".join(result["unchanged"])
    assert "Allow-HTTPS" in unchanged_flat or "Block-All" in unchanged_flat, \
        f"Common policies should be unchanged: {result['unchanged']}"
    print(f"  PASS  test_diff_fortinet_unchanged — {len(result['unchanged'])} unchanged")


def test_diff_configs_fortinet_dispatch():
    path_a = _write_tmp(FORTI_V1)
    path_b = _write_tmp(FORTI_V2)
    result = diff_configs("fortinet", path_a, path_b)
    assert "added" in result
    print("  PASS  test_diff_configs_fortinet_dispatch")


# ── diff_paloalto tests ───────────────────────────────────────────────────────

PA_V1 = """\
<?xml version="1.0"?>
<config><devices><entry><vsys><entry><security><rules>
  <entry name="Allow-HTTPS">
    <source><member>any</member></source>
    <destination><member>10.0.0.1</member></destination>
    <application><member>ssl</member></application>
    <service><member>application-default</member></service>
    <action>allow</action>
  </entry>
  <entry name="Allow-DNS">
    <source><member>10.0.0.0/8</member></source>
    <destination><member>8.8.8.8</member></destination>
    <application><member>dns</member></application>
    <service><member>application-default</member></service>
    <action>allow</action>
  </entry>
  <entry name="Deny-All">
    <source><member>any</member></source>
    <destination><member>any</member></destination>
    <application><member>any</member></application>
    <service><member>any</member></service>
    <action>deny</action>
  </entry>
</rules></security></entry></vsys></entry></devices></config>
"""

PA_V2 = """\
<?xml version="1.0"?>
<config><devices><entry><vsys><entry><security><rules>
  <entry name="Allow-HTTPS">
    <source><member>any</member></source>
    <destination><member>10.0.0.1</member></destination>
    <application><member>ssl</member></application>
    <service><member>application-default</member></service>
    <action>allow</action>
  </entry>
  <entry name="Allow-NTP">
    <source><member>10.0.0.0/8</member></source>
    <destination><member>time.cloudflare.com</member></destination>
    <application><member>ntp</member></application>
    <service><member>application-default</member></service>
    <action>allow</action>
  </entry>
  <entry name="Deny-All">
    <source><member>any</member></source>
    <destination><member>any</member></destination>
    <application><member>any</member></application>
    <service><member>any</member></service>
    <action>deny</action>
  </entry>
</rules></security></entry></vsys></entry></devices></config>
"""


def test_diff_paloalto_added():
    path_a = _write_xml(PA_V1)
    path_b = _write_xml(PA_V2)
    result = diff_paloalto(path_a, path_b)
    assert len(result["added"]) >= 1, f"Expected ≥1 added rule: {result['added']}"
    assert any("Allow-NTP" in r for r in result["added"]), f"Allow-NTP should be added: {result['added']}"
    print(f"  PASS  test_diff_paloalto_added — {len(result['added'])} added")


def test_diff_paloalto_removed():
    path_a = _write_xml(PA_V1)
    path_b = _write_xml(PA_V2)
    result = diff_paloalto(path_a, path_b)
    assert len(result["removed"]) >= 1, f"Expected ≥1 removed rule: {result['removed']}"
    assert any("Allow-DNS" in r for r in result["removed"]), f"Allow-DNS should be removed: {result['removed']}"
    print(f"  PASS  test_diff_paloalto_removed — {len(result['removed'])} removed")


def test_diff_paloalto_identical():
    path = _write_xml(PA_V1)
    result = diff_paloalto(path, path)
    assert result["added"] == []
    assert result["removed"] == []
    print(f"  PASS  test_diff_paloalto_identical — {len(result['unchanged'])} unchanged")


def test_diff_configs_paloalto_dispatch():
    path_a = _write_xml(PA_V1)
    path_b = _write_xml(PA_V2)
    result = diff_configs("paloalto", path_a, path_b)
    assert "added" in result
    print("  PASS  test_diff_configs_paloalto_dispatch")


# ── diff_pfsense tests ────────────────────────────────────────────────────────

PF_V1 = """\
<?xml version="1.0"?>
<pfsense><filter>
  <rule>
    <type>pass</type><interface>wan</interface>
    <source><any/></source><destination><address>10.0.0.1</address></destination>
    <protocol>tcp</protocol><log/><descr>Allow Web</descr>
  </rule>
  <rule>
    <type>pass</type><interface>lan</interface>
    <source><address>192.168.1.0/24</address></source>
    <destination><address>10.0.0.50</address></destination>
    <protocol>tcp</protocol><log/><descr>LAN App</descr>
  </rule>
  <rule>
    <type>block</type><interface>wan</interface>
    <source><any/></source><destination><any/></destination>
    <protocol>any</protocol><log/><descr>WAN Block</descr>
  </rule>
</filter></pfsense>
"""

PF_V2 = """\
<?xml version="1.0"?>
<pfsense><filter>
  <rule>
    <type>pass</type><interface>wan</interface>
    <source><any/></source><destination><address>10.0.0.1</address></destination>
    <protocol>tcp</protocol><log/><descr>Allow Web</descr>
  </rule>
  <rule>
    <type>pass</type><interface>lan</interface>
    <source><address>192.168.1.0/24</address></source>
    <destination><address>10.0.0.60</address></destination>
    <protocol>tcp</protocol><log/><descr>LAN DB</descr>
  </rule>
  <rule>
    <type>block</type><interface>wan</interface>
    <source><any/></source><destination><any/></destination>
    <protocol>any</protocol><log/><descr>WAN Block</descr>
  </rule>
</filter></pfsense>
"""


def test_diff_pfsense_added():
    path_a = _write_xml(PF_V1)
    path_b = _write_xml(PF_V2)
    result = diff_pfsense(path_a, path_b)
    assert len(result["added"]) >= 1, f"Expected ≥1 added rule: {result['added']}"
    print(f"  PASS  test_diff_pfsense_added — {len(result['added'])} added")


def test_diff_pfsense_removed():
    path_a = _write_xml(PF_V1)
    path_b = _write_xml(PF_V2)
    result = diff_pfsense(path_a, path_b)
    assert len(result["removed"]) >= 1, f"Expected ≥1 removed rule: {result['removed']}"
    print(f"  PASS  test_diff_pfsense_removed — {len(result['removed'])} removed")


def test_diff_pfsense_identical():
    path = _write_xml(PF_V1)
    result = diff_pfsense(path, path)
    assert result["added"] == []
    assert result["removed"] == []
    print(f"  PASS  test_diff_pfsense_identical — {len(result['unchanged'])} unchanged")


def test_diff_configs_pfsense_dispatch():
    path_a = _write_xml(PF_V1)
    path_b = _write_xml(PF_V2)
    result = diff_configs("pfsense", path_a, path_b)
    assert "added" in result
    print("  PASS  test_diff_configs_pfsense_dispatch")


# ── diff_aws tests ────────────────────────────────────────────────────────────

AWS_V1 = [{
    "GroupId": "sg-001",
    "GroupName": "web-tier",
    "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []},
        {"IpProtocol": "tcp", "FromPort": 80,  "ToPort": 80,  "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []},
    ],
}]

AWS_V2 = [{
    "GroupId": "sg-001",
    "GroupName": "web-tier",
    "IpPermissions": [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []},
        {"IpProtocol": "tcp", "FromPort": 8443, "ToPort": 8443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []},
    ],
}]


def test_diff_aws_added():
    path_a = _write_json(AWS_V1)
    path_b = _write_json(AWS_V2)
    result = diff_aws(path_a, path_b)
    assert len(result["added"]) >= 1, f"Expected ≥1 added rule: {result['added']}"
    assert any("8443" in r for r in result["added"])
    print(f"  PASS  test_diff_aws_added — {len(result['added'])} added")


def test_diff_aws_removed():
    path_a = _write_json(AWS_V1)
    path_b = _write_json(AWS_V2)
    result = diff_aws(path_a, path_b)
    assert len(result["removed"]) >= 1, f"Expected ≥1 removed rule: {result['removed']}"
    assert any("80" in r for r in result["removed"])
    print(f"  PASS  test_diff_aws_removed — {len(result['removed'])} removed")


def test_diff_aws_identical():
    path = _write_json(AWS_V1)
    result = diff_aws(path, path)
    assert result["added"] == []
    assert result["removed"] == []
    print(f"  PASS  test_diff_aws_identical — {len(result['unchanged'])} unchanged")


def test_diff_configs_aws_dispatch():
    path_a = _write_json(AWS_V1)
    path_b = _write_json(AWS_V2)
    result = diff_configs("aws", path_a, path_b)
    assert "added" in result
    print("  PASS  test_diff_configs_aws_dispatch")


# ── diff_azure tests ──────────────────────────────────────────────────────────

AZURE_V1 = [{
    "name": "web-nsg",
    "securityRules": [
        {"name": "Allow-443", "properties": {"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "*", "destinationPortRange": "443"}},
        {"name": "Allow-80",  "properties": {"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "*", "destinationPortRange": "80"}},
    ],
}]

AZURE_V2 = [{
    "name": "web-nsg",
    "securityRules": [
        {"name": "Allow-443",  "properties": {"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "*", "destinationPortRange": "443"}},
        {"name": "Allow-8443", "properties": {"direction": "Inbound", "access": "Allow", "sourceAddressPrefix": "*", "destinationPortRange": "8443"}},
    ],
}]


def test_diff_azure_added():
    path_a = _write_json(AZURE_V1)
    path_b = _write_json(AZURE_V2)
    result = diff_azure(path_a, path_b)
    assert len(result["added"]) >= 1, f"Expected ≥1 added rule: {result['added']}"
    assert any("Allow-8443" in r for r in result["added"])
    print(f"  PASS  test_diff_azure_added — {len(result['added'])} added")


def test_diff_azure_removed():
    path_a = _write_json(AZURE_V1)
    path_b = _write_json(AZURE_V2)
    result = diff_azure(path_a, path_b)
    assert len(result["removed"]) >= 1, f"Expected ≥1 removed rule: {result['removed']}"
    assert any("Allow-80" in r for r in result["removed"])
    print(f"  PASS  test_diff_azure_removed — {len(result['removed'])} removed")


def test_diff_azure_identical():
    path = _write_json(AZURE_V1)
    result = diff_azure(path, path)
    assert result["added"] == []
    assert result["removed"] == []
    print(f"  PASS  test_diff_azure_identical — {len(result['unchanged'])} unchanged")


def test_diff_configs_azure_dispatch():
    path_a = _write_json(AZURE_V1)
    path_b = _write_json(AZURE_V2)
    result = diff_configs("azure", path_a, path_b)
    assert "added" in result
    print("  PASS  test_diff_configs_azure_dispatch")


# ── diff_configs error handling ───────────────────────────────────────────────

def test_diff_configs_unsupported_vendor():
    try:
        diff_configs("gcp", "/tmp/a", "/tmp/b")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Unsupported vendor" in str(e)
    print("  PASS  test_diff_configs_unsupported_vendor")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n── Diff Engine Tests ──\n")
    failures = 0
    tests = [
        test_diff_asa_added, test_diff_asa_removed, test_diff_asa_unchanged,
        test_diff_asa_identical, test_diff_asa_log_normalization,
        test_diff_configs_asa_dispatch, test_diff_configs_ftd_dispatch,
        test_diff_fortinet_added, test_diff_fortinet_removed, test_diff_fortinet_unchanged,
        test_diff_configs_fortinet_dispatch,
        test_diff_paloalto_added, test_diff_paloalto_removed, test_diff_paloalto_identical,
        test_diff_configs_paloalto_dispatch,
        test_diff_pfsense_added, test_diff_pfsense_removed, test_diff_pfsense_identical,
        test_diff_configs_pfsense_dispatch,
        test_diff_aws_added, test_diff_aws_removed, test_diff_aws_identical,
        test_diff_configs_aws_dispatch,
        test_diff_azure_added, test_diff_azure_removed, test_diff_azure_identical,
        test_diff_configs_azure_dispatch,
        test_diff_configs_unsupported_vendor,
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
