"""Tests for pfSense parser and normalized audit findings."""

import json
import os
import tempfile

from cashel.export import to_csv, to_json, to_sarif
from cashel.pfsense import (
    _f,
    audit_pfsense,
    check_any_any_pf,
    check_missing_logging_pf,
    check_wan_any_source_pf,
    parse_pfsense,
)
from cashel.remediation import generate_plan
from cashel.rule_quality import check_shadow_rules_pfsense

TESTS_DIR = os.path.dirname(__file__)

PFSENSE_RICH = """\
<?xml version="1.0"?>
<pfsense>
  <filter>
    <rule>
      <tracker>1001</tracker>
      <type>pass</type>
      <interface>wan</interface>
      <source><any/></source>
      <destination><any/></destination>
      <protocol>any</protocol>
      <descr>Allow All</descr>
    </rule>
    <rule>
      <tracker>1002</tracker>
      <type>pass</type>
      <interface>wan</interface>
      <source><any/></source>
      <destination>
        <address>10.0.0.1</address>
        <port>443</port>
      </destination>
      <protocol>tcp</protocol>
      <log/>
      <descr>Allow Web</descr>
    </rule>
    <rule>
      <tracker>1003</tracker>
      <type>block</type>
      <interface>wan</interface>
      <source><any/></source>
      <destination><any/></destination>
      <protocol>any</protocol>
      <log/>
      <descr>Block All</descr>
    </rule>
  </filter>
</pfsense>
"""


def _write_tmp(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".xml")
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    return path


def _rules():
    rules, error = parse_pfsense(os.path.join(TESTS_DIR, "test_pfsense.xml"))
    assert error is None
    return rules


def test_parse_pfsense_returns_rules_and_error_tuple():
    rules, error = parse_pfsense(os.path.join(TESTS_DIR, "test_pfsense.xml"))

    assert error is None
    assert rules
    assert rules[0]["descr"] == "Allow All"


def test_parse_pfsense_captures_rule_evidence_and_metadata_fields():
    path = _write_tmp(PFSENSE_RICH)
    try:
        rules, error = parse_pfsense(path)
    finally:
        os.unlink(path)

    assert error is None
    first = rules[0]
    web = rules[1]
    assert first["tracker"] == "1001"
    assert first["disabled"] is False
    assert "<tracker>1001</tracker>" in first["_raw"]
    assert web["destination_port"] == "443"


def test_audit_pfsense_returns_existing_public_shape():
    findings, rules = audit_pfsense(os.path.join(TESTS_DIR, "test_pfsense.xml"))

    assert findings
    assert rules
    assert all(isinstance(finding, dict) for finding in findings)


def test_pfsense_legacy_helper_shape_still_works():
    finding = _f("LOW", "hygiene", "[LOW] Legacy pfSense finding", "Fix it.")

    assert finding["severity"] == "LOW"
    assert finding["category"] == "hygiene"
    assert finding["message"] == "[LOW] Legacy pfSense finding"
    assert finding["remediation"] == "Fix it."
    assert finding["vendor"] == "pfsense"


def test_pfsense_findings_keep_legacy_keys_and_enriched_fields():
    findings, _rules_out = audit_pfsense(os.path.join(TESTS_DIR, "test_pfsense.xml"))

    for finding in findings:
        assert finding["severity"]
        assert finding["category"]
        assert finding["message"]
        assert "remediation" in finding
        assert finding["id"].startswith("CASHEL-PFSENSE-")
        assert finding["vendor"] == "pfsense"
        assert finding["title"]
        assert finding["evidence"]
        assert finding["confidence"]
        assert isinstance(finding["metadata"], dict)


def test_pfsense_any_any_finding_includes_rule_metadata():
    finding = check_any_any_pf(_rules())[0]
    metadata = finding["metadata"]

    assert finding["id"] == "CASHEL-PFSENSE-EXPOSURE-001"
    assert finding["rule_name"] == "Allow All"
    assert finding["affected_object"] == "Allow All"
    assert "<descr>Allow All</descr>" in finding["evidence"]
    assert metadata["interface"] == "wan"
    assert metadata["source"] == "1"
    assert metadata["destination"] == "1"
    assert metadata["protocol"] == "any"
    assert metadata["type"] == "pass"
    assert metadata["action"] == "pass"
    assert metadata["log"] is False


def test_pfsense_missing_logging_finding_includes_logging_metadata():
    finding = check_missing_logging_pf(_rules())[0]

    assert finding["id"] == "CASHEL-PFSENSE-LOGGING-001"
    assert finding["metadata"]["log"] is False
    assert "Enable Log packets" in "\n".join(finding["suggested_commands"])


def test_pfsense_wan_exposure_uses_ui_style_guidance():
    finding = check_wan_any_source_pf(_rules())[0]
    commands = "\n".join(finding["suggested_commands"])

    assert finding["id"] == "CASHEL-PFSENSE-EXPOSURE-002"
    assert "pfSense UI: Firewall > Rules > WAN" in commands
    assert "pfctl" not in commands.lower()


def test_pfsense_remediation_plan_consumes_commands_and_evidence():
    finding = check_missing_logging_pf(_rules())[0]
    plan = generate_plan([finding], "pfsense")
    step = plan["phases"][0]["steps"][0]

    assert step["id"] == "CASHEL-PFSENSE-LOGGING-001"
    assert step["title"] == finding["title"]
    assert step["evidence"] == finding["evidence"]
    assert "Enable Log packets" in step["suggested_commands"]


def test_pfsense_exports_preserve_enriched_fields():
    finding = check_any_any_pf(_rules())[0]
    entry = {
        "filename": "config.xml",
        "vendor": "pfsense",
        "findings": [finding],
        "summary": {"total": 1},
    }

    json_out = json.loads(to_json(entry))
    assert json_out["findings"][0]["id"] == "CASHEL-PFSENSE-EXPOSURE-001"
    assert json_out["findings"][0]["metadata"]["interface"] == "wan"

    csv_out = to_csv(entry)
    assert "CASHEL-PFSENSE-EXPOSURE-001" in csv_out
    assert "Allow All" in csv_out

    sarif_out = json.loads(to_sarif(entry))
    result = sarif_out["runs"][0]["results"][0]
    rule = sarif_out["runs"][0]["tool"]["driver"]["rules"][0]
    assert result["ruleId"] == "CASHEL-PFSENSE-EXPOSURE-001"
    assert result["properties"]["evidence"] == finding["evidence"]
    assert rule["id"] == "CASHEL-PFSENSE-EXPOSURE-001"


def test_pfsense_old_and_plain_findings_remain_compatible():
    old_dict = {
        "severity": "MEDIUM",
        "category": "logging",
        "message": "[MEDIUM] pfSense rule missing logging.",
        "remediation": "Enable logging in the pfSense UI.",
    }
    plan = generate_plan([old_dict, "[LOW] Plain archive finding"], "pfsense")

    assert plan["total_steps"] == 1
    step = plan["phases"][0]["steps"][0]
    assert step["description"] == old_dict["message"]
    assert "suggested_commands" not in step


def test_rule_quality_still_accepts_pfsense_rule_list():
    findings = check_shadow_rules_pfsense(_rules())

    assert findings
    assert findings[0]["id"] == "CASHEL-PFSENSE-REDUNDANCY-001"
