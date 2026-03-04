import xml.etree.ElementTree as ET


def parse_pfsense(filepath):
    """Parse a pfSense XML config and return firewall rules"""
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        return None, f"Failed to parse pfSense config: {e}"

    rules = []
    for rule in root.findall(".//filter/rule"):
        r = {
            "type": rule.findtext("type") or "pass",
            "interface": rule.findtext("interface") or "",
            "source": rule.findtext("source/any") or rule.findtext("source/address") or "specific",
            "destination": rule.findtext("destination/any") or rule.findtext("destination/address") or "specific",
            "protocol": rule.findtext("protocol") or "any",
            "log": rule.find("log") is not None,
            "descr": rule.findtext("descr") or "unnamed"
        }
        rules.append(r)

    return rules, None


def check_any_any_pf(rules):
    findings = []
    for r in rules:
        if r["type"] == "pass" and r["source"] == "1" and r["destination"] == "1":
            findings.append(f"[HIGH] Overly permissive rule '{r['descr']}': source=any destination=any")
    return findings


def check_missing_logging_pf(rules):
    findings = []
    for r in rules:
        if r["type"] == "pass" and not r["log"]:
            findings.append(f"[MEDIUM] Permit rule '{r['descr']}' missing logging")
    return findings


def check_deny_all_pf(rules):
    findings = []
    has_deny_all = any(
        r["type"] == "block" and r["source"] == "1" and r["destination"] == "1"
        for r in rules
    )
    if not has_deny_all:
        findings.append("[HIGH] No explicit deny-all rule found")
    return findings


def check_redundant_rules_pf(rules):
    findings = []
    seen = []
    for r in rules:
        signature = (r["type"], r["source"], r["destination"], r["protocol"])
        if signature in seen:
            findings.append(f"[MEDIUM] Redundant rule detected: '{r['descr']}'")
        else:
            seen.append(signature)
    return findings


def audit_pfsense(filepath):
    rules, error = parse_pfsense(filepath)
    if error:
        return [f"[ERROR] {error}"], []

    findings = []
    findings += check_any_any_pf(rules)
    findings += check_missing_logging_pf(rules)
    findings += check_deny_all_pf(rules)
    findings += check_redundant_rules_pf(rules)
    return findings, rules