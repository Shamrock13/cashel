import xml.etree.ElementTree as ET


def parse_paloalto(filepath):
    """Parse a Palo Alto XML config and return security rules"""
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        return None, f"Failed to parse Palo Alto config: {e}"

    # Find security rules - standard PA config path
    rules = root.findall(".//security/rules/entry")
    return rules, None


def check_any_any_pa(rules):
    findings = []
    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")

        if action == "allow" and "any" in src and "any" in dst:
            findings.append(f"[HIGH] Overly permissive rule '{name}': source=any destination=any")
    return findings


def check_missing_logging_pa(rules):
    findings = []
    for rule in rules:
        name = rule.get("name", "unnamed")
        log_end = rule.findtext(".//log-end")
        log_start = rule.findtext(".//log-start")
        action = rule.findtext(".//action")

        if action == "allow" and log_end != "yes" and log_start != "yes":
            findings.append(f"[MEDIUM] Permit rule '{name}' missing logging")
    return findings


def check_deny_all_pa(rules):
    findings = []
    has_deny_all = False

    for rule in rules:
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")

        if action == "deny" and "any" in src and "any" in dst:
            has_deny_all = True
            break

    if not has_deny_all:
        findings.append("[HIGH] No explicit deny-all rule found")
    return findings


def check_redundant_rules_pa(rules):
    findings = []
    seen = []

    for rule in rules:
        name = rule.get("name", "unnamed")
        src = tuple(sorted([s.text for s in rule.findall(".//source/member")]))
        dst = tuple(sorted([d.text for d in rule.findall(".//destination/member")]))
        app = tuple(sorted([a.text for a in rule.findall(".//application/member")]))
        action = rule.findtext(".//action")

        signature = (src, dst, app, action)
        if signature in seen:
            findings.append(f"[MEDIUM] Redundant rule detected: '{name}'")
        else:
            seen.append(signature)
    return findings


def audit_paloalto(filepath):
    rules, error = parse_paloalto(filepath)
    if error:
        return [f"[ERROR] {error}"]

    findings = []
    findings += check_any_any_pa(rules)
    findings += check_missing_logging_pa(rules)
    findings += check_deny_all_pa(rules)
    findings += check_redundant_rules_pa(rules)
    return findings