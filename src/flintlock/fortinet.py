import re


def parse_fortinet(filepath):
    """Parse a FortiGate config and return firewall policies"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
    except Exception as e:
        return None, f"Failed to read FortiGate config: {e}"

    policies = []
    current_policy = None

    for line in content.splitlines():
        line = line.strip()

        if line.startswith("edit "):
            current_policy = {"id": line.split("edit ")[1], "srcaddr": [], "dstaddr": [], 
                            "service": [], "action": "", "logtraffic": "", "name": ""}

        elif current_policy is not None:
            if line.startswith("set name "):
                current_policy["name"] = line.split("set name ")[1].strip('"')
            elif line.startswith("set srcaddr "):
                current_policy["srcaddr"] = [x.strip('"') for x in line.replace("set srcaddr ", "").strip().split()]
            elif line.startswith("set dstaddr "):
                current_policy["dstaddr"] = [x.strip('"') for x in line.replace("set dstaddr ", "").strip().split()]
            elif line.startswith("set service "):
                current_policy["service"] = [x.strip('"') for x in line.replace("set service ", "").strip().split()]
            elif line.startswith("set action "):
                current_policy["action"] = line.split("set action ")[1].strip().strip('"')
            elif line.startswith("set logtraffic "):
                current_policy["logtraffic"] = line.split("set logtraffic ")[1].strip().strip('"')
            elif line == "next":
                policies.append(current_policy)
                current_policy = None

    return policies, None


def check_any_any_forti(policies):
    findings = []
    for p in policies:
        name = p.get("name") or f"Policy ID {p.get('id')}"
        src = p.get("srcaddr", [])
        dst = p.get("dstaddr", [])
        action = p.get("action", "")

        if action == "accept" and "all" in src and "all" in dst:
            findings.append(f"[HIGH] Overly permissive rule '{name}': source=all destination=all")
    return findings


def check_missing_logging_forti(policies):
    findings = []
    for p in policies:
        name = p.get("name") or f"Policy ID {p.get('id')}"
        action = p.get("action", "")
        logtraffic = p.get("logtraffic", "")

        if action == "accept" and logtraffic not in ["all", "utm"]:
            findings.append(f"[MEDIUM] Permit rule '{name}' missing logging")
    return findings


def check_deny_all_forti(policies):
    findings = []
    has_deny_all = False

    for p in policies:
        src = p.get("srcaddr", [])
        dst = p.get("dstaddr", [])
        action = p.get("action", "")

        if action == "deny" and "all" in src and "all" in dst:
            has_deny_all = True
            break

    if not has_deny_all:
        findings.append("[HIGH] No explicit deny-all rule found")
    return findings


def check_redundant_rules_forti(policies):
    findings = []
    seen = []

    for p in policies:
        name = p.get("name") or f"Policy ID {p.get('id')}"
        src = tuple(sorted(p.get("srcaddr", [])))
        dst = tuple(sorted(p.get("dstaddr", [])))
        svc = tuple(sorted(p.get("service", [])))
        action = p.get("action", "")

        signature = (src, dst, svc, action)
        if signature in seen:
            findings.append(f"[MEDIUM] Redundant rule detected: '{name}'")
        else:
            seen.append(signature)
    return findings


def audit_fortinet(filepath):
    policies, error = parse_fortinet(filepath)
    if error:
        return [f"[ERROR] {error}"]

    findings = []
    findings += check_any_any_forti(policies)
    findings += check_missing_logging_forti(policies)
    findings += check_deny_all_forti(policies)
    findings += check_redundant_rules_forti(policies)
    return findings, policies