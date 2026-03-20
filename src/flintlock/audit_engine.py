"""Shared audit engine utilities used by both web.py and scheduler_runner.py.

Extracts the vendor-dispatch logic and finding helpers so they can be
imported without creating circular dependencies.
"""
from ciscoconfparse import CiscoConfParse


# ── Finding helpers ────────────────────────────────────────────────────────────

def _f(severity, category, message, remediation=""):
    return {"severity": severity, "category": category, "message": message, "remediation": remediation}


def _finding_msg(f):
    return f["message"] if isinstance(f, dict) else f


def _findings_to_strings(findings):
    return [_finding_msg(f) for f in findings]


def _wrap_compliance(s):
    if isinstance(s, dict):
        return s
    sev = "HIGH" if any(x in s for x in ("-HIGH", "[HIGH]")) else "MEDIUM"
    return {"severity": sev, "category": "compliance", "message": s, "remediation": None}


def _sort_findings(findings: list) -> list:
    def priority(f):
        msg = _finding_msg(f)
        is_comp = any(x in msg for x in ("PCI-", "CIS-", "NIST-", "HIPAA-"))
        if "[HIGH]"   in msg and not is_comp:
            return 0
        if "[MEDIUM]" in msg and not is_comp:
            return 1
        if "HIGH"     in msg and is_comp:
            return 2
        if "MEDIUM"   in msg and is_comp:
            return 3
        return 4
    return sorted(findings, key=priority)


def _build_summary(findings):
    def _count(tag):
        return len([f for f in findings if tag in _finding_msg(f)])
    high   = [f for f in findings if "[HIGH]"   in _finding_msg(f) and not any(x in _finding_msg(f) for x in ["PCI-", "CIS-", "NIST-", "HIPAA-"])]
    medium = [f for f in findings if "[MEDIUM]" in _finding_msg(f) and not any(x in _finding_msg(f) for x in ["PCI-", "CIS-", "NIST-", "HIPAA-"])]
    score  = max(0, 100 - len(high) * 10 - len(medium) * 3)
    return {
        "high":          len(high),
        "medium":        len(medium),
        "pci_high":      _count("PCI-HIGH"),
        "pci_medium":    _count("PCI-MEDIUM"),
        "cis_high":      _count("CIS-HIGH"),
        "cis_medium":    _count("CIS-MEDIUM"),
        "nist_high":     _count("NIST-HIGH"),
        "nist_medium":   _count("NIST-MEDIUM"),
        "hipaa_high":    _count("HIPAA-HIGH"),
        "hipaa_medium":  _count("HIPAA-MEDIUM"),
        "total":         len(findings),
        "score":         score,
    }


# ── ASA audit helpers ──────────────────────────────────────────────────────────

def _check_any_any(parse):
    return [
        _f("HIGH", "exposure",
           f"[HIGH] Overly permissive rule found: {r.text.strip()}",
           "Restrict source and destination to specific IP ranges. "
           "Remove or scope down any/any permit rules to enforce least-privilege access.")
        for r in parse.find_objects(r"access-list.*permit.*any any")
    ]


def _check_missing_logging(parse):
    return [
        _f("MEDIUM", "logging",
           f"[MEDIUM] Permit rule missing logging: {r.text.strip()}",
           "Add the 'log' keyword to all permit rules. "
           "Without logging, permitted traffic produces no syslog entries for monitoring.")
        for r in parse.find_objects(r"access-list.*permit") if "log" not in r.text
    ]


def _check_deny_all(parse):
    if parse.find_objects(r"access-list.*deny ip any any"):
        return []
    return [_f(
        "HIGH", "hygiene",
        "[HIGH] No explicit deny-all rule found at end of ACL",
        "Add an explicit 'access-list <name> deny ip any any log' at the end of each ACL. "
        "Relying on implicit deny produces no log entries and is not auditable."
    )]


def _check_redundant_rules(parse):
    findings, seen = [], []
    for rule in parse.find_objects(r"access-list.*permit"):
        text_clean = rule.text.strip().lower().replace(" log", "").strip()
        if text_clean in seen:
            findings.append(_f(
                "MEDIUM", "redundancy",
                f"[MEDIUM] Redundant rule detected: {rule.text.strip()}",
                "Remove duplicate ACL entries to keep the access-list clean and auditable. "
                "Redundant rules indicate configuration drift and complicate change management."
            ))
        else:
            seen.append(text_clean)
    return findings


def _check_telnet_asa(parse):
    return [
        _f("MEDIUM", "protocol",
           f"[MEDIUM] Telnet management access configured: {r.text.strip()}",
           "Disable Telnet management (no telnet ...) and enforce SSH. "
           "Telnet transmits all data including credentials in cleartext.")
        for r in parse.find_objects(r"^telnet\s")
    ]


def _check_icmp_any_asa(parse):
    return [
        _f("MEDIUM", "exposure",
           f"[MEDIUM] Unrestricted ICMP permit rule: {r.text.strip()}",
           "Restrict ICMP to specific source ranges or permit only echo-reply, "
           "unreachable, and time-exceeded message types needed for diagnostics.")
        for r in parse.find_objects(r"access-list.*permit icmp any any")
    ]


def _audit_asa(filepath):
    parse = CiscoConfParse(filepath, ignore_blank_lines=False)
    findings = (
        _check_any_any(parse)
        + _check_missing_logging(parse)
        + _check_deny_all(parse)
        + _check_redundant_rules(parse)
        + _check_telnet_asa(parse)
        + _check_icmp_any_asa(parse)
    )
    return findings, parse


# ── Vendor dispatch ────────────────────────────────────────────────────────────

def run_vendor_audit(vendor: str, temp_path: str):
    """
    Run the appropriate auditor for the given vendor.
    Returns (findings, parse_obj_or_None, extra_data_or_None).
    parse_obj is set for ASA/FTD (CiscoConfParse).
    extra_data is set for Fortinet/pfSense (list of policy dicts).
    """
    from .ftd import audit_ftd
    from .paloalto import audit_paloalto
    from .fortinet import audit_fortinet
    from .pfsense import audit_pfsense
    from .aws import audit_aws_sg
    from .azure import audit_azure_nsg

    if vendor == "ftd":
        findings, parse = audit_ftd(temp_path)
        return findings, parse, None
    if vendor == "asa":
        findings, parse = _audit_asa(temp_path)
        return findings, parse, None
    if vendor == "paloalto":
        findings, rules = audit_paloalto(temp_path)
        return findings, None, rules  # rules returned as extra_data for compliance reuse
    if vendor == "fortinet":
        findings, extra_data = audit_fortinet(temp_path)
        return findings, None, extra_data
    if vendor == "pfsense":
        findings, extra_data = audit_pfsense(temp_path)
        return findings, None, extra_data
    if vendor == "aws":
        findings, extra_data = audit_aws_sg(temp_path)
        return findings, None, extra_data
    if vendor == "azure":
        findings, extra_data = audit_azure_nsg(temp_path)
        return findings, None, extra_data
    raise ValueError(f"Unknown vendor: {vendor}")


def run_compliance_checks(vendor: str, compliance: str, parse, extra_data, temp_path: str = "") -> list:
    """Run compliance checks for the given vendor and framework. Returns raw finding strings.

    For paloalto, extra_data should be the rules list returned by run_vendor_audit — the file
    is NOT re-parsed here, eliminating the double-parse that would otherwise occur.
    """
    from .compliance import (
        check_cis_compliance, check_pci_compliance, check_nist_compliance,
        check_hipaa_compliance,
        check_cis_compliance_ftd, check_pci_compliance_ftd, check_nist_compliance_ftd,
        check_hipaa_compliance_ftd,
        check_cis_compliance_pa, check_pci_compliance_pa, check_nist_compliance_pa,
        check_hipaa_compliance_pa,
        check_cis_compliance_forti, check_pci_compliance_forti, check_nist_compliance_forti,
        check_hipaa_compliance_forti,
        check_cis_compliance_pf, check_pci_compliance_pf, check_nist_compliance_pf,
        check_hipaa_compliance_pf,
    )

    if vendor in ("aws", "azure"):
        return []

    fn_map: dict = {}

    if vendor == "asa":
        fn_map = {
            "cis":   (check_cis_compliance,   parse),
            "pci":   (check_pci_compliance,   parse),
            "nist":  (check_nist_compliance,  parse),
            "hipaa": (check_hipaa_compliance, parse),
        }
    elif vendor == "ftd":
        fn_map = {
            "cis":   (check_cis_compliance_ftd,   parse),
            "pci":   (check_pci_compliance_ftd,   parse),
            "nist":  (check_nist_compliance_ftd,  parse),
            "hipaa": (check_hipaa_compliance_ftd, parse),
        }
    elif vendor == "paloalto":
        # extra_data is the rules list already parsed by run_vendor_audit — no re-parse needed
        rules = extra_data or []
        fn_map = {
            "cis":   (check_cis_compliance_pa,   rules),
            "pci":   (check_pci_compliance_pa,   rules),
            "nist":  (check_nist_compliance_pa,  rules),
            "hipaa": (check_hipaa_compliance_pa, rules),
        }
    elif vendor == "fortinet":
        fn_map = {
            "cis":   (check_cis_compliance_forti,   extra_data),
            "pci":   (check_pci_compliance_forti,   extra_data),
            "nist":  (check_nist_compliance_forti,  extra_data),
            "hipaa": (check_hipaa_compliance_forti, extra_data),
        }
    elif vendor == "pfsense":
        fn_map = {
            "cis":   (check_cis_compliance_pf,   extra_data),
            "pci":   (check_pci_compliance_pf,   extra_data),
            "nist":  (check_nist_compliance_pf,  extra_data),
            "hipaa": (check_hipaa_compliance_pf, extra_data),
        }

    entry = fn_map.get(compliance)
    if not entry:
        return []
    fn, arg = entry
    if arg is None:
        return []
    return fn(arg)
