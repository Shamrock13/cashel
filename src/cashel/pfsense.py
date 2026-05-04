# defusedxml prevents XXE (XML External Entity) injection attacks when parsing
# user-supplied firewall configs.  Drop-in replacement for ElementTree.
from defusedxml import ElementTree as ET

from .models.findings import make_finding


def _f(
    severity,
    category,
    message,
    remediation="",
    *,
    id=None,
    vendor="pfsense",
    title=None,
    evidence=None,
    affected_object=None,
    rule_id=None,
    rule_name=None,
    confidence="medium",
    impact=None,
    verification=None,
    rollback=None,
    compliance_refs=None,
    suggested_commands=None,
    metadata=None,
):
    """Build a structured finding dict."""
    return make_finding(
        severity,
        category,
        message,
        remediation,
        id=id,
        vendor=vendor,
        title=title,
        evidence=evidence,
        affected_object=affected_object,
        rule_id=rule_id,
        rule_name=rule_name,
        confidence=confidence,
        impact=impact,
        verification=verification,
        rollback=rollback,
        compliance_refs=compliance_refs,
        suggested_commands=suggested_commands,
        metadata=metadata,
    )


def _rule_name(rule):
    return rule.get("descr") or rule.get("tracker") or "unnamed"


def _rule_ref(rule):
    return rule.get("tracker") or _rule_name(rule)


def _rule_evidence(rule):
    return rule.get("_raw") or (
        f"interface={rule.get('interface', '')} type={rule.get('type', '')} "
        f"source={rule.get('source', '')} destination={rule.get('destination', '')} "
        f"protocol={rule.get('protocol', '')} log={rule.get('log', False)}"
    )


def _rule_metadata(rule):
    return {
        "rule_description": rule.get("descr", ""),
        "interface": rule.get("interface", ""),
        "type": rule.get("type", ""),
        "action": rule.get("type", ""),
        "protocol": rule.get("protocol", ""),
        "source": rule.get("source", ""),
        "destination": rule.get("destination", ""),
        "source_port": rule.get("source_port", ""),
        "destination_port": rule.get("destination_port", ""),
        "log": rule.get("log", False),
        "disabled": rule.get("disabled", False),
        "tracker": rule.get("tracker", ""),
        "raw": _rule_evidence(rule),
    }


def _rule_kwargs(
    rule,
    title,
    *,
    id,
    confidence="high",
    impact=None,
    verification=None,
    rollback=None,
    suggested_commands=None,
    metadata=None,
):
    merged_metadata = _rule_metadata(rule)
    if metadata:
        merged_metadata.update(metadata)
    return {
        "id": id,
        "title": title,
        "evidence": _rule_evidence(rule),
        "affected_object": _rule_ref(rule),
        "rule_id": rule.get("tracker") or None,
        "rule_name": _rule_name(rule),
        "confidence": confidence,
        "impact": impact,
        "verification": verification,
        "rollback": rollback,
        "suggested_commands": suggested_commands or [],
        "metadata": merged_metadata,
    }


def _ui_rule_path(rule):
    interface = (rule.get("interface") or "<INTERFACE>").upper()
    ref = _rule_ref(rule)
    return f"pfSense UI: Firewall > Rules > {interface} > edit rule {ref}"


def _rule_guidance(rule, *actions):
    return [_ui_rule_path(rule), *actions]


def _rule_endpoint(rule, field):
    if rule.find(f"{field}/any") is not None:
        return "1"
    return rule.findtext(f"{field}/address") or "specific"


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
            "source": _rule_endpoint(rule, "source"),
            "destination": _rule_endpoint(rule, "destination"),
            "source_port": rule.findtext("source/port") or "",
            "destination_port": rule.findtext("destination/port") or "",
            "protocol": rule.findtext("protocol") or "any",
            "log": rule.find("log") is not None,
            "disabled": rule.find("disabled") is not None,
            "descr": rule.findtext("descr") or "",
            "tracker": rule.findtext("tracker") or "",
            "_raw": ET.tostring(rule, encoding="unicode"),
        }
        rules.append(r)

    return rules, None


def check_any_any_pf(rules):
    findings = []
    for r in rules:
        if r["type"] == "pass" and r["source"] == "1" and r["destination"] == "1":
            name = r["descr"] or "unnamed"
            findings.append(
                _f(
                    "HIGH",
                    "exposure",
                    f"[HIGH] Overly permissive rule '{name}': source=any destination=any",
                    "Restrict source and destination to specific hosts or networks. "
                    "Pass-all rules allow unrestricted traffic between all segments.",
                    **_rule_kwargs(
                        r,
                        "pfSense pass rule allows any source to any destination",
                        id="CASHEL-PFSENSE-EXPOSURE-001",
                        impact="A broad pass rule can allow unintended traffic through the interface.",
                        verification=(
                            "Confirm the rule no longer uses any for both source and destination, "
                            "then re-run the audit."
                        ),
                        rollback="Restore the prior rule from a pfSense config backup if approved traffic is disrupted.",
                        suggested_commands=_rule_guidance(
                            r,
                            "Set source to <SPECIFIC_SOURCE_ALIAS>",
                            "Set destination to <SPECIFIC_DESTINATION_ALIAS>",
                            "Disable or remove the rule only after confirming no approved traffic depends on it",
                        ),
                    ),
                )
            )
    return findings


def check_missing_logging_pf(rules):
    findings = []
    for r in rules:
        if r["type"] == "pass" and not r["log"]:
            name = r["descr"] or "unnamed"
            findings.append(
                _f(
                    "MEDIUM",
                    "logging",
                    f"[MEDIUM] Permit rule '{name}' missing logging",
                    "Enable logging on all pass rules to ensure permitted traffic is recorded "
                    "for audit trail, compliance, and incident response purposes.",
                    **_rule_kwargs(
                        r,
                        "pfSense pass rule is missing logging",
                        id="CASHEL-PFSENSE-LOGGING-001",
                        impact="Permitted traffic may not appear in firewall logs for investigation or compliance review.",
                        verification="Confirm firewall logs show traffic handled by the rule after enabling logging.",
                        rollback="Disable rule logging if volume is excessive and an approved alternate logging control exists.",
                        suggested_commands=_rule_guidance(
                            r,
                            "Enable Log packets that are handled by this rule",
                        ),
                    ),
                )
            )
    return findings


def check_deny_all_pf(rules):
    has_deny_all = any(
        r["type"] == "block" and r["source"] == "1" and r["destination"] == "1"
        for r in rules
    )
    if has_deny_all:
        return []
    return [
        _f(
            "HIGH",
            "hygiene",
            "[HIGH] No explicit deny-all rule found",
            "Add an explicit block-all rule at the bottom of the ruleset. "
            "pfSense has a default deny, but an explicit logged rule confirms the policy and aids monitoring.",
            id="CASHEL-PFSENSE-HYGIENE-001",
            title="pfSense ruleset is missing an explicit deny-all rule",
            evidence="No block rule with source any and destination any was found.",
            affected_object="filter rules",
            confidence="medium",
            impact="The ruleset relies on implicit default behavior and may lack logged deny evidence.",
            verification="Confirm a final logged block rule exists after pass rules on relevant interfaces.",
            rollback="Disable or remove the new block rule from the pfSense UI if it blocks approved traffic.",
            suggested_commands=[
                "pfSense UI: Firewall > Rules > <INTERFACE> > add rule at bottom",
                "Set action to Block",
                "Set source to any",
                "Set destination to any",
                "Enable Log packets that are handled by this rule",
            ],
            metadata={"checked_rules": [_rule_name(rule) for rule in rules]},
        )
    ]


def check_redundant_rules_pf(rules):
    findings = []
    seen = []
    for r in rules:
        name = r["descr"] or "unnamed"
        sig = (r["type"], r["source"], r["destination"], r["protocol"])
        if sig in seen:
            findings.append(
                _f(
                    "MEDIUM",
                    "redundancy",
                    f"[MEDIUM] Redundant rule detected: '{name}'",
                    "Remove duplicate rules to keep the ruleset concise. "
                    "Duplicate rules can mask effective policy intent and complicate reviews.",
                    **_rule_kwargs(
                        r,
                        "pfSense rule duplicates an earlier rule",
                        id="CASHEL-PFSENSE-REDUNDANCY-002",
                        impact="Duplicate rules increase review effort and can obscure the intended policy.",
                        verification="Confirm duplicate rules are removed or consolidated, then re-run the audit.",
                        rollback="Restore the removed rule from a pfSense config backup if traffic changes unexpectedly.",
                        suggested_commands=_rule_guidance(
                            r,
                            "Disable or remove the duplicate rule only after confirming no approved traffic depends on it",
                        ),
                        metadata={"duplicate_signature": sig},
                    ),
                )
            )
        else:
            seen.append(sig)
    return findings


def check_missing_description_pf(rules):
    """Flag rules with no meaningful description."""
    generic = {
        "",
        "unnamed",
        "default allow lan to any rule",
        "default deny rule",
        "anti-lockout rule",
    }
    findings = []
    for r in rules:
        desc = (r.get("descr") or "").strip().lower()
        if desc in generic:
            display = r.get("descr") or "unnamed"
            findings.append(
                _f(
                    "MEDIUM",
                    "hygiene",
                    f"[MEDIUM] Rule '{display}' has no meaningful description",
                    "Add a descriptive label to every rule documenting its purpose, owner, and associated change request.",
                    **_rule_kwargs(
                        r,
                        "pfSense rule is missing a meaningful description",
                        id="CASHEL-PFSENSE-HYGIENE-002",
                        impact="Missing descriptions slow audits, troubleshooting, and change reviews.",
                        verification="Confirm the rule description documents purpose, owner, and change reference.",
                        rollback="Restore the prior description if the new description is inaccurate.",
                        suggested_commands=_rule_guidance(
                            r,
                            "Set description to <PURPOSE_OWNER_CHANGE_REFERENCE>",
                        ),
                    ),
                )
            )
    return findings


def check_wan_any_source_pf(rules):
    """Flag WAN-facing pass rules that allow any source."""
    findings = []
    for r in rules:
        if (
            r["type"] == "pass"
            and r["interface"].lower() == "wan"
            and r["source"] == "1"
        ):
            name = r["descr"] or "unnamed"
            findings.append(
                _f(
                    "HIGH",
                    "exposure",
                    f"[HIGH] WAN-facing pass rule '{name}' allows any source — internet-exposed",
                    "Restrict WAN-facing pass rules to specific known source IP ranges. "
                    "Any-source rules on the WAN interface are directly internet-exposed.",
                    **_rule_kwargs(
                        r,
                        "pfSense WAN pass rule allows any source",
                        id="CASHEL-PFSENSE-EXPOSURE-002",
                        impact="WAN any-source rules can expose services to the internet.",
                        verification=(
                            "Confirm the WAN rule source is limited to approved external addresses "
                            "or aliases, then re-run the audit."
                        ),
                        rollback="Restore the prior source value from a pfSense config backup if approved access is disrupted.",
                        suggested_commands=_rule_guidance(
                            r,
                            "Set source to <APPROVED_EXTERNAL_SOURCE_ALIAS>",
                            "Confirm destination and destination port match only the required service",
                        ),
                    ),
                )
            )
    return findings


def audit_pfsense(filepath):
    rules, error = parse_pfsense(filepath)
    if error:
        return [
            _f(
                "HIGH",
                "hygiene",
                f"[ERROR] {error}",
                "",
                id="CASHEL-PFSENSE-PARSE-001",
                title="pfSense configuration could not be parsed",
                evidence=error,
                affected_object=filepath,
                confidence="high",
                verification="Confirm the uploaded file is valid pfSense XML and re-run the audit.",
                metadata={"filepath": filepath},
            )
        ], []

    findings = []
    findings += check_any_any_pf(rules)
    findings += check_missing_logging_pf(rules)
    findings += check_deny_all_pf(rules)
    findings += check_redundant_rules_pf(rules)
    findings += check_missing_description_pf(rules)
    findings += check_wan_any_source_pf(rules)
    return findings, rules
