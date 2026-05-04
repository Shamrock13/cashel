"""Juniper SRX firewall config parser and auditor.

Handles two Juniper configuration styles:
  - "set" style (flat commands): ``set security policies from-zone X to-zone Y ...``
  - Hierarchical (brace) style:  ``security { policies { from-zone X to-zone Y { ... } } }``

Returns normalised policy dicts compatible with the rest of the Cashel
audit pipeline plus system-level findings from management-plane checks.
"""

from __future__ import annotations

import re

from .models.findings import make_finding

# Applications Juniper ships as insecure defaults
_INSECURE_APPS = {
    "junos-telnet",
    "telnet",
    "junos-ftp",
    "ftp",
    "junos-tftp",
    "tftp",
    "junos-snmp-agentx",
}
_BROAD_ADDRS = {"any", "any-ipv4", "any-ipv6"}


def _f(
    severity,
    category,
    message,
    remediation="",
    *,
    id=None,
    vendor="juniper",
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


def _policy_label(policy: dict) -> str:
    return f"{policy['from_zone']}→{policy['to_zone']} policy '{policy['name']}'"


def _policy_evidence(policy: dict) -> str:
    raw = policy.get("_raw")
    if isinstance(raw, list) and raw:
        return "\n".join(raw)
    if isinstance(raw, str) and raw:
        return raw
    return (
        f"from-zone={policy.get('from_zone', '')} to-zone={policy.get('to_zone', '')} "
        f"policy={policy.get('name', '')} src={policy.get('src', [])} "
        f"dst={policy.get('dst', [])} app={policy.get('app', [])} "
        f"action={policy.get('action', '')} log={policy.get('log', False)}"
    )


def _policy_metadata(policy: dict) -> dict:
    return {
        "policy_name": policy.get("name", ""),
        "from_zone": policy.get("from_zone", ""),
        "to_zone": policy.get("to_zone", ""),
        "source_address": policy.get("src", []),
        "destination_address": policy.get("dst", []),
        "application": policy.get("app", []),
        "action": policy.get("action"),
        "log": policy.get("log", False),
        "session_init": policy.get("session_init", False),
        "session_close": policy.get("session_close", False),
        "disabled": policy.get("disabled", False),
        "raw": _policy_evidence(policy),
    }


def _policy_kwargs(
    policy: dict,
    title: str,
    *,
    id: str,
    confidence: str = "high",
    impact: str | None = None,
    verification: str | None = None,
    rollback: str | None = None,
    suggested_commands: list[str] | None = None,
    metadata: dict | None = None,
) -> dict:
    merged_metadata = _policy_metadata(policy)
    if metadata:
        merged_metadata.update(metadata)
    return {
        "id": id,
        "title": title,
        "evidence": _policy_evidence(policy),
        "affected_object": policy.get("name", ""),
        "rule_id": policy.get("name", ""),
        "rule_name": policy.get("name", ""),
        "confidence": confidence,
        "impact": impact,
        "verification": verification,
        "rollback": rollback,
        "suggested_commands": suggested_commands or [],
        "metadata": merged_metadata,
    }


def _system_evidence(content: str, pattern: str) -> str:
    match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(0).strip()
    return pattern


def _system_metadata(
    subsystem: str,
    service: str,
    configured_value: str = "",
    **extra,
) -> dict:
    data = {
        "subsystem": subsystem,
        "service_name": service,
        "configured_value": configured_value,
    }
    data.update(extra)
    return data


# ── Config-style detection ────────────────────────────────────────────────────


def _is_set_style(content: str) -> bool:
    return bool(re.search(r"^\s*set security", content, re.MULTILINE))


# ── "set" style parser ────────────────────────────────────────────────────────

_SET_POLICY_RE = re.compile(
    r"^set security policies from-zone (\S+) to-zone (\S+) policy (\S+)\s+(.+)$"
)
_DEACTIVATE_RE = re.compile(
    r"^deactivate security policies from-zone (\S+) to-zone (\S+) policy (\S+)"
)


def _parse_set_style(content: str) -> list[dict]:
    """Parse flat ``set`` commands into normalised policy dicts."""
    policies: dict = {}  # (fz, tz, name) → dict

    for raw_line in content.splitlines():
        line = raw_line.strip()

        m = _SET_POLICY_RE.match(line)
        if m:
            fz, tz, name, rest = m.groups()
            key = (fz, tz, name)
            if key not in policies:
                policies[key] = {
                    "name": name,
                    "from_zone": fz,
                    "to_zone": tz,
                    "src": [],
                    "dst": [],
                    "app": [],
                    "action": None,
                    "log": False,
                    "session_init": False,
                    "session_close": False,
                    "disabled": False,
                    "_raw": [],
                }
            p = policies[key]
            p["_raw"].append(line)

            if rest.startswith("match source-address "):
                p["src"].append(rest[len("match source-address ") :].strip())
            elif rest.startswith("match destination-address "):
                p["dst"].append(rest[len("match destination-address ") :].strip())
            elif rest.startswith("match application "):
                p["app"].append(rest[len("match application ") :].strip())
            elif rest.startswith("then reject"):
                p["action"] = "reject"
            elif rest.startswith("then deny"):
                p["action"] = "deny"
            elif "then permit" in rest:
                p["action"] = "permit"
                if "log" in rest:
                    p["log"] = True
                    if "session-init" in rest:
                        p["session_init"] = True
                    if "session-close" in rest or "log" in rest:
                        p["session_close"] = True
            continue

        m2 = _DEACTIVATE_RE.match(line)
        if m2:
            fz, tz, name = m2.groups()
            key = (fz, tz, name)
            if key in policies:
                policies[key]["disabled"] = True

    return list(policies.values())


# ── Hierarchical (brace) style parser ────────────────────────────────────────


def _parse_hierarchical(content: str) -> list[dict]:
    """Parse brace-style Juniper config into normalised policy dicts.

    Uses a simple depth-tracking state machine; does not require a full
    grammar parser and handles multi-line configurations reliably.
    """
    policies = []
    in_security_policies = False
    current_fz = current_tz = current_name = None
    current_policy: dict | None = None
    in_match = in_then = False
    depth = 0

    for raw_line in content.splitlines():
        line = raw_line.strip().rstrip(";")

        opens = raw_line.count("{")
        closes = raw_line.count("}")
        depth += opens - closes

        # Entering/leaving security.policies block
        if "security {" in raw_line and depth <= 2:
            in_security_policies = True
        if in_security_policies and depth == 0:
            in_security_policies = False

        if not in_security_policies:
            continue

        # Zone-pair header: from-zone X to-zone Y {
        m = re.match(r"from-zone\s+(\S+)\s+to-zone\s+(\S+)", line)
        if m:
            current_fz, current_tz = m.group(1), m.group(2)
            current_name = None
            current_policy = None
            in_match = in_then = False
            continue

        # Policy block: [inactive: ]policy <name> {
        m = re.match(r"(?:inactive:\s*)?policy\s+(\S+)", line)
        if m and current_fz:
            if current_policy is not None:
                policies.append(current_policy)
            current_name = m.group(1)
            inactive = "inactive:" in line
            current_policy = {
                "name": current_name,
                "from_zone": current_fz,
                "to_zone": current_tz,
                "src": [],
                "dst": [],
                "app": [],
                "action": None,
                "log": False,
                "session_init": False,
                "session_close": False,
                "disabled": inactive,
                "_raw": [line],
            }
            in_match = in_then = False
            continue

        if current_policy is None:
            continue

        if line == "match {":
            in_match, in_then = True, False
            continue
        if line == "then {":
            in_match, in_then = False, True
            continue
        if line in ("}", "};"):
            in_match = in_then = False
            continue

        if in_match:
            if line.startswith("source-address "):
                current_policy["src"].append(line.split(None, 1)[1])
            elif line.startswith("destination-address "):
                current_policy["dst"].append(line.split(None, 1)[1])
            elif line.startswith("application "):
                current_policy["app"].append(line.split(None, 1)[1])

        if in_then:
            if current_policy["action"] is None:
                if "reject" in line:
                    current_policy["action"] = "reject"
                elif "deny" in line:
                    current_policy["action"] = "deny"
                elif "permit" in line:
                    current_policy["action"] = "permit"
            if "log" in line:
                current_policy["log"] = True
            if "session-init" in line:
                current_policy["session_init"] = True
            if "session-close" in line:
                current_policy["session_close"] = True
        current_policy["_raw"].append(line)

    if current_policy is not None:
        policies.append(current_policy)

    return policies


# ── Public parser ─────────────────────────────────────────────────────────────


def parse_juniper(filepath: str) -> tuple[list[dict], str | None]:
    """Parse a Juniper SRX config file.

    Returns (policies, error_message).  error_message is None on success.
    """
    try:
        with open(filepath) as fh:
            content = fh.read()
    except OSError as exc:
        return [], f"Failed to read Juniper config: {exc}"

    if _is_set_style(content):
        policies = _parse_set_style(content)
    else:
        policies = _parse_hierarchical(content)

    return policies, content  # return content so caller can do system checks


# ── Policy-level checks ───────────────────────────────────────────────────────


def check_any_any_juniper(policies: list[dict]) -> list[dict]:
    """Flag permit rules that allow any source, any destination, any application."""
    findings = []
    for p in policies:
        if p.get("disabled") or p.get("action") != "permit":
            continue
        src_broad = all(s.lower() in _BROAD_ADDRS for s in (p["src"] or ["any"]))
        dst_broad = all(d.lower() in _BROAD_ADDRS for d in (p["dst"] or ["any"]))
        app_any = any(
            a.lower() in ("any", "any-ipv4", "any-ipv6", "junos-any")
            for a in (p["app"] or ["any"])
        )
        if src_broad and dst_broad and app_any:
            label = _policy_label(p)
            findings.append(
                _f(
                    "CRITICAL",
                    "exposure",
                    f"[CRITICAL] {label}: permits any source, any destination, any application.",
                    f"Restrict source-address, destination-address, and application in policy '{p['name']}'. "
                    "Apply least-privilege — allow only the specific zones, addresses, and applications needed.",
                    **_policy_kwargs(
                        p,
                        "Juniper policy permits any source, destination, and application",
                        id="CASHEL-JUNIPER-EXPOSURE-001",
                        impact="A broad permit policy can allow unintended traffic across the zone pair.",
                        verification=(
                            "Confirm the policy no longer uses any for source, destination, "
                            "and application, then re-run the audit."
                        ),
                        rollback=(
                            "Restore the previous match terms from configuration history if "
                            "least-privilege changes block approved traffic."
                        ),
                        suggested_commands=[
                            "set security policies from-zone <SRC_ZONE> to-zone <DST_ZONE> policy <POLICY_NAME> match source-address <SOURCE_OBJECT>",
                            "set security policies from-zone <SRC_ZONE> to-zone <DST_ZONE> policy <POLICY_NAME> match destination-address <DEST_OBJECT>",
                            "set security policies from-zone <SRC_ZONE> to-zone <DST_ZONE> policy <POLICY_NAME> match application <APPLICATION>",
                        ],
                    ),
                )
            )
    return findings


def check_missing_log_juniper(policies: list[dict]) -> list[dict]:
    """Flag permit rules that do not enable session logging."""
    findings = []
    for p in policies:
        if p.get("disabled") or p.get("action") != "permit" or p.get("log"):
            continue
        label = _policy_label(p)
        findings.append(
            _f(
                "MEDIUM",
                "logging",
                f"[MEDIUM] {label}: permit policy has no session logging enabled.",
                f"Add 'then permit log session-close' (set style) or a 'log {{ session-close; }}' block "
                f"under 'then permit' in policy '{p['name']}' to enable traffic logging.",
                **_policy_kwargs(
                    p,
                    "Juniper permit policy is missing session logging",
                    id="CASHEL-JUNIPER-LOGGING-001",
                    impact="Permitted traffic may not be visible in session logs or downstream monitoring.",
                    verification=(
                        "Confirm session-init or session-close logging is enabled for the policy "
                        "and matched sessions appear in logs."
                    ),
                    rollback="Remove or revert the added log terms if logging volume is unacceptable.",
                    suggested_commands=[
                        "set security policies from-zone <SRC_ZONE> to-zone <DST_ZONE> policy <POLICY_NAME> then log session-init session-close",
                    ],
                ),
            )
        )
    return findings


def check_insecure_apps_juniper(policies: list[dict]) -> list[dict]:
    """Flag permit rules that allow known-insecure applications (Telnet, FTP, TFTP)."""
    findings = []
    for p in policies:
        if p.get("disabled") or p.get("action") != "permit":
            continue
        bad = [a for a in p.get("app", []) if a.lower() in _INSECURE_APPS]
        if not bad:
            continue
        label = _policy_label(p)
        # Telnet is CRITICAL; other insecure apps are HIGH
        has_telnet = any(a.lower() in ("telnet", "junos-telnet") for a in bad)
        severity = "CRITICAL" if has_telnet else "HIGH"
        findings.append(
            _f(
                severity,
                "protocol",
                f"[{severity}] {label}: permits insecure application(s): {', '.join(bad)}.",
                "Replace cleartext protocols with encrypted equivalents: "
                "use SSH instead of Telnet, SFTP/SCP instead of FTP, and SNMPv3 instead of SNMP. "
                f"Remove or restrict the application term in policy '{p['name']}'.",
                **_policy_kwargs(
                    p,
                    "Juniper policy permits insecure applications",
                    id="CASHEL-JUNIPER-PROTOCOL-001",
                    impact="Cleartext or legacy applications can expose credentials and sensitive traffic.",
                    verification=(
                        "Confirm the policy no longer permits the insecure application terms "
                        "or limits them to an approved migration exception, then re-run the audit."
                    ),
                    rollback="Restore the prior application terms if replacement protocols break approved access.",
                    suggested_commands=[
                        "delete security policies from-zone <SRC_ZONE> to-zone <DST_ZONE> policy <POLICY_NAME> match application <INSECURE_APPLICATION>",
                        "set security policies from-zone <SRC_ZONE> to-zone <DST_ZONE> policy <POLICY_NAME> match application <APPROVED_APPLICATION>",
                    ],
                    metadata={"insecure_applications": bad},
                ),
            )
        )
    return findings


def check_deny_all_juniper(policies: list[dict]) -> list[dict]:
    """Flag zone-pairs that have no explicit deny-all catch-all at the end of the policy list."""
    # Group policies by zone-pair; the last active policy should be a deny/reject
    zone_pairs: dict = {}
    for p in policies:
        if p.get("disabled"):
            continue
        key = (p["from_zone"], p["to_zone"])
        zone_pairs.setdefault(key, []).append(p)

    findings = []
    for (fz, tz), pollist in zone_pairs.items():
        last = pollist[-1]
        src_any = all(s.lower() in _BROAD_ADDRS for s in (last["src"] or ["any"]))
        dst_any = all(d.lower() in _BROAD_ADDRS for d in (last["dst"] or ["any"]))
        app_any = any(
            a.lower() in ("any", "junos-any") for a in (last["app"] or ["any"])
        )
        is_deny = last.get("action") in ("deny", "reject")
        if not (src_any and dst_any and app_any and is_deny):
            findings.append(
                _f(
                    "HIGH",
                    "hygiene",
                    f"[HIGH] Zone pair {fz}→{tz}: no explicit deny-all catch-all policy at end of rule list.",
                    f"Add a final policy under from-zone {fz} to-zone {tz} that matches "
                    "source-address any, destination-address any, application any "
                    "with action deny to ensure a documented, auditable default-deny posture.",
                    id="CASHEL-JUNIPER-HYGIENE-001",
                    title="Juniper zone pair is missing an explicit deny-all policy",
                    evidence=_policy_evidence(last),
                    affected_object=f"{fz}->{tz}",
                    rule_name=last.get("name", ""),
                    confidence="medium",
                    impact="The zone pair relies on implicit behavior and may lack explicit deny logging.",
                    verification=(
                        "Confirm a final deny or reject policy exists for the zone pair, "
                        "logs unmatched traffic where appropriate, and appears after permit policies."
                    ),
                    rollback="Deactivate or remove the new deny policy if it blocks approved traffic.",
                    suggested_commands=[
                        "set security policies from-zone <SRC_ZONE> to-zone <DST_ZONE> policy <DENY_POLICY_NAME> match source-address any",
                        "set security policies from-zone <SRC_ZONE> to-zone <DST_ZONE> policy <DENY_POLICY_NAME> match destination-address any",
                        "set security policies from-zone <SRC_ZONE> to-zone <DST_ZONE> policy <DENY_POLICY_NAME> match application any",
                        "set security policies from-zone <SRC_ZONE> to-zone <DST_ZONE> policy <DENY_POLICY_NAME> then deny",
                        "set security policies from-zone <SRC_ZONE> to-zone <DST_ZONE> policy <DENY_POLICY_NAME> then log session-init session-close",
                    ],
                    metadata={
                        "from_zone": fz,
                        "to_zone": tz,
                        "last_policy": last.get("name", ""),
                        "last_policy_metadata": _policy_metadata(last),
                    },
                )
            )
    return findings


# ── System-level checks ───────────────────────────────────────────────────────


def check_system_juniper(content: str) -> list[dict]:
    """Checks against the raw config text for management-plane weaknesses."""
    findings = []
    cl = content.lower()

    # Telnet enabled on management plane
    has_telnet = bool(re.search(r"set system services telnet", content)) or (
        "services {" in content and re.search(r"\btelnet;", content)
    )
    if has_telnet:
        findings.append(
            _f(
                "CRITICAL",
                "management",
                "[CRITICAL] Telnet management service is enabled.",
                "Disable Telnet: 'delete system services telnet' (set style) or remove the "
                "telnet stanza from 'system { services { ... } }'. Use SSH exclusively.",
                id="CASHEL-JUNIPER-MANAGEMENT-001",
                title="Juniper Telnet management service is enabled",
                evidence=_system_evidence(
                    content, r"^\s*set system services telnet.*$|\btelnet;"
                ),
                affected_object="system services telnet",
                confidence="high",
                impact="Telnet exposes management traffic and credentials in cleartext.",
                verification=(
                    "Confirm Telnet is removed and SSH remains available only from approved "
                    "management networks, then re-run the audit."
                ),
                rollback="Restore the previous services stanza only if emergency access requires it.",
                suggested_commands=["delete system services telnet"],
                metadata=_system_metadata("system services", "telnet", "enabled"),
            )
        )

    # SSH not explicitly configured
    has_ssh = bool(re.search(r"set system services ssh", content)) or (
        "services {" in content and re.search(r"\bssh\s*\{", content)
    )
    if not has_ssh:
        findings.append(
            _f(
                "MEDIUM",
                "management",
                "[MEDIUM] SSH management service not explicitly configured.",
                "Enable SSH: 'set system services ssh' and optionally enforce "
                "'set system services ssh root-login deny' and protocol-version v2.",
                id="CASHEL-JUNIPER-MANAGEMENT-002",
                title="Juniper SSH management service is not explicitly configured",
                evidence="No system services ssh configuration was found.",
                affected_object="system services ssh",
                confidence="medium",
                impact="Administrators may lack an encrypted management path or rely on weaker access methods.",
                verification="Confirm SSH is configured and reachable only from approved management networks.",
                rollback="Remove the SSH service stanza if it was enabled on the wrong interface or network.",
                suggested_commands=[
                    "set system services ssh",
                    "set system services ssh root-login deny",
                ],
                metadata=_system_metadata("system services", "ssh", "missing"),
            )
        )

    # No NTP configured
    has_ntp = bool(re.search(r"set system ntp", content)) or "ntp {" in cl
    if not has_ntp:
        findings.append(
            _f(
                "MEDIUM",
                "hygiene",
                "[MEDIUM] No NTP server configured.",
                "Add at least one NTP server: 'set system ntp server <IP>'. "
                "Accurate timestamps are required for log correlation and compliance.",
                id="CASHEL-JUNIPER-HYGIENE-002",
                title="Juniper NTP is not configured",
                evidence="No system ntp configuration was found.",
                affected_object="system ntp",
                confidence="medium",
                impact="Incorrect timestamps can weaken incident timelines, audit trails, and log correlation.",
                verification="Confirm the device synchronizes to approved NTP servers and logs show accurate time.",
                rollback="Remove or replace the NTP server entry if the selected server is unreachable or unauthorized.",
                suggested_commands=["set system ntp server <NTP_SERVER_IP>"],
                metadata=_system_metadata("system", "ntp", "missing"),
            )
        )

    # No syslog configured
    has_syslog = bool(re.search(r"set system syslog", content)) or "syslog {" in cl
    if not has_syslog:
        findings.append(
            _f(
                "HIGH",
                "logging",
                "[HIGH] No syslog configuration found.",
                "Configure remote syslog: 'set system syslog host <IP> any any'. "
                "Without remote logging, audit trails are lost if the device is compromised.",
                id="CASHEL-JUNIPER-LOGGING-002",
                title="Juniper remote syslog is not configured",
                evidence="No system syslog configuration was found.",
                affected_object="system syslog",
                confidence="medium",
                impact="Device logs may be unavailable after compromise, reboot, or local log rotation.",
                verification="Confirm logs are delivered to the approved remote syslog destination.",
                rollback="Remove or update the syslog host if the configured destination is incorrect.",
                suggested_commands=[
                    "set system syslog host <SYSLOG_SERVER_IP> any any"
                ],
                metadata=_system_metadata("system", "syslog", "missing"),
            )
        )

    # Weak SNMP (v1/v2c community)
    snmp_community = re.findall(r"set snmp community (\S+)", content)
    if snmp_community:
        for comm in snmp_community:
            findings.append(
                _f(
                    "HIGH",
                    "protocol",
                    f"[HIGH] SNMPv1/v2c community string '{comm}' configured.",
                    "Migrate to SNMPv3 with authentication and privacy: "
                    "'set snmp v3 usm local-engine user <name> authentication-sha ...' "
                    "and remove all 'set snmp community' statements.",
                    id="CASHEL-JUNIPER-PROTOCOL-002",
                    title="Juniper SNMPv1/v2c community is configured",
                    evidence=_system_evidence(
                        content, rf"^\s*set snmp community {re.escape(comm)}.*$"
                    ),
                    affected_object=f"snmp community {comm}",
                    confidence="high",
                    impact="SNMP community strings are shared secrets and do not provide SNMPv3-grade authentication or privacy.",
                    verification=(
                        "Confirm SNMPv3 users are configured and the community string is removed "
                        "after monitoring is migrated."
                    ),
                    rollback="Restore the community temporarily only if monitoring migration fails and risk is accepted.",
                    suggested_commands=[
                        "delete snmp community <COMMUNITY>",
                        "set snmp v3 usm local-engine user <USER> authentication-sha <AUTH_KEY>",
                    ],
                    metadata=_system_metadata("snmp", "community", comm),
                )
            )

    # Root login over SSH permitted
    if re.search(r"set system services ssh root-login allow", content):
        findings.append(
            _f(
                "HIGH",
                "management",
                "[HIGH] SSH root login is explicitly allowed.",
                "Disable root SSH login: 'set system services ssh root-login deny'. "
                "Use named admin accounts with appropriate privileges instead.",
                id="CASHEL-JUNIPER-MANAGEMENT-003",
                title="Juniper SSH root login is allowed",
                evidence=_system_evidence(
                    content, r"^\s*set system services ssh root-login allow.*$"
                ),
                affected_object="system services ssh root-login",
                confidence="high",
                impact="Direct root SSH access weakens accountability and increases management-plane risk.",
                verification="Confirm root-login is deny and named administrator accounts can still authenticate.",
                rollback="Restore the prior root-login setting only for a documented emergency access exception.",
                suggested_commands=["set system services ssh root-login deny"],
                metadata=_system_metadata("system services", "ssh root-login", "allow"),
            )
        )

    # No zone screens (SYN-flood / DoS protection)
    has_screens = (
        bool(
            re.search(
                r"set security zones security-zone \S+ host-inbound-traffic", content
            )
        )
        or bool(re.search(r"set security screen", content))
        or "screen {" in cl
    )
    if not has_screens:
        findings.append(
            _f(
                "MEDIUM",
                "exposure",
                "[MEDIUM] No security screen (DoS protection) configuration found.",
                "Configure zone screens to protect against SYN-flood and other DoS attacks: "
                "'set security screen ids-option <name> icmp flood' and apply to relevant zones.",
                id="CASHEL-JUNIPER-EXPOSURE-002",
                title="Juniper security screen protection is not configured",
                evidence="No security screen configuration was found.",
                affected_object="security screen",
                confidence="medium",
                impact="Zones may lack baseline DoS protections such as flood screening.",
                verification="Confirm screen options are configured and applied to appropriate security zones.",
                rollback="Remove or tune the screen option if it causes false positives or traffic disruption.",
                suggested_commands=[
                    "set security screen ids-option <SCREEN_NAME> icmp flood",
                    "set security zones security-zone <ZONE_NAME> screen <SCREEN_NAME>",
                ],
                metadata=_system_metadata("security", "screen", "missing"),
            )
        )

    return findings


# ── Top-level auditor ─────────────────────────────────────────────────────────


def audit_juniper(filepath: str) -> tuple[list[dict], list[dict]]:
    """Full audit of a Juniper SRX config file.

    Returns (findings, policies) where policies is the normalised list of
    security policy dicts (used for compliance re-checks and shadow detection).
    """
    policies, content_or_err = parse_juniper(filepath)

    if isinstance(content_or_err, str) and not policies:
        # parse_juniper returned an error string
        return [
            _f(
                "HIGH",
                "parse",
                f"[HIGH] Parse error: {content_or_err}",
                "",
                id="CASHEL-JUNIPER-PARSE-001",
                title="Juniper configuration could not be parsed",
                evidence=content_or_err,
                affected_object=filepath,
                confidence="high",
                verification="Confirm the file exists and is a readable Juniper SRX configuration, then re-run the audit.",
                metadata={"filepath": filepath},
            )
        ], []

    content: str = content_or_err or ""  # parse_juniper returns content on success

    findings: list[dict] = []
    findings += check_system_juniper(content)
    findings += check_any_any_juniper(policies)
    findings += check_missing_log_juniper(policies)
    findings += check_insecure_apps_juniper(policies)
    findings += check_deny_all_juniper(policies)

    return findings, policies
