"""Compliance framework checks — CIS, PCI-DSS, NIST SP 800-41, HIPAA Security Rule.

Each check function returns a list of finding strings tagged with the framework
prefix (CIS-HIGH, PCI-MEDIUM, NIST-HIGH, HIPAA-HIGH, etc.).

Vendors covered: Cisco ASA, Cisco FTD, Palo Alto, Fortinet, pfSense.
"""

# ══════════════════════════════════════════════════════════════ CISCO ASA ══


def check_cis_compliance(parse):
    """CIS Cisco ASA Firewall Benchmark checks."""
    findings = []

    # CIS 1 — Explicit deny-all at end of ACL
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append("[CIS-HIGH] CIS Control 1: No default deny-all rule found")

    # CIS 2 — No any/any permit rules (least privilege)
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[CIS-HIGH] CIS Control 2: {len(any_any)} any/any permit rule(s) violate least privilege"
        )

    # CIS 3 — All permit rules must have logging
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 3: Permit rule missing logging: {rule.text.strip()}"
            )

    # CIS 4 — SSH must be locked to version 2
    if parse.find_objects(r"^ssh version 1"):
        findings.append("[CIS-HIGH] CIS Control 4: SSHv1 is enabled — disable it and enforce SSHv2 only")
    elif not parse.find_objects(r"^ssh version 2"):
        findings.append("[CIS-MEDIUM] CIS Control 4: SSH version not explicitly locked to version 2")

    # CIS 5 — SNMPv1/v2c community strings must not be used
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[CIS-HIGH] CIS Control 5: SNMPv1/v2c community string in use: {r.text.strip()} — migrate to SNMPv3"
        )

    # CIS 6 — Telnet management access must be disabled
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[CIS-HIGH] CIS Control 6: Telnet management access is configured — disable and use SSH"
        )

    # CIS 7 — HTTP/ASDM server should be disabled or restricted
    if parse.find_objects(r"^http server enable"):
        if not parse.find_objects(r"^http\s+\d"):
            findings.append(
                "[CIS-MEDIUM] CIS Control 7: HTTP/ASDM server enabled with no host restriction"
            )

    # CIS 8 — NTP server must be configured
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 8: No NTP server configured — accurate timestamps are required for log integrity"
        )

    # CIS 9 — Login banner must be set
    if not parse.find_objects(r"^banner (login|motd|exec)"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 9: No login banner configured — banners provide legal notice and deter unauthorized access"
        )

    # CIS 10 — Password encryption must be enabled
    if not parse.find_objects(r"^password encryption aes") and not parse.find_objects(r"^service password-encryption"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 10: Password encryption not configured — enable 'service password-encryption' or AES encryption"
        )

    # CIS 11 — Unrestricted ICMP from any source
    if parse.find_objects(r"access-list.*permit icmp any any"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 11: Unrestricted ICMP (any/any) permitted — restrict ICMP to necessary types and sources"
        )

    return findings


def check_pci_compliance(parse):
    """PCI-DSS Requirement checks for Cisco ASA."""
    findings = []

    # PCI Req 1.3 — No any/any rules (direct routes to cardholder data prohibited)
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[PCI-HIGH] PCI Req 1.3: {len(any_any)} any/any rule(s) found — direct routes to cardholder data prohibited"
        )

    # PCI Req 10.2 — All permit rules must log (audit trail)
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[PCI-MEDIUM] PCI Req 10.2: Permit rule missing logging: {rule.text.strip()}"
            )

    # PCI Req 1.2 — Explicit deny all must exist
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    # PCI Req 2.2.3 — Insecure protocols (Telnet) must be disabled
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[PCI-HIGH] PCI Req 2.2.3: Telnet management access configured — Telnet is an insecure protocol prohibited by PCI-DSS"
        )

    # PCI Req 2.2 — SNMPv1/v2c must not be used
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[PCI-HIGH] PCI Req 2.2: SNMPv1/v2c community string in use: {r.text.strip()} — PCI-DSS requires SNMPv3"
        )

    # PCI Req 10.5 — Syslog server must be configured (log protection)
    if not parse.find_objects(r"^logging host"):
        findings.append(
            "[PCI-HIGH] PCI Req 10.5: No remote syslog server configured — logs must be sent to a protected central log server"
        )

    # PCI Req 6.4 — NTP required for accurate audit timestamps
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[PCI-MEDIUM] PCI Req 10.4: No NTP server configured — synchronized time is required for accurate audit log timestamps"
        )

    # PCI Req 2.2 — HTTP/ASDM server exposure
    if parse.find_objects(r"^http server enable") and not parse.find_objects(r"^http\s+\d"):
        findings.append(
            "[PCI-MEDIUM] PCI Req 2.2: HTTP/ASDM server enabled with no host restriction — restrict to authorized management hosts"
        )

    # PCI Req 1.1 — Unrestricted ICMP
    if parse.find_objects(r"access-list.*permit icmp any any"):
        findings.append(
            "[PCI-MEDIUM] PCI Req 1.1: Unrestricted ICMP (any/any) permitted — restrict to necessary types to limit network exposure"
        )

    return findings


def check_nist_compliance(parse):
    """NIST SP 800-41 / NIST 800-53 checks for Cisco ASA."""
    findings = []

    # NIST AC-6 — Least privilege: no any/any
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[NIST-HIGH] NIST AC-6: {len(any_any)} any/any permit rule(s) violate least privilege principle"
        )

    # NIST AU-2 — Audit events: logging required on permit rules
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[NIST-MEDIUM] NIST AU-2: Permit rule missing audit logging: {rule.text.strip()}"
            )

    # NIST SC-7 — Boundary protection: deny-all must exist
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append("[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found")

    # NIST SC-8 — Transmission confidentiality: no Telnet
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[NIST-HIGH] NIST SC-8: Telnet configured — NIST SC-8 requires encrypted management channels; use SSH"
        )

    # NIST AU-9 — Log protection: remote syslog required
    if not parse.find_objects(r"^logging host"):
        findings.append(
            "[NIST-HIGH] NIST AU-9: No remote syslog server configured — logs must be protected from local modification or loss"
        )

    # NIST IA-3 — Device authentication: SNMPv3 required
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[NIST-HIGH] NIST IA-3: SNMPv1/v2c community string in use — NIST requires authenticated SNMPv3: {r.text.strip()}"
        )

    # NIST CM-7 — Least functionality: SSH version lock
    if parse.find_objects(r"^ssh version 1"):
        findings.append(
            "[NIST-HIGH] NIST CM-7: SSHv1 is enabled — disable to enforce least functionality"
        )
    elif not parse.find_objects(r"^ssh version 2"):
        findings.append(
            "[NIST-MEDIUM] NIST CM-7: SSH version not locked to version 2 — enforce SSHv2 to reduce attack surface"
        )

    # NIST AU-8 — Time stamps: NTP required
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[NIST-MEDIUM] NIST AU-8: No NTP server configured — accurate time synchronization is required for reliable audit timestamps"
        )

    # NIST AC-17 — Remote access: HTTP/ASDM exposure
    if parse.find_objects(r"^http server enable") and not parse.find_objects(r"^http\s+\d"):
        findings.append(
            "[NIST-MEDIUM] NIST AC-17: HTTP/ASDM management server unrestricted — limit remote access to authorized management hosts"
        )

    return findings


# ══════════════════════════════════════════════════════════ CISCO FTD ══


def check_cis_compliance_ftd(parse):
    """CIS checks for Cisco FTD (LINA CLI config)."""
    findings = []

    # CIS 1 — Explicit deny-all
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append("[CIS-HIGH] CIS Control 1: No default deny-all ACL rule found")

    # CIS 2 — No any/any permit
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[CIS-HIGH] CIS Control 2: {len(any_any)} any/any permit rule(s) violate least privilege"
        )

    # CIS 3 — All permit rules must log
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 3: Permit rule missing logging: {rule.text.strip()}"
            )

    # CIS 4 — Threat detection must be enabled
    if not parse.find_objects(r"^threat-detection"):
        findings.append(
            "[CIS-HIGH] CIS Control 4: Threat detection not configured — enable threat-detection basic-threat"
        )

    # CIS 5 — Intrusion policy (IPS/Snort) must be referenced
    if not parse.find_objects(r"^intrusion-policy") and not parse.find_objects(r"snort"):
        findings.append(
            "[CIS-HIGH] CIS Control 5: No intrusion prevention policy reference found — assign an IPS policy in FMC"
        )

    # CIS 6 — SSH version 2 only
    if parse.find_objects(r"^ssh version 1"):
        findings.append("[CIS-HIGH] CIS Control 6: SSHv1 is enabled — enforce SSHv2 only")
    elif not parse.find_objects(r"^ssh version 2"):
        findings.append("[CIS-MEDIUM] CIS Control 6: SSH version not locked to version 2")

    # CIS 7 — SNMPv1/v2c must not be used
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[CIS-HIGH] CIS Control 7: SNMPv1/v2c community string configured — migrate to SNMPv3: {r.text.strip()}"
        )

    # CIS 8 — No Telnet
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[CIS-HIGH] CIS Control 8: Telnet management access configured — disable and use SSH"
        )

    # CIS 9 — NTP configured
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 9: No NTP server configured — accurate timestamps required for FTD event correlation"
        )

    # CIS 10 — Remote syslog
    if not parse.find_objects(r"^logging host"):
        findings.append(
            "[CIS-MEDIUM] CIS Control 10: No remote syslog server configured"
        )

    return findings


def check_pci_compliance_ftd(parse):
    """PCI-DSS checks for Cisco FTD."""
    findings = []

    # PCI 1.3 — No any/any
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[PCI-HIGH] PCI Req 1.3: {len(any_any)} any/any rule(s) — direct routes to cardholder data prohibited"
        )

    # PCI 10.2 — Logging on permit rules
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[PCI-MEDIUM] PCI Req 10.2: Permit rule missing logging: {rule.text.strip()}"
            )

    # PCI 1.2 — Explicit deny all
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    # PCI 2.2.3 — Telnet prohibited
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[PCI-HIGH] PCI Req 2.2.3: Telnet management configured — prohibited by PCI-DSS"
        )

    # PCI 10.5 — Remote syslog
    if not parse.find_objects(r"^logging host"):
        findings.append(
            "[PCI-HIGH] PCI Req 10.5: No remote syslog server — logs must be sent to a protected central server"
        )

    # PCI 2.2 — SNMP
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[PCI-HIGH] PCI Req 2.2: SNMPv1/v2c in use: {r.text.strip()} — PCI-DSS requires SNMPv3"
        )

    # PCI 6.4 — IPS must be deployed
    if not parse.find_objects(r"^intrusion-policy") and not parse.find_objects(r"snort"):
        findings.append(
            "[PCI-HIGH] PCI Req 6.6: No intrusion prevention policy found — IPS is required to detect and block web-based attacks"
        )

    # PCI 10.4 — NTP for audit timestamps
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[PCI-MEDIUM] PCI Req 10.4: No NTP server configured — synchronized time required for audit log integrity"
        )

    return findings


def check_nist_compliance_ftd(parse):
    """NIST SP 800-41 / NIST 800-53 checks for Cisco FTD."""
    findings = []

    # NIST AC-6 — Least privilege
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[NIST-HIGH] NIST AC-6: {len(any_any)} any/any rule(s) violate least privilege"
        )

    # NIST AU-2 — Audit logging
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[NIST-MEDIUM] NIST AU-2: Permit rule missing audit logging: {rule.text.strip()}"
            )

    # NIST SC-7 — Boundary protection
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append("[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found")

    # NIST SC-8 — No Telnet
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[NIST-HIGH] NIST SC-8: Telnet configured — use encrypted SSH management per NIST SC-8"
        )

    # NIST SI-3 — IPS/malware protection
    if not parse.find_objects(r"^intrusion-policy") and not parse.find_objects(r"snort"):
        findings.append(
            "[NIST-HIGH] NIST SI-3: No intrusion prevention policy found — NIST SI-3 requires malicious code protection"
        )

    # NIST AU-9 — Log protection via remote syslog
    if not parse.find_objects(r"^logging host"):
        findings.append(
            "[NIST-HIGH] NIST AU-9: No remote syslog server — audit records must be protected from local loss or tampering"
        )

    # NIST IA-3 — SNMPv3 for device authentication
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            f"[NIST-HIGH] NIST IA-3: SNMPv1/v2c in use — NIST requires authenticated SNMPv3: {r.text.strip()}"
        )

    # NIST AU-8 — NTP
    if not parse.find_objects(r"^ntp server"):
        findings.append(
            "[NIST-MEDIUM] NIST AU-8: No NTP server — accurate timestamps required for audit records"
        )

    return findings


# ════════════════════════════════════════════════════════ PALO ALTO ══


def check_cis_compliance_pa(rules):
    """CIS Palo Alto Networks Firewall Benchmark checks."""
    findings = []

    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")
        log_end = rule.findtext(".//log-end")
        log_start = rule.findtext(".//log-start")
        apps = [a.text for a in rule.findall(".//application/member")]
        profile_setting = rule.find(".//profile-setting")

        # CIS 1 — No any/any permit
        if action == "allow" and "any" in src and "any" in dst:
            findings.append(
                f"[CIS-HIGH] CIS Control 1: Rule '{name}' violates least privilege — any/any permit"
            )

        # CIS 2 — All permit rules must log
        if action == "allow" and log_end != "yes" and log_start != "yes":
            findings.append(
                f"[CIS-MEDIUM] CIS Control 2: Rule '{name}' missing logging"
            )

        # CIS 3 — Security profiles must be attached to allow rules
        if action == "allow":
            has_profile = profile_setting is not None and (
                profile_setting.find(".//profiles") is not None
                or profile_setting.find(".//group") is not None
            )
            if not has_profile:
                findings.append(
                    f"[CIS-MEDIUM] CIS Control 3: Rule '{name}' has no security profile attached — "
                    "attach an AV, IPS, and URL filtering profile to inspect allowed traffic"
                )

        # CIS 4 — Application 'any' in allow rules
        if action == "allow" and "any" in apps:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 4: Rule '{name}' permits any application — "
                "specify allowed applications to enforce application-based policy"
            )

    # CIS 5 — Deny all must exist
    has_deny_all = any(
        rule.findtext(".//action") == "deny"
        and "any" in [s.text for s in rule.findall(".//source/member")]
        and "any" in [d.text for d in rule.findall(".//destination/member")]
        for rule in rules
    )
    if not has_deny_all:
        findings.append("[CIS-HIGH] CIS Control 5: No default deny-all rule found")

    # CIS 6 — Unnamed rules
    unnamed = [r for r in rules if not r.get("name") or r.get("name", "").lower() in ("unnamed", "")]
    if unnamed:
        findings.append(
            f"[CIS-MEDIUM] CIS Control 6: {len(unnamed)} unnamed rule(s) found — all rules must be named for audit clarity"
        )

    return findings


def check_pci_compliance_pa(rules):
    """PCI-DSS checks for Palo Alto Networks."""
    findings = []

    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")
        log_end = rule.findtext(".//log-end")
        log_start = rule.findtext(".//log-start")
        profile_setting = rule.find(".//profile-setting")

        # PCI 1.3 — No any/any
        if action == "allow" and "any" in src and "any" in dst:
            findings.append(
                f"[PCI-HIGH] PCI Req 1.3: Rule '{name}' — direct routes to cardholder data prohibited"
            )

        # PCI 10.2 — Logging required
        if action == "allow" and log_end != "yes" and log_start != "yes":
            findings.append(
                f"[PCI-MEDIUM] PCI Req 10.2: Rule '{name}' missing audit logging"
            )

        # PCI 6.6 — Security profiles for application inspection
        if action == "allow":
            has_profile = profile_setting is not None and (
                profile_setting.find(".//profiles") is not None
                or profile_setting.find(".//group") is not None
            )
            if not has_profile:
                findings.append(
                    f"[PCI-MEDIUM] PCI Req 6.6: Rule '{name}' has no security profile — "
                    "attach IPS/AV profiles to inspect traffic for cardholder data threats"
                )

    # PCI 1.2 — Explicit deny all
    has_deny_all = any(
        rule.findtext(".//action") == "deny"
        and "any" in [s.text for s in rule.findall(".//source/member")]
        and "any" in [d.text for d in rule.findall(".//destination/member")]
        for rule in rules
    )
    if not has_deny_all:
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    return findings


def check_nist_compliance_pa(rules):
    """NIST SP 800-41 / NIST 800-53 checks for Palo Alto Networks."""
    findings = []

    for rule in rules:
        name = rule.get("name", "unnamed")
        src = [s.text for s in rule.findall(".//source/member")]
        dst = [d.text for d in rule.findall(".//destination/member")]
        action = rule.findtext(".//action")
        log_end = rule.findtext(".//log-end")
        log_start = rule.findtext(".//log-start")
        apps = [a.text for a in rule.findall(".//application/member")]
        profile_setting = rule.find(".//profile-setting")

        # NIST AC-6 — Least privilege
        if action == "allow" and "any" in src and "any" in dst:
            findings.append(
                f"[NIST-HIGH] NIST AC-6: Rule '{name}' violates least privilege principle"
            )

        # NIST AU-2 — Audit logging
        if action == "allow" and log_end != "yes" and log_start != "yes":
            findings.append(
                f"[NIST-MEDIUM] NIST AU-2: Rule '{name}' missing audit logging"
            )

        # NIST SI-3 — Security profiles (malicious code protection)
        if action == "allow":
            has_profile = profile_setting is not None and (
                profile_setting.find(".//profiles") is not None
                or profile_setting.find(".//group") is not None
            )
            if not has_profile:
                findings.append(
                    f"[NIST-MEDIUM] NIST SI-3: Rule '{name}' has no security profile — "
                    "attach AV/IPS profiles per NIST SI-3 malicious code protection requirement"
                )

        # NIST CM-7 — Application 'any' reduces least functionality
        if action == "allow" and "any" in apps:
            findings.append(
                f"[NIST-MEDIUM] NIST CM-7: Rule '{name}' permits any application — "
                "specify applications to enforce least functionality"
            )

    # NIST SC-7 — Boundary protection
    has_deny_all = any(
        rule.findtext(".//action") == "deny"
        and "any" in [s.text for s in rule.findall(".//source/member")]
        and "any" in [d.text for d in rule.findall(".//destination/member")]
        for rule in rules
    )
    if not has_deny_all:
        findings.append("[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found")

    return findings


# ══════════════════════════════════════════════════════════ FORTINET ══


def check_cis_compliance_forti(policies):
    """CIS Fortinet FortiGate Benchmark checks."""
    findings = []

    for p in policies:
        name = p.get("name") or f"Policy ID {p.get('id')}"
        src = p.get("srcaddr", [])
        dst = p.get("dstaddr", [])
        action = p.get("action", "")
        logtraffic = p.get("logtraffic", "")
        service = p.get("service", [])
        av_profile = p.get("av-profile", "")
        ips_sensor = p.get("ips-sensor", "")
        webfilter_profile = p.get("webfilter-profile", "")

        # CIS 1 — No any/any permit
        if action == "accept" and "all" in src and "all" in dst:
            findings.append(
                f"[CIS-HIGH] CIS Control 1: Rule '{name}' violates least privilege — source/dest all"
            )

        # CIS 2 — All permit rules must log
        if action == "accept" and logtraffic not in ("all", "utm"):
            findings.append(
                f"[CIS-MEDIUM] CIS Control 2: Rule '{name}' missing logging"
            )

        # CIS 3 — Service 'ALL' in permit rules
        if action == "accept" and "ALL" in service:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 3: Rule '{name}' permits all services — restrict to required services only"
            )

        # CIS 4 — AV profile attached to permit rules
        if action == "accept" and not av_profile:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 4: Rule '{name}' has no AV profile attached"
            )

        # CIS 5 — IPS sensor attached to permit rules
        if action == "accept" and not ips_sensor:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 5: Rule '{name}' has no IPS sensor attached"
            )

        # CIS 6 — Web filter for internet-facing rules
        if action == "accept" and not webfilter_profile and "all" in dst:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 6: Rule '{name}' with unrestricted destination has no web filter profile"
            )

    # CIS 7 — Deny all must exist
    has_deny_all = any(
        p.get("action") == "deny"
        and "all" in p.get("srcaddr", [])
        and "all" in p.get("dstaddr", [])
        for p in policies
    )
    if not has_deny_all:
        findings.append("[CIS-HIGH] CIS Control 7: No default deny-all rule found")

    return findings


def check_pci_compliance_forti(policies):
    """PCI-DSS checks for Fortinet FortiGate."""
    findings = []

    for p in policies:
        name = p.get("name") or f"Policy ID {p.get('id')}"
        src = p.get("srcaddr", [])
        dst = p.get("dstaddr", [])
        action = p.get("action", "")
        logtraffic = p.get("logtraffic", "")
        ips_sensor = p.get("ips-sensor", "")
        av_profile = p.get("av-profile", "")
        service = p.get("service", [])

        # PCI 1.3 — No any/any
        if action == "accept" and "all" in src and "all" in dst:
            findings.append(
                f"[PCI-HIGH] PCI Req 1.3: Rule '{name}' — direct routes to cardholder data prohibited"
            )

        # PCI 10.2 — Logging required
        if action == "accept" and logtraffic not in ("all", "utm"):
            findings.append(
                f"[PCI-MEDIUM] PCI Req 10.2: Rule '{name}' missing audit logging"
            )

        # PCI 6.6 — IPS required for allowed traffic
        if action == "accept" and not ips_sensor:
            findings.append(
                f"[PCI-MEDIUM] PCI Req 6.6: Rule '{name}' has no IPS sensor — IPS required to detect attacks against cardholder data"
            )

        # PCI 5.1 — AV required for allowed traffic
        if action == "accept" and not av_profile:
            findings.append(
                f"[PCI-MEDIUM] PCI Req 5.1: Rule '{name}' has no AV profile — AV protection required per PCI-DSS Req 5"
            )

        # PCI 1.1 — Service ALL prohibited
        if action == "accept" and "ALL" in service:
            findings.append(
                f"[PCI-MEDIUM] PCI Req 1.1: Rule '{name}' permits all services — define only required and documented services"
            )

    # PCI 1.2 — Explicit deny all
    has_deny_all = any(
        p.get("action") == "deny"
        and "all" in p.get("srcaddr", [])
        and "all" in p.get("dstaddr", [])
        for p in policies
    )
    if not has_deny_all:
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    return findings


def check_nist_compliance_forti(policies):
    """NIST SP 800-41 / NIST 800-53 checks for Fortinet FortiGate."""
    findings = []

    for p in policies:
        name = p.get("name") or f"Policy ID {p.get('id')}"
        src = p.get("srcaddr", [])
        dst = p.get("dstaddr", [])
        action = p.get("action", "")
        logtraffic = p.get("logtraffic", "")
        ips_sensor = p.get("ips-sensor", "")
        av_profile = p.get("av-profile", "")
        service = p.get("service", [])

        # NIST AC-6 — Least privilege
        if action == "accept" and "all" in src and "all" in dst:
            findings.append(
                f"[NIST-HIGH] NIST AC-6: Rule '{name}' violates least privilege principle"
            )

        # NIST AU-2 — Audit logging
        if action == "accept" and logtraffic not in ("all", "utm"):
            findings.append(
                f"[NIST-MEDIUM] NIST AU-2: Rule '{name}' missing audit logging"
            )

        # NIST SI-3 — Malicious code protection (AV)
        if action == "accept" and not av_profile:
            findings.append(
                f"[NIST-MEDIUM] NIST SI-3: Rule '{name}' has no AV profile — malicious code protection required"
            )

        # NIST SI-4 — Intrusion detection (IPS)
        if action == "accept" and not ips_sensor:
            findings.append(
                f"[NIST-MEDIUM] NIST SI-4: Rule '{name}' has no IPS sensor — network monitoring and intrusion detection required"
            )

        # NIST CM-7 — Least functionality: no ALL services
        if action == "accept" and "ALL" in service:
            findings.append(
                f"[NIST-MEDIUM] NIST CM-7: Rule '{name}' permits all services — restrict to required services only"
            )

    # NIST SC-7 — Boundary protection
    has_deny_all = any(
        p.get("action") == "deny"
        and "all" in p.get("srcaddr", [])
        and "all" in p.get("dstaddr", [])
        for p in policies
    )
    if not has_deny_all:
        findings.append("[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found")

    return findings


# ══════════════════════════════════════════════════════════ PFSENSE ══


def check_cis_compliance_pf(rules):
    """CIS pfSense Firewall Benchmark checks."""
    findings = []

    for r in rules:
        iface = r.get("interface", "unknown")

        # CIS 1 — No any/any permit
        if r["type"] == "pass" and r["source"] == "1" and r["destination"] == "1":
            findings.append(
                f"[CIS-HIGH] CIS Control 1: Rule '{r['descr']}' violates least privilege — any/any on {iface}"
            )

        # CIS 2 — All permit rules must log
        if r["type"] == "pass" and not r["log"]:
            findings.append(
                f"[CIS-MEDIUM] CIS Control 2: Rule '{r['descr']}' missing logging"
            )

        # CIS 3 — Protocol 'any' in permit rules
        if r["type"] == "pass" and r.get("protocol") in ("any", "", None):
            findings.append(
                f"[CIS-MEDIUM] CIS Control 3: Rule '{r['descr']}' permits any protocol — restrict to required protocols"
            )

    # CIS 4 — Deny all must exist
    has_deny_all = any(
        r["type"] == "block" and r["source"] == "1" and r["destination"] == "1"
        for r in rules
    )
    if not has_deny_all:
        findings.append("[CIS-HIGH] CIS Control 4: No default deny-all rule found")

    # CIS 5 — Block rules must exist (defense in depth)
    block_rules = [r for r in rules if r["type"] == "block"]
    if not block_rules:
        findings.append(
            "[CIS-MEDIUM] CIS Control 5: No explicit block rules found — rely on explicit deny rather than implicit default"
        )

    return findings


def check_pci_compliance_pf(rules):
    """PCI-DSS checks for pfSense."""
    findings = []

    for r in rules:
        iface = r.get("interface", "unknown")

        # PCI 1.3 — No any/any
        if r["type"] == "pass" and r["source"] == "1" and r["destination"] == "1":
            findings.append(
                f"[PCI-HIGH] PCI Req 1.3: Rule '{r['descr']}' — direct routes to cardholder data prohibited (any/any on {iface})"
            )

        # PCI 10.2 — Logging required
        if r["type"] == "pass" and not r["log"]:
            findings.append(
                f"[PCI-MEDIUM] PCI Req 10.2: Rule '{r['descr']}' missing audit logging"
            )

        # PCI 1.1 — Protocol 'any' in permit rules
        if r["type"] == "pass" and r.get("protocol") in ("any", "", None):
            findings.append(
                f"[PCI-MEDIUM] PCI Req 1.1: Rule '{r['descr']}' permits any protocol — document and restrict all allowed services"
            )

    # PCI 1.2 — Explicit deny all
    has_deny_all = any(
        r["type"] == "block" and r["source"] == "1" and r["destination"] == "1"
        for r in rules
    )
    if not has_deny_all:
        findings.append("[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found")

    return findings


def check_nist_compliance_pf(rules):
    """NIST SP 800-41 / NIST 800-53 checks for pfSense."""
    findings = []

    for r in rules:
        iface = r.get("interface", "unknown")

        # NIST AC-6 — Least privilege
        if r["type"] == "pass" and r["source"] == "1" and r["destination"] == "1":
            findings.append(
                f"[NIST-HIGH] NIST AC-6: Rule '{r['descr']}' violates least privilege (any/any on {iface})"
            )

        # NIST AU-2 — Audit logging
        if r["type"] == "pass" and not r["log"]:
            findings.append(
                f"[NIST-MEDIUM] NIST AU-2: Rule '{r['descr']}' missing audit logging"
            )

        # NIST CM-7 — Least functionality: no protocol 'any'
        if r["type"] == "pass" and r.get("protocol") in ("any", "", None):
            findings.append(
                f"[NIST-MEDIUM] NIST CM-7: Rule '{r['descr']}' permits any protocol — restrict to required protocols (least functionality)"
            )

    # NIST SC-7 — Boundary protection
    has_deny_all = any(
        r["type"] == "block" and r["source"] == "1" and r["destination"] == "1"
        for r in rules
    )
    if not has_deny_all:
        findings.append("[NIST-HIGH] NIST SC-7: No boundary protection deny-all rule found")

    return findings


# ══════════════════════════════════════════════════════════ HIPAA COMPLIANCE ══


def check_hipaa_compliance(parse):
    """HIPAA Security Rule checks for Cisco ASA.

    Maps to 45 CFR Part 164, Subpart C (Security Standards).
    """
    findings = []

    # §164.312(a)(1) — Access control: no any/any permit
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[HIPAA-HIGH] HIPAA §164.312(a)(1): {len(any_any)} any/any permit rule(s) violate access control"
        )

    # §164.312(b) — Audit controls: all permit rules must log
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.312(b): Permit rule missing audit logging: {rule.text.strip()}"
            )

    # §164.308(a)(1)(ii)(A) — Risk analysis: no explicit deny-all
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.308(a)(1)(ii)(A): No explicit deny-all rule — boundary risk not addressed"
        )

    # §164.312(e)(1) — Transmission security: Telnet in use
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.312(e)(1): Telnet transmits ePHI in cleartext — disable and enforce SSH"
        )

    # §164.312(e)(1) — Transmission security: SSHv1
    if parse.find_objects(r"^ssh version 1"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.312(e)(1): SSHv1 in use — weak encryption threatens ePHI transmission security"
        )

    # §164.308(a)(5)(ii)(B) — Malware protection: HTTP server enabled
    if parse.find_objects(r"^http server enable"):
        findings.append(
            "[HIPAA-MEDIUM] HIPAA §164.308(a)(5)(ii)(B): HTTP management server enabled — use HTTPS only to protect ePHI"
        )

    # §164.308(a)(4) — Information access management: SNMPv1/v2c
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.308(a)(4): SNMPv1/v2c in use — cleartext SNMP can expose ePHI network data; migrate to SNMPv3"
        )

    # §164.312(a)(2)(i) — Unique user identification: no login banner
    if not parse.find_objects(r"^banner (login|motd)"):
        findings.append(
            "[HIPAA-MEDIUM] HIPAA §164.312(a)(2)(i): No login banner — required for authorized-use notice and user accountability"
        )

    return findings


def check_hipaa_compliance_ftd(parse):
    """HIPAA Security Rule checks for Cisco FTD (LINA CLI)."""
    findings = []

    # §164.312(a)(1) — Access control: any/any permit
    any_any = parse.find_objects(r"access-list.*permit.*any any")
    if any_any:
        findings.append(
            f"[HIPAA-HIGH] HIPAA §164.312(a)(1): {len(any_any)} any/any permit rule(s) violate access control"
        )

    # §164.312(b) — Audit controls: logging
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.312(b): Permit rule missing audit logging: {rule.text.strip()}"
            )

    # §164.308(a)(1)(ii)(A) — Risk analysis: deny-all
    if not parse.find_objects(r"access-list.*deny ip any any"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.308(a)(1)(ii)(A): No explicit deny-all rule — boundary risk not mitigated"
        )

    # §164.312(e)(1) — Transmission security: Telnet
    if parse.find_objects(r"^telnet\s"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.312(e)(1): Telnet configured — ePHI transmission in cleartext"
        )

    # §164.308(a)(5)(ii)(B) — Malware / threat detection
    if not parse.find_objects(r"^threat-detection basic-threat"):
        findings.append(
            "[HIPAA-MEDIUM] HIPAA §164.308(a)(5)(ii)(B): Threat detection not enabled — enable basic threat detection to protect ePHI systems"
        )

    # §164.308(a)(5)(ii)(B) — IPS / Snort inspection
    if not parse.find_objects(r"^access-control-policy"):
        findings.append(
            "[HIPAA-MEDIUM] HIPAA §164.308(a)(5)(ii)(B): No access-control-policy — IPS/Snort inspection may not be active"
        )

    # §164.308(a)(4) — Information access management: SNMPv1/v2c
    for r in parse.find_objects(r"^snmp-server community"):
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.308(a)(4): SNMPv1/v2c community string detected — migrate to SNMPv3 to protect ePHI network data"
        )

    return findings


def check_hipaa_compliance_pa(rules):
    """HIPAA Security Rule checks for Palo Alto Networks."""
    findings = []

    for rule in rules:
        name = rule.get("name", "unnamed")
        src  = rule.get("from", [])
        dst  = rule.get("to", [])
        act  = rule.get("action", "")
        log  = rule.get("log-end", "no")

        # §164.312(a)(1) — Access control: any/any permit
        if act == "allow" and "any" in src and "any" in dst:
            findings.append(
                f"[HIPAA-HIGH] HIPAA §164.312(a)(1): Rule '{name}' permits any-to-any — violates access control"
            )

        # §164.312(b) — Audit controls: log-end
        if act == "allow" and log != "yes":
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.312(b): Rule '{name}' missing session-end logging — audit trail incomplete"
            )

        # §164.308(a)(5)(ii)(B) — Malware: security profiles
        profiles = rule.get("profile-setting", {})
        has_profiles = bool(profiles.get("profiles") or profiles.get("group"))
        if act == "allow" and not has_profiles:
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.308(a)(5)(ii)(B): Rule '{name}' has no security profile — AV/IPS protection for ePHI not applied"
            )

    # §164.308(a)(1)(ii)(A) — Risk analysis: no deny-all
    has_deny_all = any(
        r.get("action") == "deny" and "any" in r.get("from", []) and "any" in r.get("to", [])
        for r in rules
    )
    if not has_deny_all:
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.308(a)(1)(ii)(A): No explicit deny-all rule — boundary risk not addressed"
        )

    return findings


def check_hipaa_compliance_forti(policies):
    """HIPAA Security Rule checks for Fortinet FortiGate."""
    findings = []

    for p in policies:
        name    = p.get("name", f"policy-{p.get('policyid', '?')}")
        srcaddr = p.get("srcaddr", [])
        dstaddr = p.get("dstaddr", [])
        action  = p.get("action", "")
        logtr   = p.get("logtraffic", "disable")
        av      = p.get("av-profile", "")
        ips     = p.get("ips-sensor", "")

        # §164.312(a)(1) — Access control: any/any permit
        if action == "accept" and "all" in srcaddr and "all" in dstaddr:
            findings.append(
                f"[HIPAA-HIGH] HIPAA §164.312(a)(1): Policy '{name}' allows all-to-all — violates access control"
            )

        # §164.312(b) — Audit controls: logging
        if action == "accept" and logtr == "disable":
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.312(b): Policy '{name}' has logging disabled — no audit trail for ePHI traffic"
            )

        # §164.308(a)(5)(ii)(B) — Malware: AV profile
        if action == "accept" and not av:
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.308(a)(5)(ii)(B): Policy '{name}' has no AV profile — malware protection for ePHI missing"
            )

        # §164.308(a)(5)(ii)(B) — IPS sensor
        if action == "accept" and not ips:
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.308(a)(5)(ii)(B): Policy '{name}' has no IPS sensor — intrusion protection for ePHI missing"
            )

        # §164.312(e)(1) — Transmission security: service ALL
        service = p.get("service", [])
        if action == "accept" and "ALL" in service:
            findings.append(
                f"[HIPAA-HIGH] HIPAA §164.312(e)(1): Policy '{name}' permits ALL services — restrict to required services to protect ePHI"
            )

    # §164.308(a)(1)(ii)(A) — Risk analysis: disabled policies accumulate risk
    disabled = [p for p in policies if p.get("status") == "disable"]
    if disabled:
        findings.append(
            f"[HIPAA-MEDIUM] HIPAA §164.308(a)(1)(ii)(A): {len(disabled)} disabled policy/policies not reviewed — stale rules increase ePHI risk"
        )

    return findings


def check_hipaa_compliance_pf(rules):
    """HIPAA Security Rule checks for pfSense."""
    findings = []

    for r in rules:
        iface = r.get("interface", "unknown")
        descr = r.get("descr", "unnamed")

        # §164.312(a)(1) — Access control: any/any pass
        if r["type"] == "pass" and r["source"] == "1" and r["destination"] == "1":
            findings.append(
                f"[HIPAA-HIGH] HIPAA §164.312(a)(1): Rule '{descr}' on {iface} allows any/any — violates access control"
            )

        # §164.312(b) — Audit controls: logging
        if r["type"] == "pass" and not r["log"]:
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.312(b): Rule '{descr}' on {iface} missing logging — audit trail incomplete"
            )

        # §164.312(e)(1) — Transmission security: protocol any
        if r["type"] == "pass" and r.get("protocol") in ("any", "", None):
            findings.append(
                f"[HIPAA-MEDIUM] HIPAA §164.312(e)(1): Rule '{descr}' on {iface} permits any protocol — restrict to required protocols"
            )

    # §164.308(a)(1)(ii)(A) — Risk analysis: no explicit block-all
    has_deny_all = any(
        r["type"] == "block" and r["source"] == "1" and r["destination"] == "1"
        for r in rules
    )
    if not has_deny_all:
        findings.append(
            "[HIPAA-HIGH] HIPAA §164.308(a)(1)(ii)(A): No explicit deny-all rule — boundary protection risk not addressed"
        )

    return findings
