# Cashel — CLI Reference

## Basic usage

```bash
PYTHONPATH=src python -m cashel.main --file config.txt --vendor asa
```

## With compliance checks (legacy gate under review)

```bash
PYTHONPATH=src python -m cashel.main --file config.txt --vendor asa --compliance pci
```

## Export PDF report

```bash
PYTHONPATH=src python -m cashel.main --file config.txt --vendor asa --report
```

## Supported `--vendor` values

```
--vendor cisco      Cisco ASA or FTD (auto-detected from config content)
--vendor fortinet   Fortinet FortiGate
--vendor gcp        GCP VPC Firewall
--vendor iptables   iptables (Linux)
--vendor juniper    Juniper SRX
--vendor nftables   nftables (Linux)
--vendor paloalto   Palo Alto Networks
--vendor pfsense    pfSense
--vendor aws        AWS Security Groups
--vendor azure      Azure NSG
```

Omit `--vendor` to use auto-detection.

## Supported `--compliance` values

```
--compliance cis     CIS Benchmark
--compliance hipaa   HIPAA Security Rule
--compliance nist    NIST SP 800-41
--compliance pci     PCI-DSS
--compliance soc2    SOC2
--compliance stig    DISA STIG
```

Compliance checks run without a license or legacy access state when a supported
framework is selected.

## Example output

```
Cashel — Starting audit of firewall.xml (paloalto)

[HIGH] Overly permissive rule 'Allow-Any-Any': source=any destination=any
[HIGH] No explicit deny-all rule found
[MEDIUM] Permit rule 'Allow-Any-Any' missing logging
[MEDIUM] Redundant rule detected: 'Allow-Web-Duplicate'

--- PCI Compliance Checks ---
[PCI-HIGH] PCI Req 1.3: Rule 'Allow-Any-Any' - direct routes to cardholder data prohibited
[PCI-HIGH] PCI Req 1.2: No explicit deny-all rule found
[PCI-MEDIUM] PCI Req 10.2: Rule 'Allow-Any-Any' missing audit logging

--- Audit Summary ---
High Severity:         2
Medium Severity:       2
PCI Compliance High:   2
PCI Compliance Medium: 1
Total Issues:          7
Score:                 54/100
---------------------

Report saved to: report.pdf
```

---

## CI policy gate — `cashel gate`

Audit a config and exit non-zero when it violates policy. Built for
pipelines: gate a firewall change in CI before it ships.

```bash
# Fail the build on any HIGH or CRITICAL finding (default policy)
cashel gate --file fw.cfg

# Stricter: also require a minimum score, include PCI checks
cashel gate --file fw.cfg --compliance pci --fail-on medium --min-score 70

# Machine-readable result (for CI artifacts / downstream tooling)
cashel gate --file fw.cfg --json > gate-result.json

# Regression gating: fail only on findings NEW versus an approved baseline.
# This is the brownfield adoption path — existing finding debt doesn't block
# the pipeline, but any new HIGH+ finding does.
cashel gate --file fw.cfg --baseline approved/fw.cfg
```

| Option | Default | Meaning |
|---|---|---|
| `--file, -f` | required | Config file to audit |
| `--vendor, -v` | auto-detect | Vendor key (same values as `audit`) |
| `--compliance, -c` | none | Also run a compliance framework |
| `--fail-on` | `high` | Fail if any finding is at or above this severity (`critical`, `high`, `medium`, `low`) |
| `--min-score` | none | Fail if the 0–100 audit score is below this value |
| `--baseline, -b` | none | Approved baseline config; the severity gate then applies only to NEW findings (`min-score` still checks the full audit). New/resolved findings are reported in both output modes. |
| `--json` | off | Emit the full gate document to stdout |

**Exit codes:** `0` gate passed · `1` gate violation · `2` usage or input error.

The `--json` document includes provenance — `config_sha256`, config size,
engine version, and timestamp — so any verdict can be reproduced from the
same input. Same config + same policy + same engine version ⇒ same result.

GitHub Actions example:

```yaml
- name: Gate firewall config
  run: |
    pip install cashel
    cashel gate --file firewall/edge.cfg --fail-on high --min-score 70
```

---

## SSH commands by vendor

These are the commands Cashel issues when connecting to a device via Live SSH.

| Vendor | Command issued |
|---|---|
| Cisco (ASA / FTD) | `terminal pager 0` → `show running-config` |
| Fortinet | `show full-configuration firewall policy` |
| iptables (Linux) | `iptables-save` (sudo fallback) |
| Juniper SRX | `set cli screen-length 0` → `show configuration \| display set` |
| nftables (Linux) | `nft list ruleset` (sudo fallback) |
| Palo Alto | `show config running` |
| pfSense | `cat /conf/config.xml` |
