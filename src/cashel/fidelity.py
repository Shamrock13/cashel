"""Parser fidelity registry — machine-readable, per-vendor coverage honesty.

Cashel does not claim equal depth for every parser. This registry is the
single machine-readable source for what each vendor path actually delivers,
mirrored in docs/vendor-enrichment-coverage.md. It is surfaced in CLI audit
output, gate documents, and GET /api/v1/vendors so results never imply more
coverage than the parser has.

Maturity levels (audit depth):
  mature        — primary investment area; strongest checks and evidence
  partial       — useful checks exist; coverage not uniformly normalized
  experimental  — basic static audit coverage only

Enrichment levels (finding model alignment):
  full     — current checks emit normalized findings with stable IDs,
             evidence, verification, rollback, and parser context
  partial  — normalized findings, but some check families lack parser
             context or complete metadata
"""

from __future__ import annotations

VENDOR_FIDELITY: dict[str, dict] = {
    "asa": {
        "display": "Cisco ASA",
        "maturity": "mature",
        "enrichment": "full",
        "notes": "Reference enrichment pattern; most normalized vendor path.",
    },
    "ftd": {
        "display": "Cisco FTD",
        "maturity": "mature",
        "enrichment": "partial",
        "notes": "Device posture checks carry config-presence evidence with limited metadata.",
    },
    "fortinet": {
        "display": "Fortinet FortiGate",
        "maturity": "mature",
        "enrichment": "full",
        "notes": "Policy-backed findings fully enriched; no management-plane parsing yet.",
    },
    "paloalto": {
        "display": "Palo Alto Networks",
        "maturity": "mature",
        "enrichment": "full",
        "notes": "Shadow checks use lighter metadata than policy-backed findings.",
    },
    "juniper": {
        "display": "Juniper SRX",
        "maturity": "partial",
        "enrichment": "partial",
        "notes": "Shadow checks have lighter metadata and no rollback guidance.",
    },
    "pfsense": {
        "display": "pfSense",
        "maturity": "partial",
        "enrichment": "partial",
        "notes": "Procedural (UI-oriented) remediation; shadow checks have lighter metadata.",
    },
    "iptables": {
        "display": "iptables",
        "maturity": "partial",
        "enrichment": "full",
        "notes": "Host-firewall reference pattern; filter-table checks only.",
    },
    "nftables": {
        "display": "nftables",
        "maturity": "partial",
        "enrichment": "full",
        "notes": "Host-firewall checks; table/chain/rule metadata included.",
    },
    "aws": {
        "display": "AWS Security Groups",
        "maturity": "experimental",
        "enrichment": "full",
        "notes": "Static checks only; no rule-order analysis (SGs are most-permissive).",
    },
    "azure": {
        "display": "Azure NSG",
        "maturity": "partial",
        "enrichment": "full",
        "notes": "Includes NSG shadow checks; flow-log confirmation is presence-based.",
    },
    "gcp": {
        "display": "GCP VPC Firewall",
        "maturity": "experimental",
        "enrichment": "full",
        "notes": "Static checks only; priority-based ordering not analyzed.",
    },
}


def vendor_fidelity(vendor: str) -> dict:
    """Fidelity record for a vendor key, with the key included.

    Unknown vendors return an explicit unknown record rather than guessing.
    """
    record = VENDOR_FIDELITY.get(vendor)
    if record is None:
        return {
            "vendor": vendor,
            "display": vendor,
            "maturity": "unknown",
            "enrichment": "unknown",
            "notes": "Vendor not in the fidelity registry.",
        }
    return {"vendor": vendor, **record}
