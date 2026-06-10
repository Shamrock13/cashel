import json
import sys

import typer
from pathlib import Path
from .reporter import generate_report
from .audit_engine import (
    _build_summary,
    _finding_msg,
    run_compliance_checks,
    run_vendor_audit,
)

cli = typer.Typer(no_args_is_help=False)

_VALID_VENDORS = [
    "asa",
    "ftd",
    "paloalto",
    "fortinet",
    "pfsense",
    "aws",
    "azure",
    "gcp",
    "juniper",
    "iptables",
    "nftables",
]
_VALID_FRAMEWORKS = ["cis", "pci", "nist", "hipaa", "soc2", "stig"]


def _resolve_vendor(vendor: str | None, file: str) -> str:
    """Validate an explicit vendor or auto-detect one from the config file."""
    if vendor:
        if vendor not in _VALID_VENDORS:
            typer.echo(f"Unknown vendor: {vendor}. Use: {', '.join(_VALID_VENDORS)}")
            raise typer.Exit(1)
        return vendor
    from ._vendor_helpers import detect_vendor

    try:
        content = Path(file).read_text(errors="replace")
    except OSError as exc:
        typer.echo(f"Cannot read file: {exc}", err=True)
        raise typer.Exit(1)
    detected = detect_vendor(content, Path(file).name)
    if not detected or detected not in _VALID_VENDORS:
        typer.echo(
            "Could not auto-detect vendor. Specify one with "
            f"--vendor: {', '.join(_VALID_VENDORS)}",
            err=True,
        )
        raise typer.Exit(1)
    typer.echo(f"Auto-detected vendor: {detected}")
    return detected


@cli.command()
def audit(
    file: str = typer.Option(None, "--file", "-f", help="Path to firewall config file"),
    vendor: str = typer.Option(
        None,
        "--vendor",
        "-v",
        help="Firewall vendor: asa, ftd, paloalto, fortinet, pfsense, aws, azure, gcp, juniper, iptables, nftables",
    ),
    compliance: str = typer.Option(
        None,
        "--compliance",
        "-c",
        help="Compliance framework: cis, pci, nist, hipaa, soc2, stig",
    ),
    report: bool = typer.Option(False, "--report", "-r", help="Export PDF report"),
):
    """Cashel - Firewall configuration auditing tool"""

    if not file:
        typer.echo("Cashel v2.0.0")
        typer.echo("Usage: python3 src/cashel/main.py --file config.txt --vendor asa")
        raise typer.Exit()

    if compliance and compliance not in _VALID_FRAMEWORKS:
        typer.echo(
            f"Unknown framework: {compliance}. Use: {', '.join(_VALID_FRAMEWORKS)}"
        )
        raise typer.Exit(1)

    if not Path(file).is_file():
        typer.echo(f"File not found: {file}", err=True)
        raise typer.Exit(1)

    vendor = _resolve_vendor(vendor, file)

    from .fidelity import vendor_fidelity

    fid = vendor_fidelity(vendor)
    typer.echo(f"\nCashel v2.0.0 — Starting audit of {file} ({vendor})")
    typer.echo(
        f"Parser fidelity: {fid['maturity']} (enrichment: {fid['enrichment']})\n"
    )

    findings, parse, extra_data = run_vendor_audit(vendor, file)

    if findings:
        for f in findings:
            typer.echo(_finding_msg(f))
    else:
        typer.echo("[PASS] No issues found")

    if compliance:
        typer.echo(f"\n--- {compliance.upper()} Compliance Checks ---")
        cf = run_compliance_checks(vendor, compliance, parse, extra_data, file)
        for f in cf:
            typer.echo(_finding_msg(f) if isinstance(f, dict) else f)
        findings = list(findings) + list(cf)

    if report:
        output = generate_report(findings, file, vendor, compliance)
        typer.echo(f"\n📄 Report saved to: {output}")

    s = _build_summary(findings)
    typer.echo("\n--- Audit Summary ---")
    typer.echo(f"High Severity:         {s['high']}")
    typer.echo(f"Medium Severity:       {s['medium']}")
    if s["pci_high"] or s["pci_medium"]:
        typer.echo(f"PCI Compliance High:   {s['pci_high']}")
        typer.echo(f"PCI Compliance Medium: {s['pci_medium']}")
    if s["cis_high"] or s["cis_medium"]:
        typer.echo(f"CIS Compliance High:   {s['cis_high']}")
        typer.echo(f"CIS Compliance Medium: {s['cis_medium']}")
    if s["nist_high"] or s["nist_medium"]:
        typer.echo(f"NIST Compliance High:  {s['nist_high']}")
        typer.echo(f"NIST Compliance Medium:{s['nist_medium']}")
    if s["hipaa_high"] or s["hipaa_medium"]:
        typer.echo(f"HIPAA Compliance High: {s['hipaa_high']}")
        typer.echo(f"HIPAA Compliance Medium:{s['hipaa_medium']}")
    if s["soc2_high"] or s["soc2_medium"]:
        typer.echo(f"SOC2 Compliance High:  {s['soc2_high']}")
        typer.echo(f"SOC2 Compliance Medium:{s['soc2_medium']}")
    if s["stig_cat_i"] or s["stig_cat_ii"] or s["stig_cat_iii"]:
        typer.echo(f"STIG CAT I:            {s['stig_cat_i']}")
        typer.echo(f"STIG CAT II:           {s['stig_cat_ii']}")
        typer.echo(f"STIG CAT III:          {s['stig_cat_iii']}")
    typer.echo(f"Total Issues:          {s['total']}")
    typer.echo("---------------------")


@cli.command()
def gate(
    file: str = typer.Option(..., "--file", "-f", help="Path to firewall config file"),
    vendor: str = typer.Option(
        None, "--vendor", "-v", help="Firewall vendor (auto-detected if omitted)"
    ),
    compliance: str = typer.Option(
        None,
        "--compliance",
        "-c",
        help="Also run compliance checks: cis, pci, nist, hipaa, soc2, stig",
    ),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Fail if any finding is at or above this severity: critical, high, medium, low",
    ),
    min_score: int = typer.Option(
        None, "--min-score", help="Fail if the audit score (0-100) is below this value"
    ),
    baseline: str = typer.Option(
        None,
        "--baseline",
        "-b",
        help="Approved baseline config; the severity gate then applies only to NEW findings",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit machine-readable gate result to stdout"
    ),
):
    """CI policy gate: audit a config and exit non-zero on policy violation.

    Exit codes: 0 = gate passed, 1 = gate violation, 2 = usage/input error.
    """
    from .gate import build_gate_document, evaluate_gate

    if not Path(file).is_file():
        typer.echo(f"File not found: {file}", err=True)
        raise typer.Exit(2)
    if baseline and not Path(baseline).is_file():
        typer.echo(f"Baseline file not found: {baseline}", err=True)
        raise typer.Exit(2)
    if compliance and compliance not in _VALID_FRAMEWORKS:
        typer.echo(
            f"Unknown framework: {compliance}. Use: {', '.join(_VALID_FRAMEWORKS)}",
            err=True,
        )
        raise typer.Exit(2)

    vendor = _resolve_vendor(vendor, file)

    def _audit(path: str) -> list:
        findings, parse, extra_data = run_vendor_audit(vendor, path)
        if compliance:
            findings = list(findings) + list(
                run_compliance_checks(vendor, compliance, parse, extra_data, path)
            )
        return list(findings)

    findings = _audit(file)
    baseline_findings = _audit(baseline) if baseline else None

    try:
        result = evaluate_gate(
            findings,
            fail_on=fail_on,
            min_score=min_score,
            baseline_findings=baseline_findings,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2)

    if json_output:
        doc = build_gate_document(
            result,
            findings,
            file=file,
            vendor=vendor,
            compliance=compliance,
            baseline_file=baseline,
        )
        typer.echo(json.dumps(doc, indent=2, default=str))
    else:
        from .fidelity import vendor_fidelity

        fid = vendor_fidelity(vendor)
        c = result["counts"]
        typer.echo(f"\nCashel gate — {file} ({vendor})")
        typer.echo(
            f"Parser fidelity: {fid['maturity']} (enrichment: {fid['enrichment']})"
        )
        typer.echo(
            f"Score: {result['score']}  "
            f"critical:{c['critical']} high:{c['high']} "
            f"medium:{c['medium']} low:{c['low']} info:{c['info']}"
        )
        if "baseline" in result:
            b = result["baseline"]
            typer.echo(
                f"Baseline: {baseline} — "
                f"{b['new_count']} new, {b['resolved_count']} resolved"
            )
        for v in result["violations"]:
            typer.echo(f"VIOLATION [{v['rule']}] {v['message']}")
        typer.echo("GATE: PASS" if result["passed"] else "GATE: FAIL")

    raise typer.Exit(0 if result["passed"] else 1)


_COMMANDS = {"audit", "gate"}


def app(args: list[str] | None = None) -> None:
    """CLI entry point with legacy bare-option compatibility.

    `cashel --file fw.cfg --vendor asa` (pre-subcommand form) still works by
    routing option-style invocations to the `audit` command.
    """
    argv = list(sys.argv[1:]) if args is None else list(args)
    if argv and argv[0] not in _COMMANDS and argv[0] not in ("--help", "-h"):
        argv = ["audit"] + argv
    elif not argv:
        argv = ["audit"]
    cli(argv)


if __name__ == "__main__":
    app()
