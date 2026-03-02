import typer
import logging
from loguru import logger
logger.disable("ciscoconfparse")

from ciscoconfparse import CiscoConfParse

app = typer.Typer()

def check_any_any(parse):
    findings = []
    for rule in parse.find_objects(r"access-list.*permit.*any any"):
        findings.append(f"[HIGH] Overly permissive rule found: {rule.text}")
    return findings
def check_missing_logging(parse):
    findings = []
    for rule in parse.find_objects(r"access-list.*permit"):
        if "log" not in rule.text:
            findings.append(f"[MEDIUM] Permit rule missing logging: {rule.text}")
    return findings
def check_deny_all(parse):
    findings = []
    deny_rules = parse.find_objects(r"access-list.*deny ip any any")
    if not deny_rules:
        findings.append("[HIGH] No explicit deny-all rule found at end of ACL")
    return findings
def check_redundant_rules(parse):
    findings = []
    seen = []
    for rule in parse.find_objects(r"access-list.*permit"):
        # Strip the line down to core components to compare
        text = rule.text.strip().lower()
        # Remove 'log' from end for comparison purposes
        text_clean = text.replace(" log", "").strip()
        if text_clean in seen:
            findings.append(f"[MEDIUM] Redundant rule detected: {rule.text}")
        else:
            seen.append(text_clean)
    return findings

@app.command()
def audit(
    file: str = typer.Option(None, "--file", "-f", help="Path to firewall config file"),
    vendor: str = typer.Option(None, "--vendor", "-v", help="Firewall vendor: paloalto, asa, pfsense")
):
    """FWAudit - Firewall configuration auditing tool"""

    if not file or not vendor:
        typer.echo("FWAudit v0.1")
        typer.echo("Usage: python3 src/fwaudit/main.py --file config.txt --vendor asa")
        raise typer.Exit()

    typer.echo(f"\nFWAudit v0.1 — Starting audit of {file} ({vendor})\n")

    if vendor == "asa":
        parse = CiscoConfParse(file, ignore_blank_lines=False)
        findings = []
        findings += check_any_any(parse)
        findings += check_missing_logging(parse)
        findings += check_deny_all(parse)
        findings += check_redundant_rules(parse)
    
        if findings:
            for f in findings:
                typer.echo(f)
        else:
            typer.echo("[PASS] No issues found")
    
    high = [f for f in findings if "[HIGH]" in f]
    medium = [f for f in findings if "[MEDIUM]" in f]

    typer.echo(f"\n--- Audit Summary ---")
    typer.echo(f"High Severity:   {len(high)}")
    typer.echo(f"Medium Severity: {len(medium)}")
    typer.echo(f"Total Issues:    {len(findings)}")
    typer.echo(f"---------------------")
    

if __name__ == "__main__":
    app()