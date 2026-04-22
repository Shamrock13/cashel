"""Reports blueprint — /reports/* and /remediation-plan."""

import io
import logging
import os
import uuid
import zipfile
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, send_file

from cashel._helpers import _require_role
from cashel.archive import get_entry
from cashel.export import to_csv, to_json, to_sarif
from cashel.extensions import limiter
from cashel.remediation import generate_plan, plan_to_markdown, plan_to_pdf
from cashel.reporter import generate_cover_pdf, generate_report

logger = logging.getLogger(__name__)

REPORTS_FOLDER = os.environ.get("REPORTS_FOLDER", "/tmp/cashel_reports")

reports_bp = Blueprint("reports", __name__)


def _safe_report_path(filename):
    """Resolve a report filename and verify it stays inside REPORTS_FOLDER."""
    path = os.path.realpath(os.path.join(REPORTS_FOLDER, filename))
    if not path.startswith(os.path.realpath(REPORTS_FOLDER) + os.sep):
        return None
    if not os.path.exists(path):
        return None
    return path


@reports_bp.route("/reports", methods=["GET"])
def reports_list():
    """List all saved PDF reports."""
    reports = []
    for fname in sorted(os.listdir(REPORTS_FOLDER), reverse=True):
        if fname.endswith(".pdf"):
            path = os.path.join(REPORTS_FOLDER, fname)
            reports.append(
                {
                    "filename": fname,
                    "size": os.path.getsize(path),
                    "mtime": os.path.getmtime(path),
                }
            )
    return jsonify(reports)


@reports_bp.route("/reports/<filename>")
def download_report(filename):
    path = _safe_report_path(filename)
    if not path:
        return "Not found", 404
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@reports_bp.route("/reports/<filename>/view")
def view_report(filename):
    """Serve PDF inline for in-browser viewing."""
    path = _safe_report_path(filename)
    if not path:
        return "Not found", 404
    return send_file(path, as_attachment=False, mimetype="application/pdf")


@reports_bp.route("/remediation-plan", methods=["POST"])
@limiter.limit("30/minute")
def remediation_plan_inline():
    """Generate a remediation plan from inline audit data (POST JSON).

    Expected body: {findings, vendor, filename?, compliance?, summary?}
    Query param: fmt = json | markdown | pdf  (default: json)
    """
    from flask import current_app

    data = request.get_json(silent=True) or {}
    findings = data.get("findings") or data.get("enriched_findings") or []
    vendor = data.get("vendor", "unknown")
    filename = data.get("filename", "")
    compliance = data.get("compliance")
    summary = data.get("summary")

    if not findings:
        return jsonify({"error": "No findings provided."}), 400

    plan = generate_plan(findings, vendor, filename, compliance, summary)
    fmt = request.args.get("fmt", "json").lower()

    if fmt == "json":
        return jsonify(plan)
    elif fmt == "markdown":
        md = plan_to_markdown(plan)
        base = (filename or "audit").rsplit(".", 1)[0]
        return current_app.response_class(
            md,
            mimetype="text/markdown",
            headers={
                "Content-Disposition": f'attachment; filename="{base}_remediation.md"'
            },
        )
    elif fmt == "pdf":
        inline = request.args.get("inline") == "1"
        report_name = f"remediation_{uuid.uuid4().hex[:8]}.pdf"
        report_path = os.path.join(REPORTS_FOLDER, report_name)
        os.makedirs(REPORTS_FOLDER, exist_ok=True)
        plan_to_pdf(plan, report_path)
        download_name = f"{(filename or 'audit').rsplit('.', 1)[0]}_remediation.pdf"
        return send_file(
            report_path,
            mimetype="application/pdf",
            as_attachment=not inline,
            download_name=download_name,
        )
    else:
        return jsonify(
            {"error": f"Unknown format '{fmt}'. Use json, markdown, or pdf."}
        ), 400


@reports_bp.route("/reports/<report_id>/evidence-bundle", methods=["POST"])
@_require_role("admin", "auditor")
def evidence_bundle(report_id):
    """Generate and download a compliance evidence bundle ZIP for an archived audit.

    Optional query param: ?compliance=pci,cis — filter/label compliance frameworks.
    Returns a ZIP with: audit_report.pdf, findings.csv, findings.json,
    findings.sarif, and cover.pdf (one-page summary).
    """
    entry = get_entry(report_id)
    if not entry:
        return jsonify({"error": "Not found"}), 404

    compliance_param = request.args.get("compliance")

    os.makedirs(REPORTS_FOLDER, exist_ok=True)
    run_id = uuid.uuid4().hex[:8]

    # ── Generate audit_report.pdf ──────────────────────────────────────────────
    audit_pdf_path = os.path.join(REPORTS_FOLDER, f"bundle_audit_{run_id}.pdf")
    generate_report(
        findings=entry.get("findings", []),
        filename=entry.get("filename", ""),
        vendor=entry.get("vendor", "unknown"),
        compliance=compliance_param,
        output_path=audit_pdf_path,
        summary=entry.get("summary"),
    )

    # ── Generate cover.pdf ─────────────────────────────────────────────────────
    cover_pdf_path = os.path.join(REPORTS_FOLDER, f"bundle_cover_{run_id}.pdf")
    generate_cover_pdf(entry, cover_pdf_path, compliance=compliance_param)

    # ── Assemble ZIP in memory ─────────────────────────────────────────────────
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("findings.json", to_json(entry))
        zf.writestr("findings.csv", to_csv(entry))
        zf.writestr("findings.sarif", to_sarif(entry))
        with open(audit_pdf_path, "rb") as fh:
            zf.writestr("audit_report.pdf", fh.read())
        with open(cover_pdf_path, "rb") as fh:
            zf.writestr("cover.pdf", fh.read())
    zip_buf.seek(0)

    # ── Clean up temp PDFs ─────────────────────────────────────────────────────
    for path in (audit_pdf_path, cover_pdf_path):
        try:
            os.remove(path)
        except OSError:
            logger.warning("Could not remove temp file: %s", path)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    download_name = f"cashel_evidence_{report_id}_{timestamp}.zip"

    return send_file(
        zip_buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=download_name,
    )
