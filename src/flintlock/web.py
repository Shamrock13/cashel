import atexit
import json
import os
import re
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file

from .license import check_license, activate_license, deactivate_license
from .ftd import is_ftd_config
from .reporter import generate_report
from .audit_engine import (
    _findings_to_strings, _wrap_compliance,
    _sort_findings, _build_summary,
    run_vendor_audit, run_compliance_checks,
)
from .diff import diff_configs
from .archive import save_audit, list_archive, get_entry, delete_entry, compare_entries
from .activity_log import (
    log_activity, list_activity, delete_activity_entry, clear_activity,
    ACTION_FILE_AUDIT, ACTION_SSH_CONNECT, ACTION_CONFIG_DIFF,
)
from .settings import get_settings, save_settings
from .schedule_store import (
    list_schedules, get_schedule, create_schedule,
    update_schedule, delete_schedule,
)
from .scheduler_runner import (
    start_scheduler, stop_scheduler, reload_job,
    run_now as scheduler_run_now, scheduler_available,
)

UPLOAD_FOLDER    = os.environ.get("UPLOAD_FOLDER",    "/tmp/flintlock_uploads")
REPORTS_FOLDER   = os.environ.get("REPORTS_FOLDER",   "/tmp/flintlock_reports")
ARCHIVE_FOLDER   = os.environ.get("ARCHIVE_FOLDER",   "/tmp/flintlock_archive")
ACTIVITY_FOLDER  = os.environ.get("ACTIVITY_FOLDER",  "/tmp/flintlock_activity")

for _d in (UPLOAD_FOLDER, REPORTS_FOLDER, ARCHIVE_FOLDER, ACTIVITY_FOLDER):
    os.makedirs(_d, exist_ok=True)

# Settings folder is created lazily by settings.py on first save

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload limit


VENDOR_DISPLAY = {
    "asa":      "Cisco",
    "ftd":      "Cisco",
    "paloalto": "Palo Alto Networks",
    "fortinet": "Fortinet",
    "pfsense":  "pfSense",
    "aws":      "AWS Security Group",
    "azure":    "Azure NSG",
}

ALL_VENDORS = set(VENDOR_DISPLAY)


# ── Vendor auto-detection ─────────────────────────────────────────────────────

def detect_vendor(content: str, filename: str) -> str | None:
    """Infer firewall vendor from file content and filename."""
    filename_lower = filename.lower()
    content_lower  = content.lower()
    stripped       = content.strip()

    # JSON-based: AWS or Azure
    if stripped.startswith("{") or stripped.startswith("[") or filename_lower.endswith(".json"):
        try:
            data = json.loads(content[:8192])  # partial parse for detection
            if isinstance(data, dict):
                if "SecurityGroups" in data or "GroupId" in data or "IpPermissions" in data:
                    return "aws"
                if "securityRules" in data or "defaultSecurityRules" in data:
                    return "azure"
                if isinstance(data.get("value"), list):
                    # Could be az network nsg list output
                    if data["value"] and "securityRules" in data["value"][0]:
                        return "azure"
            elif isinstance(data, list) and data:
                first = data[0]
                if "GroupId" in first or "IpPermissions" in first:
                    return "aws"
                if "securityRules" in first or "defaultSecurityRules" in first:
                    return "azure"
        except Exception:
            pass

    # XML-based: pfSense or Palo Alto
    if stripped.startswith("<") or filename_lower.endswith(".xml"):
        if "<pfsense>" in content_lower or ("<filter>" in content_lower and "<rule>" in content_lower):
            return "pfsense"
        if any(k in content_lower for k in ("<devices>", "<vsys>", "<security>", "<rulebase>")):
            return "paloalto"

    # Text-based: Fortinet
    if "config firewall policy" in content_lower or (
        "set srcintf" in content_lower and "set dstintf" in content_lower
    ):
        return "fortinet"

    # Text-based: Cisco FTD (check before ASA — FTD has ASA-style ACLs too)
    if any(k in content_lower for k in ("access-control-policy", "firepower threat defense",
                                         "firepower-module", "intrusion-policy")):
        return "ftd"

    # Text-based: Cisco ASA
    if "access-list" in content_lower and any(k in content_lower for k in ("permit", "deny")):
        return "asa"

    return None


def validate_vendor_format(content: str, filename: str, vendor: str) -> tuple[bool, str]:
    """Return (is_valid, error_message). Ensures the file actually matches the vendor format."""
    content_lower = content.lower()
    is_xml  = content.strip().startswith("<") or filename.lower().endswith(".xml")
    is_json = content.strip().startswith(("{", "[")) or filename.lower().endswith(".json")

    if vendor == "ftd":
        if is_xml or is_json:
            return False, "Cisco FTD LINA configs are text-based, but this file appears to be XML or JSON."
        # FTD configs may or may not have access-list; require at least some Cisco CLI content
        if not any(k in content_lower for k in ("access-list", "access-control-policy",
                                                  "threat-detection", "intrusion-policy",
                                                  "interface", "firepower")):
            return False, "No recognizable Cisco FTD configuration markers found. Check vendor selection."

    elif vendor == "asa":
        if is_xml or is_json:
            return False, "Cisco configs are text-based, but this file appears to be XML or JSON."
        # If the file actually looks like FTD, upgrade silently
        if is_ftd_config(content):
            return True, ""  # will be re-routed to ftd in run_audit
        if "access-list" not in content_lower:
            return False, "No Cisco access-list statements found. Check vendor selection."

    elif vendor == "paloalto":
        if not is_xml:
            return False, "Palo Alto configs are XML-based, but this file is not XML."
        if not any(m in content_lower for m in ("<devices>", "<vsys>", "<security>", "<rulebase>")):
            return False, "This XML does not contain Palo Alto Networks configuration markers."

    elif vendor == "fortinet":
        if is_xml or is_json:
            return False, "Fortinet configs are text-based, but this file appears to be XML or JSON."
        if not any(m in content_lower for m in ("config firewall policy", "set srcintf", "set dstintf")):
            return False, "No Fortinet firewall policy statements found. Check vendor selection."

    elif vendor == "pfsense":
        if not is_xml:
            return False, "pfSense configs are XML-based, but this file is not XML."
        if "<pfsense>" not in content_lower:
            return False, "pfSense root element <pfsense> not found in this XML file."

    elif vendor == "aws":
        if not is_json:
            return False, "AWS Security Group exports are JSON. Please upload a .json file."

    elif vendor == "azure":
        if not is_json:
            return False, "Azure NSG exports are JSON. Please upload a .json file."

    else:
        return False, f"Unknown vendor: {vendor}"

    return True, ""


# ── Hostname extraction ───────────────────────────────────────────────────────

def extract_hostname(vendor: str, content: str) -> str | None:
    """Try to extract the device hostname from a config file."""
    try:
        if vendor in ("asa", "ftd"):
            m = re.search(r"^hostname\s+(\S+)", content, re.MULTILINE)
            return m.group(1) if m else None

        if vendor == "paloalto":
            root = ET.fromstring(content)
            el = root.find(".//devices/entry/deviceconfig/system/hostname")
            return el.text.strip() if el is not None and el.text else None

        if vendor == "fortinet":
            block = re.search(r"config system global(.*?)end", content, re.DOTALL)
            if block:
                m = re.search(r'set hostname\s+"?([^"\n]+)"?', block.group(1))
                return m.group(1).strip().strip('"') if m else None
            return None

        if vendor == "pfsense":
            root = ET.fromstring(content)
            el = root.find("system/hostname")
            return el.text.strip() if el is not None and el.text else None

        if vendor == "aws":
            data = json.loads(content)
            groups = data if isinstance(data, list) else data.get("SecurityGroups", [data])
            if groups:
                for t in groups[0].get("Tags", []):
                    if t.get("Key") == "Name":
                        return t["Value"]
                return groups[0].get("GroupName")

        if vendor == "azure":
            data = json.loads(content)
            items = data.get("value", [data]) if isinstance(data, dict) else data
            if items:
                return items[0].get("name")

    except Exception:
        pass
    return None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    licensed, license_info = check_license()
    return render_template("index.html", licensed=licensed, license_info=license_info)


@app.route("/audit", methods=["POST"])
def run_audit():
    if "config" not in request.files or request.files["config"].filename == "":
        return jsonify({"error": "No config file uploaded"}), 400

    vendor       = request.form.get("vendor", "auto").strip().lower()
    compliance   = request.form.get("compliance", "").strip().lower() or None
    generate_pdf = request.form.get("report") == "1"
    archive_it   = request.form.get("archive") == "1"
    tag          = request.form.get("tag", "").strip() or None

    upload = request.files["config"]
    suffix = Path(upload.filename).suffix or ".txt"
    temp_name = f"{uuid.uuid4()}{suffix}"
    temp_path = os.path.join(UPLOAD_FOLDER, temp_name)
    upload.save(temp_path)

    try:
        with open(temp_path, "r", errors="ignore") as f:
            sample = f.read(16384)
    except Exception:
        sample = ""

    if vendor == "auto":
        vendor = detect_vendor(sample, upload.filename) or ""

    if vendor not in ALL_VENDORS:
        os.remove(temp_path)
        return jsonify({"error": "Could not determine vendor. Please select one manually."}), 400

    # When user selects "Cisco" (asa) manually, check if file is actually FTD
    if vendor == "asa" and is_ftd_config(sample):
        vendor = "ftd"

    detected_hostname = extract_hostname(vendor, sample)

    is_valid, validation_msg = validate_vendor_format(sample, upload.filename, vendor)
    if not is_valid:
        os.remove(temp_path)
        return jsonify({"error": f"Wrong vendor selected ({VENDOR_DISPLAY.get(vendor, vendor)}): {validation_msg}"}), 400

    try:
        findings, parse, extra_data = run_vendor_audit(vendor, temp_path)

        # Compliance checks (license-gated; not applicable for AWS/Azure)
        license_warning = None
        if compliance and vendor not in ("aws", "azure"):
            licensed, _ = check_license()
            if not licensed:
                license_warning = (
                    "Compliance checks require a valid license. "
                    'Purchase one at <a href="https://shamrock13.gumroad.com/l/flintlock" '
                    'target="_blank" rel="noopener">shamrock13.gumroad.com/l/flintlock</a>. '
                    "Once purchased, enter your key using the Licensed/Unlicensed badge in the top-right corner."
                )
            else:
                raw = run_compliance_checks(vendor, compliance, parse, extra_data)
                findings += [_wrap_compliance(c) for c in raw]

        findings = _sort_findings(findings)
        summary  = _build_summary(findings)

        report_filename = None
        if generate_pdf:
            report_name = f"flintlock_report_{uuid.uuid4().hex[:8]}.pdf"
            report_path = os.path.join(REPORTS_FOLDER, report_name)
            generate_report(_findings_to_strings(findings), upload.filename, vendor, compliance, output_path=report_path, summary=summary)
            report_filename = report_name

        # Optional archive save (store plain strings)
        archive_id = None
        if archive_it:
            archive_id, _ = save_audit(
                upload.filename, vendor, _findings_to_strings(findings), summary, config_path=temp_path, tag=tag
            )

        # Always log activity
        log_activity(
            ACTION_FILE_AUDIT, upload.filename, vendor=vendor, success=True,
            details={"total": summary.get("total", 0), "high": summary.get("high", 0),
                     "archived": archive_id is not None},
        )

        return jsonify({
            "findings":           _findings_to_strings(findings),
            "enriched_findings":  findings,
            "summary":            summary,
            "report":             report_filename,
            "license_warning":    license_warning,
            "detected_vendor":    vendor,
            "detected_hostname":  detected_hostname,
            "archive_id":         archive_id,
        })

    except Exception as e:
        log_activity(ACTION_FILE_AUDIT, upload.filename, vendor=vendor or "unknown",
                     success=False, error=str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ── Config diff ───────────────────────────────────────────────────────────────

@app.route("/diff", methods=["POST"])
def run_diff():
    if "config_a" not in request.files or "config_b" not in request.files:
        return jsonify({"error": "Two config files required (config_a and config_b)"}), 400
    if request.files["config_a"].filename == "" or request.files["config_b"].filename == "":
        return jsonify({"error": "Both config files must be selected"}), 400

    vendor = request.form.get("vendor", "auto").strip().lower()

    upload_a = request.files["config_a"]
    upload_b = request.files["config_b"]
    suffix_a = Path(upload_a.filename).suffix or ".txt"
    suffix_b = Path(upload_b.filename).suffix or ".txt"
    path_a = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}{suffix_a}")
    path_b = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}{suffix_b}")
    upload_a.save(path_a)
    upload_b.save(path_b)

    try:
        # Auto-detect from the first file if needed
        if vendor == "auto":
            with open(path_a, "r", errors="ignore") as f:
                sample = f.read(16384)
            vendor = detect_vendor(sample, upload_a.filename) or ""

        if vendor not in ALL_VENDORS:
            return jsonify({"error": "Could not determine vendor. Please select one manually."}), 400

        result = diff_configs(vendor, path_a, path_b)
        result["vendor"]     = vendor
        result["filename_a"] = upload_a.filename
        result["filename_b"] = upload_b.filename

        log_activity(ACTION_CONFIG_DIFF,
                     f"{upload_a.filename} → {upload_b.filename}",
                     vendor=vendor, success=True,
                     details={"added": len(result.get("added", [])),
                               "removed": len(result.get("removed", [])),
                               "unchanged": len(result.get("unchanged", []))})
        return jsonify(result)

    except Exception as e:
        log_activity(ACTION_CONFIG_DIFF,
                     f"{upload_a.filename} → {upload_b.filename}",
                     vendor=vendor or "unknown", success=False, error=str(e))
        return jsonify({"error": str(e)}), 500
    finally:
        for p in (path_a, path_b):
            if os.path.exists(p):
                os.remove(p)


# ── Live SSH connect ──────────────────────────────────────────────────────────

@app.route("/connect", methods=["POST"])
def live_connect():
    host       = request.form.get("host", "").strip()
    port       = request.form.get("port", "22").strip() or "22"
    username   = request.form.get("username", "").strip()
    password   = request.form.get("password", "")
    vendor     = request.form.get("vendor", "").strip().lower()
    compliance = request.form.get("compliance", "").strip().lower() or None
    tag        = request.form.get("tag", "").strip() or None

    if not host or not username or not vendor:
        return jsonify({"error": "host, username, and vendor are required"}), 400
    if vendor not in ("asa", "ftd", "fortinet", "paloalto"):
        return jsonify({"error": f"Live SSH not supported for vendor '{vendor}'. Supported: Cisco (ASA/FTD), Fortinet, Palo Alto Networks"}), 400

    label = f"{vendor.upper()}@{host}"

    try:
        from .ssh_connector import connect_and_pull
        temp_path, _ = connect_and_pull(
            vendor, host, port, username, password,
            timeout=30, upload_folder=UPLOAD_FOLDER
        )
    except Exception as e:
        # Log the failed attempt to activity log only — do NOT save to Audit History
        log_activity(ACTION_SSH_CONNECT, label, vendor=vendor, success=False, error=str(e),
                     details={"host": host, "port": port})
        return jsonify({"error": f"Connection failed: {e}"}), 500

    try:
        findings, parse, extra_data = run_vendor_audit(vendor, temp_path)

        if compliance:
            licensed, _ = check_license()
            if licensed:
                raw = run_compliance_checks(vendor, compliance, parse, extra_data)
                findings += [_wrap_compliance(c) for c in raw]

        findings = _sort_findings(findings)
        summary  = _build_summary(findings)

        # Save successful SSH audits to Audit History (store plain strings)
        archive_id, _ = save_audit(label, vendor, _findings_to_strings(findings), summary, config_path=temp_path, tag=tag)

        # Log successful activity
        log_activity(ACTION_SSH_CONNECT, label, vendor=vendor, success=True,
                     details={"host": host, "port": port,
                              "total": summary.get("total", 0), "high": summary.get("high", 0)})

        return jsonify({
            "findings":          _findings_to_strings(findings),
            "enriched_findings": findings,
            "summary":           summary,
            "detected_vendor":   vendor,
            "host":              host,
            "archive_id":        archive_id,
        })

    except Exception as e:
        log_activity(ACTION_SSH_CONNECT, label, vendor=vendor, success=False, error=str(e),
                     details={"host": host, "port": port})
        return jsonify({"error": str(e)}), 500
    finally:
        if "temp_path" in dir() and os.path.exists(temp_path):
            os.remove(temp_path)


# ── Archive API ───────────────────────────────────────────────────────────────

@app.route("/archive", methods=["GET"])
def archive_list():
    return jsonify(list_archive())


@app.route("/archive/save", methods=["POST"])
def archive_save():
    """Manually save the most recent audit result to the archive."""
    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "unknown")
    vendor   = data.get("vendor", "unknown")
    findings = data.get("findings", [])
    summary  = data.get("summary", {})
    tag      = data.get("tag")
    if not findings and not summary:
        return jsonify({"error": "No audit data to save"}), 400
    entry_id, entry = save_audit(filename, vendor, findings, summary, tag=tag)
    return jsonify({"id": entry_id, "entry": entry})


@app.route("/archive/<entry_id>", methods=["GET"])
def archive_get(entry_id):
    entry = get_entry(entry_id)
    if not entry:
        return jsonify({"error": "Not found"}), 404
    return jsonify(entry)


@app.route("/archive/<entry_id>", methods=["DELETE"])
def archive_delete(entry_id):
    deleted = delete_entry(entry_id)
    return jsonify({"deleted": deleted})


@app.route("/archive/trends", methods=["GET"])
def archive_trends():
    """Return time-series data for score/finding trends grouped by filename."""
    entries = list_archive()
    series = []
    for e in entries:
        s = e.get("summary", {})
        series.append({
            "id":        e["id"],
            "filename":  e["filename"],
            "vendor":    e.get("vendor", ""),
            "timestamp": e.get("timestamp", ""),
            "score":     s.get("score"),
            "high":      s.get("high", 0),
            "medium":    s.get("medium", 0),
            "total":     s.get("total", 0),
            "tag":       e.get("tag"),
            "version":   e.get("version", 1),
        })
    series.sort(key=lambda x: x["timestamp"])
    return jsonify(series)


@app.route("/archive/compare", methods=["POST"])
def archive_compare():
    data = request.get_json(silent=True) or {}
    id_a = data.get("id_a", "")
    id_b = data.get("id_b", "")
    if not id_a or not id_b:
        return jsonify({"error": "id_a and id_b are required"}), 400
    result, error = compare_entries(id_a, id_b)
    if error:
        return jsonify({"error": error}), 404
    return jsonify(result)


# ── Activity Log API ──────────────────────────────────────────────────────────

@app.route("/activity", methods=["GET"])
def activity_list():
    limit = int(request.args.get("limit", 200))
    return jsonify(list_activity(limit=limit))


@app.route("/activity/<event_id>", methods=["DELETE"])
def activity_delete(event_id):
    deleted = delete_activity_entry(event_id)
    return jsonify({"deleted": deleted})


@app.route("/activity/clear", methods=["POST"])
def activity_clear():
    count = clear_activity()
    return jsonify({"cleared": count})


# ── Bulk audit ────────────────────────────────────────────────────────────────

@app.route("/bulk_audit", methods=["POST"])
def bulk_audit():
    """Audit multiple config files in one request.

    Accepts: multipart/form-data with repeated field ``configs[]``.
    Optional shared fields: vendor (default auto), compliance, archive (1/0), tag.
    Returns: JSON list of per-file result objects.
    """
    uploads = request.files.getlist("configs[]")
    if not uploads or all(u.filename == "" for u in uploads):
        return jsonify({"error": "No config files uploaded"}), 400

    vendor_override = request.form.get("vendor", "auto").strip().lower()
    compliance      = request.form.get("compliance", "").strip().lower() or None
    archive_it      = request.form.get("archive") == "1"
    tag_prefix      = request.form.get("tag", "").strip() or None

    results = []

    for upload in uploads:
        if upload.filename == "":
            continue

        suffix    = Path(upload.filename).suffix or ".txt"
        temp_name = f"{uuid.uuid4()}{suffix}"
        temp_path = os.path.join(UPLOAD_FOLDER, temp_name)
        upload.save(temp_path)

        result_entry = {"filename": upload.filename, "status": "error", "findings": [],
                        "summary": {}, "vendor": None, "archive_id": None, "error": None}

        try:
            with open(temp_path, "r", errors="ignore") as f:
                sample = f.read(16384)

            vendor = vendor_override
            if vendor == "auto":
                vendor = detect_vendor(sample, upload.filename) or ""

            if vendor not in ALL_VENDORS:
                result_entry["error"] = "Could not determine vendor"
                results.append(result_entry)
                continue

            if vendor == "asa" and is_ftd_config(sample):
                vendor = "ftd"

            is_valid, validation_msg = validate_vendor_format(sample, upload.filename, vendor)
            if not is_valid:
                result_entry["error"] = validation_msg
                results.append(result_entry)
                continue

            findings, parse, extra_data = run_vendor_audit(vendor, temp_path)

            if compliance and vendor not in ("aws", "azure"):
                licensed, _ = check_license()
                if licensed:
                    raw = run_compliance_checks(vendor, compliance, parse, extra_data)
                    findings += [_wrap_compliance(c) for c in raw]

            findings = _sort_findings(findings)
            summary  = _build_summary(findings)

            archive_id = None
            if archive_it:
                tag = f"{tag_prefix}/{upload.filename}" if tag_prefix else upload.filename
                archive_id, _ = save_audit(
                    upload.filename, vendor, _findings_to_strings(findings),
                    summary, config_path=temp_path, tag=tag,
                )

            log_activity(
                ACTION_FILE_AUDIT, upload.filename, vendor=vendor, success=True,
                details={"bulk": True, "total": summary.get("total", 0),
                         "high": summary.get("high", 0), "archived": archive_id is not None},
            )

            result_entry.update({
                "status":          "ok",
                "vendor":          vendor,
                "findings":        _findings_to_strings(findings),
                "enriched_findings": findings,
                "summary":         summary,
                "archive_id":      archive_id,
            })

        except Exception as e:
            result_entry["error"] = str(e)
            log_activity(ACTION_FILE_AUDIT, upload.filename, vendor=vendor_override,
                         success=False, error=str(e), details={"bulk": True})
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        results.append(result_entry)

    return jsonify(results)


# ── Scheduled audits API ───────────────────────────────────────────────────────

@app.route("/schedules", methods=["GET"])
def schedules_list():
    return jsonify(list_schedules())


@app.route("/schedules", methods=["POST"])
def schedules_create():
    data = request.get_json(silent=True) or {}
    if not data.get("host") or not data.get("username"):
        return jsonify({"error": "host and username are required"}), 400
    schedule = create_schedule(data)
    reload_job(schedule["id"], get_schedule(schedule["id"], include_password=True))
    return jsonify(schedule), 201


@app.route("/schedules/<schedule_id>", methods=["GET"])
def schedules_get(schedule_id):
    schedule = get_schedule(schedule_id)
    if not schedule:
        return jsonify({"error": "Not found"}), 404
    return jsonify(schedule)


@app.route("/schedules/<schedule_id>", methods=["PUT"])
def schedules_update(schedule_id):
    data = request.get_json(silent=True) or {}
    schedule = update_schedule(schedule_id, data)
    if not schedule:
        return jsonify({"error": "Not found"}), 404
    reload_job(schedule_id, get_schedule(schedule_id, include_password=True))
    return jsonify(schedule)


@app.route("/schedules/<schedule_id>", methods=["DELETE"])
def schedules_delete(schedule_id):
    deleted = delete_schedule(schedule_id)
    if deleted:
        reload_job(schedule_id, None)  # removes the job from the scheduler
    return jsonify({"deleted": deleted})


@app.route("/schedules/<schedule_id>/run", methods=["POST"])
def schedules_run_now(schedule_id):
    """Trigger an immediate on-demand run of a scheduled audit."""
    schedule = get_schedule(schedule_id)
    if not schedule:
        return jsonify({"error": "Not found"}), 404
    scheduler_run_now(schedule_id)
    return jsonify({"queued": True, "id": schedule_id})


@app.route("/schedules/status", methods=["GET"])
def schedules_status():
    return jsonify({"scheduler_available": scheduler_available()})


# ── Reports / License ─────────────────────────────────────────────────────────

@app.route("/reports", methods=["GET"])
def reports_list():
    """List all saved PDF reports."""
    reports = []
    for fname in sorted(os.listdir(REPORTS_FOLDER), reverse=True):
        if fname.endswith(".pdf"):
            path = os.path.join(REPORTS_FOLDER, fname)
            reports.append({
                "filename": fname,
                "size":     os.path.getsize(path),
                "mtime":    os.path.getmtime(path),
            })
    return jsonify(reports)


@app.route("/reports/<filename>")
def download_report(filename):
    if ".." in filename or "/" in filename:
        return "Not found", 404
    path = os.path.join(REPORTS_FOLDER, filename)
    if not os.path.exists(path):
        return "Report not found", 404
    return send_file(path, as_attachment=True, download_name=filename)


@app.route("/reports/<filename>/view")
def view_report(filename):
    """Serve PDF inline for in-browser viewing."""
    if ".." in filename or "/" in filename:
        return "Not found", 404
    path = os.path.join(REPORTS_FOLDER, filename)
    if not os.path.exists(path):
        return "Report not found", 404
    return send_file(path, as_attachment=False, mimetype="application/pdf")


@app.route("/license/activate", methods=["POST"])
def license_activate():
    key = request.form.get("key", "").strip()
    success, message = activate_license(key)
    return jsonify({"success": success, "message": message})


@app.route("/license/deactivate", methods=["POST"])
def license_deactivate():
    success, message = deactivate_license()
    return jsonify({"success": success, "message": message})


@app.route("/license/status")
def license_status():
    licensed, info = check_license()
    return jsonify({"licensed": licensed, "info": info})


# ── Settings API ──────────────────────────────────────────────────────────────

@app.route("/settings", methods=["GET"])
def settings_get():
    return jsonify(get_settings())


@app.route("/settings", methods=["POST"])
def settings_save():
    data = request.get_json(silent=True) or {}
    saved = save_settings(data)
    return jsonify(saved)


def main():
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


# Start scheduler on import — covers both WSGI servers (gunicorn/uwsgi)
# and direct `flintlock-web` invocation. The scheduler has an internal
# guard that prevents double-start if this module is reloaded.
start_scheduler()
atexit.register(stop_scheduler)


if __name__ == "__main__":
    main()
