"""Settings blueprint — /settings/*, /license/*."""

import secrets
import smtplib
import ssl
from email.mime.text import MIMEText

from flask import Blueprint, jsonify, request

from cashel.license import (
    check_license,
    activate_license,
    deactivate_license,
    DEMO_MODE,
)
from cashel.settings import get_settings, save_settings, save_api_key
from cashel.syslog_handler import configure_syslog

settings_bp = Blueprint("settings_bp", __name__)


@settings_bp.route("/license/activate", methods=["POST"])
def license_activate():
    key = request.form.get("key", "").strip()
    success, message = activate_license(key)
    return jsonify({"success": success, "message": message})


@settings_bp.route("/license/deactivate", methods=["POST"])
def license_deactivate():
    success, message = deactivate_license()
    return jsonify({"success": success, "message": message})


@settings_bp.route("/license/status")
def license_status():
    licensed, info = check_license()
    return jsonify({"licensed": licensed, "info": info})


@settings_bp.route("/settings", methods=["GET"])
def settings_get():
    s = get_settings()
    # Never expose the plaintext API key over the wire — return masked hint only
    raw_key = s.pop("api_key", "")
    s["api_key_set"] = bool(raw_key)
    s["api_key_hint"] = (
        ("csh_…" + raw_key[-4:]) if len(raw_key) >= 4 else ("set" if raw_key else "")
    )
    return jsonify(s)


@settings_bp.route("/settings", methods=["POST"])
def settings_save():
    if DEMO_MODE:
        return jsonify({"error": "Settings cannot be saved in demo mode."}), 403
    data = request.get_json(silent=True) or {}
    saved = save_settings(data)
    # Reconfigure syslog immediately when settings are changed.
    configure_syslog(saved)
    saved.pop("api_key", None)
    return jsonify(saved)


@settings_bp.route("/settings/generate-api-key", methods=["POST"])
def settings_generate_api_key():
    """Generate a new random API key, store it encrypted, and return it once in plaintext.
    The caller must copy and store the key immediately — it cannot be retrieved again.
    """
    new_key = "csh_" + secrets.token_urlsafe(32)
    save_api_key(new_key)
    hint = ("csh_…" + new_key[-4:]) if len(new_key) >= 4 else ""
    return jsonify({"ok": True, "api_key": new_key, "api_key_hint": hint})


@settings_bp.route("/settings/test-smtp", methods=["POST"])
def settings_test_smtp():
    """Attempt a live SMTP connection and send a test email.

    Accepts the same SMTP fields as /settings POST so the user can test
    before saving.  Returns {ok: bool, message: str}.
    """
    if DEMO_MODE:
        return jsonify({"ok": False, "message": "SMTP is disabled in demo mode."}), 403

    data = request.get_json(silent=True) or {}
    smtp_host = (data.get("smtp_host") or "").strip()
    smtp_port = int(data.get("smtp_port") or 587)
    smtp_user = (data.get("smtp_user") or "").strip()
    smtp_password = data.get("smtp_password") or ""
    smtp_from = (data.get("smtp_from") or smtp_user or "").strip()
    smtp_tls = bool(data.get("smtp_tls", True))
    to_address = (data.get("to_address") or smtp_from or smtp_user or "").strip()

    if not smtp_host:
        return jsonify({"ok": False, "message": "SMTP host is required."}), 400
    if not to_address:
        return jsonify(
            {
                "ok": False,
                "message": "Could not determine a recipient address — set smtp_from or smtp_user.",
            }
        ), 400

    msg = MIMEText(
        "This is a test message from Cashel.\n\n"
        "If you received this, your SMTP settings are configured correctly.",
        "plain",
        "utf-8",
    )
    msg["Subject"] = "[Cashel] SMTP test"
    msg["From"] = smtp_from or to_address
    msg["To"] = to_address

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            if smtp_tls:
                server.starttls(context=context)
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from or to_address, [to_address], msg.as_string())
        return jsonify(
            {"ok": True, "message": f"Test email sent successfully to {to_address}."}
        )
    except smtplib.SMTPAuthenticationError:
        return jsonify(
            {
                "ok": False,
                "message": "Authentication failed — check username and password.",
            }
        )
    except smtplib.SMTPConnectError as exc:
        return jsonify(
            {
                "ok": False,
                "message": f"Could not connect to {smtp_host}:{smtp_port} — {exc}",
            }
        )
    except smtplib.SMTPException as exc:
        return jsonify({"ok": False, "message": f"SMTP error: {exc}"})
    except OSError as exc:
        return jsonify({"ok": False, "message": f"Connection error: {exc}"})
