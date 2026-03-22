"""Global application settings — persisted as JSON.

SECURITY ROADMAP NOTES
━━━━━━━━━━━━━━━━━━━━━━
Phase 2 — API Key Authentication (planned):
  Keys to add: ``auth_enabled`` (bool), ``api_key_hash`` (bcrypt/scrypt hash of
  the admin key), ``session_lifetime_minutes`` (int).  The login page will POST
  the key, compare it against the hash, and issue a signed session cookie.
  All state-changing routes will require either the session or X-API-Key header.

Phase 3 — Fernet Encryption for Stored Credentials (planned):
  Keys to add: ``encryption_enabled`` (bool).  A Fernet key is generated on
  first start and stored in a separate file (``FLINTLOCK_KEY_FILE`` env var,
  default: ``~/.config/flintlock/secret.key``).  The ``password_enc`` field in
  schedule files and the ``smtp_password`` setting will be Fernet-encrypted
  instead of base64-encoded.  Migration code will re-encrypt existing files on
  startup when ``encryption_enabled`` is first set.

Phase 4 — CSRF Protection (planned):
  Requires Flask-WTF.  A ``WTF_CSRF_SECRET_KEY`` will be auto-generated and
  stored here; the frontend will embed CSRF tokens in all form submissions.
"""
import json
import os

SETTINGS_FILE = os.environ.get("SETTINGS_FILE", "/tmp/flintlock_settings/settings.json")

# Valid values for enumerated security settings.
VALID_SSH_KEY_POLICIES  = ("warn", "strict", "auto_add")
VALID_ERROR_DETAIL      = ("sanitized", "full")
VALID_SYSLOG_PROTOCOLS  = ("udp", "tcp")
VALID_SYSLOG_FACILITIES = (
    "kernel", "user", "daemon",
    "local0", "local1", "local2", "local3",
    "local4", "local5", "local6", "local7",
)

DEFAULTS: dict = {
    # ── General ───────────────────────────────────────────────────────────────
    "auto_pdf":           False,
    "auto_archive":       False,
    "default_compliance": "",

    # ── SMTP (scheduled-audit email alerts) ───────────────────────────────────
    "smtp_host":     "",
    "smtp_port":     587,
    "smtp_user":     "",
    "smtp_password": "",
    "smtp_from":     "",
    "smtp_tls":      True,

    # ── Security — SSH ────────────────────────────────────────────────────────
    # Controls how unknown SSH host keys are handled for Live Connect audits.
    # "warn"     → log a warning and proceed (default; balances usability + visibility)
    # "strict"   → reject connections to hosts not in known_hosts (most secure)
    # "auto_add" → silently accept any host key (insecure; lab use only)
    "ssh_host_key_policy": "warn",

    # ── Security — Webhooks ───────────────────────────────────────────────────
    # Comma-separated list of extra hostname suffixes allowed as webhook targets,
    # in addition to the built-in allowlist (hooks.slack.com, webhook.office.com,
    # discord.com).  Example: "webhooks.mycorp.com, hooks.internal.net"
    "webhook_allowlist": "",

    # ── Security — Error detail ───────────────────────────────────────────────
    # "sanitized" → return generic messages to the browser (production default)
    # "full"      → return raw exception text (development only)
    "error_detail": "sanitized",

    # ── Syslog ────────────────────────────────────────────────────────────────
    # Forward application events to a remote syslog server for SIEM integration.
    # Protocol: "udp" (RFC 3164, default) or "tcp" (reliable delivery).
    # Facility: LOCAL0–LOCAL7, DAEMON, USER.
    "syslog_enabled":  False,
    "syslog_host":     "localhost",
    "syslog_port":     514,
    "syslog_protocol": "udp",
    "syslog_facility": "local0",
}


def get_settings() -> dict:
    """Return current settings merged with defaults (so new keys always present)."""
    try:
        with open(SETTINGS_FILE) as f:
            data = json.load(f)
        return {**DEFAULTS, **{k: data[k] for k in DEFAULTS if k in data}}
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(DEFAULTS)


def save_settings(data: dict) -> dict:
    """Persist settings. Unknown keys are ignored. Returns the saved dict."""
    merged = {}
    for k, default in DEFAULTS.items():
        merged[k] = data.get(k, default)

    # Validate enumerated fields before persisting.
    if merged["ssh_host_key_policy"] not in VALID_SSH_KEY_POLICIES:
        merged["ssh_host_key_policy"] = "warn"
    if merged["error_detail"] not in VALID_ERROR_DETAIL:
        merged["error_detail"] = "sanitized"
    if merged["syslog_protocol"] not in VALID_SYSLOG_PROTOCOLS:
        merged["syslog_protocol"] = "udp"
    if merged["syslog_facility"] not in VALID_SYSLOG_FACILITIES:
        merged["syslog_facility"] = "local0"
    try:
        merged["syslog_port"] = int(merged["syslog_port"])
        if not 1 <= merged["syslog_port"] <= 65535:
            merged["syslog_port"] = 514
    except (TypeError, ValueError):
        merged["syslog_port"] = 514

    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(merged, f, indent=2)
    return merged
