"""Schedule store — persists scheduled SSH audit jobs as individual JSON files.

Passwords are stored base64-encoded in the schedule file. This is obfuscation,
not encryption. Run Flintlock behind a firewall or reverse proxy with access
controls and restrict SCHEDULES_FOLDER permissions (chmod 600).
"""
import base64
import json
import os
import uuid
from datetime import datetime

SCHEDULES_FOLDER = os.environ.get("SCHEDULES_FOLDER", "/tmp/flintlock_schedules")

VALID_VENDORS    = ("asa", "ftd", "fortinet", "paloalto")
VALID_FREQS      = ("hourly", "daily", "weekly")
VALID_FRAMEWORKS = ("", "cis", "pci", "nist", "hipaa")


# ── Internal helpers ───────────────────────────────────────────────────────────

def _path(entry_id: str) -> str:
    return os.path.join(SCHEDULES_FOLDER, f"{entry_id}.json")


def _encode_password(password: str) -> str:
    return base64.b64encode(password.encode("utf-8")).decode("ascii")


def _decode_password(encoded: str) -> str:
    try:
        return base64.b64decode(encoded.encode("ascii")).decode("utf-8")
    except Exception:
        return ""


def _strip_password(schedule: dict) -> dict:
    """Return a copy of the schedule dict without the stored password."""
    s = {k: v for k, v in schedule.items() if k != "password_enc"}
    s["has_password"] = bool(schedule.get("password_enc"))
    return s


# ── Public CRUD ────────────────────────────────────────────────────────────────

def list_schedules(include_password: bool = False) -> list:
    os.makedirs(SCHEDULES_FOLDER, exist_ok=True)
    result = []
    for fname in sorted(os.listdir(SCHEDULES_FOLDER)):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(SCHEDULES_FOLDER, fname)) as f:
                data = json.load(f)
            result.append(data if include_password else _strip_password(data))
        except Exception:
            pass
    return result


def get_schedule(entry_id: str, include_password: bool = False) -> dict | None:
    try:
        with open(_path(entry_id)) as f:
            data = json.load(f)
        return data if include_password else _strip_password(data)
    except FileNotFoundError:
        return None


def create_schedule(data: dict) -> dict:
    os.makedirs(SCHEDULES_FOLDER, exist_ok=True)
    entry_id = uuid.uuid4().hex
    schedule = {
        "id":           entry_id,
        "name":         str(data.get("name", "Unnamed Schedule"))[:80],
        "vendor":       str(data.get("vendor", "asa")),
        "host":         str(data.get("host", "")),
        "port":         int(data.get("port", 22)),
        "username":     str(data.get("username", "")),
        "password_enc": _encode_password(str(data.get("password", ""))),
        "tag":          str(data.get("tag", ""))[:64],
        "compliance":   str(data.get("compliance", "")),
        "frequency":    str(data.get("frequency", "daily")),
        "hour":         int(data.get("hour", 2)),
        "minute":       int(data.get("minute", 0)),
        "day_of_week":  str(data.get("day_of_week", "mon")),
        "enabled":      bool(data.get("enabled", True)),
        "last_run":     None,
        "last_status":  None,
        "last_error":   None,
        "created_at":   datetime.utcnow().isoformat(),
    }
    with open(_path(entry_id), "w") as f:
        json.dump(schedule, f, indent=2)
    return _strip_password(schedule)


def update_schedule(entry_id: str, data: dict) -> dict | None:
    schedule = get_schedule(entry_id, include_password=True)
    if not schedule:
        return None
    for key in ("name", "vendor", "host", "tag", "compliance",
                "frequency", "day_of_week", "enabled"):
        if key in data:
            schedule[key] = data[key]
    for key in ("port", "hour", "minute"):
        if key in data:
            schedule[key] = int(data[key])
    if "enabled" in data:
        schedule["enabled"] = bool(data["enabled"])
    if data.get("password"):
        schedule["password_enc"] = _encode_password(str(data["password"]))
    with open(_path(entry_id), "w") as f:
        json.dump(schedule, f, indent=2)
    return _strip_password(schedule)


def delete_schedule(entry_id: str) -> bool:
    try:
        os.remove(_path(entry_id))
        return True
    except FileNotFoundError:
        return False


def record_run(entry_id: str, status: str, error: str | None = None):
    """Update last_run, last_status, last_error after a job executes."""
    schedule = get_schedule(entry_id, include_password=True)
    if not schedule:
        return
    schedule["last_run"]    = datetime.utcnow().isoformat()
    schedule["last_status"] = status
    schedule["last_error"]  = error
    with open(_path(entry_id), "w") as f:
        json.dump(schedule, f, indent=2)


def get_password(entry_id: str) -> str:
    schedule = get_schedule(entry_id, include_password=True)
    if not schedule:
        return ""
    return _decode_password(schedule.get("password_enc", ""))
