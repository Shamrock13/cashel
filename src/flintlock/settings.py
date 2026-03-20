"""Global application settings — persisted as JSON."""
import json
import os

SETTINGS_FILE = os.environ.get("SETTINGS_FILE", "/tmp/flintlock_settings/settings.json")

DEFAULTS: dict = {
    "auto_pdf": False,
    "auto_archive": False,
    "default_compliance": "",
}


def get_settings() -> dict:
    """Return current settings merged with defaults (so new keys always present)."""
    try:
        with open(SETTINGS_FILE, "r") as f:
            data = json.load(f)
        return {**DEFAULTS, **{k: data[k] for k in DEFAULTS if k in data}}
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(DEFAULTS)


def save_settings(data: dict) -> dict:
    """Persist settings. Unknown keys are ignored. Returns the saved dict."""
    merged = {k: data.get(k, DEFAULTS[k]) for k in DEFAULTS}
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(merged, f, indent=2)
    return merged
