import json
import os
from typing import Any, Dict

from exc_analyzer.constants import CONFIG_DIR
from exc_analyzer.config import ensure_config_dir

SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")
DEFAULT_SETTINGS: Dict[str, Any] = {
    "language": "en"
}


def _read_settings_file() -> Dict[str, Any]:
    ensure_config_dir()
    if not os.path.isfile(SETTINGS_FILE):
        return DEFAULT_SETTINGS.copy()
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            if isinstance(data, dict):
                merged = DEFAULT_SETTINGS.copy()
                merged.update(data)
                return merged
    except (json.JSONDecodeError, OSError):
        pass
    return DEFAULT_SETTINGS.copy()


def _write_settings_file(settings: Dict[str, Any]) -> None:
    ensure_config_dir()
    payload = DEFAULT_SETTINGS.copy()
    payload.update(settings)
    with open(SETTINGS_FILE, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def load_settings() -> Dict[str, Any]:
    """Return a copy of persisted CLI settings."""
    return _read_settings_file()


def save_settings(settings: Dict[str, Any]) -> None:
    """Persist the provided settings dictionary."""
    _write_settings_file(settings)


def get_language_preference() -> str:
    """Fetch the saved language preference (defaults to English)."""
    return str(load_settings().get("language", DEFAULT_SETTINGS["language"]))


def set_language_preference(language: str) -> None:
    """Persist the selected language preference."""
    settings = load_settings()
    settings["language"] = language
    save_settings(settings)
