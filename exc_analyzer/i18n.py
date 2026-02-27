import json
from functools import lru_cache
from typing import Any, Dict, Iterable, Optional
from pathlib import Path
DEFAULT_LANGUAGE = "en"
_py_path = Path(__file__).resolve().parent
if _py_path.name == "__pycache__":
    _py_path = _py_path.parent
_LOCALE_ROOT = _py_path / "locale"
_active_language = DEFAULT_LANGUAGE
def _normalize(code: Optional[str]) -> str:
    if not code:
        return DEFAULT_LANGUAGE
    token = code.strip().lower()
    if "." in token:
        token = token.split(".", 1)[0]
    if "_" in token:
        token = token.split("_", 1)[0]
    return token or DEFAULT_LANGUAGE
@lru_cache()
def available_languages() -> Iterable[str]:
    languages = set()
    try:
        for entry in _LOCALE_ROOT.iterdir():
            if not entry.is_dir():
                continue
            catalog = entry / "messages.json"
            if catalog.is_file():
                languages.add(entry.name.lower())
    except FileNotFoundError:
        return tuple([DEFAULT_LANGUAGE])
    languages.add(DEFAULT_LANGUAGE)
    return tuple(sorted(languages))
@lru_cache()
def _load_catalog(language: str) -> Dict[str, Any]:
    normalized = _normalize(language)
    catalog_path = _LOCALE_ROOT / normalized / "messages.json"
    try:
        with catalog_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
def _resolve_key(catalog: Dict[str, Any], key: str) -> Any:
    current: Any = catalog
    for part in key.split('.'):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current
def set_language(language: Optional[str]) -> bool:
    """Set the active language if available; returns True on success."""
    global _active_language
    normalized = _normalize(language)
    catalog_path = _LOCALE_ROOT / normalized / "messages.json"
    if normalized not in available_languages() and not catalog_path.is_file():
        _active_language = DEFAULT_LANGUAGE
        return False
    _active_language = normalized
    return True
def get_active_language() -> str:
    return _active_language
def reset_language_cache() -> None:
    _load_catalog.cache_clear()
    available_languages.cache_clear()
def _lookup(key: str, language: str) -> Any:
    catalog = _load_catalog(language)
    if not catalog:
        return None
    return _resolve_key(catalog, key)
def t(key: str, **kwargs: Any) -> Any:
    """Translate the dotted key using the active language with fallback."""
    value = _lookup(key, _active_language)
    if value is None and _active_language != DEFAULT_LANGUAGE:
        value = _lookup(key, DEFAULT_LANGUAGE)
    if value is None:
        value = key
    if isinstance(value, str) and kwargs:
        try:
            return value.format(**kwargs)
        except KeyError:
            return value
    return value
