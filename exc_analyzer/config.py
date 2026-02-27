#!/usr/bin/env python3
import os
import base64
import getpass
from exc_analyzer.constants import CONFIG_DIR
from exc_analyzer.i18n import t
from exc_analyzer.errors import ExcAnalyzerError
KEY_FILE = os.path.join(CONFIG_DIR, "build.sec")
KEYRING_SERVICE = "exc-analyzer"
KEYRING_USER = "github_token"
try:
    import keyring
    KEYRING_AVAILABLE = True
except Exception:
    KEYRING_AVAILABLE = False


def _ensure_secure_store_available() -> None:
    if not KEYRING_AVAILABLE:
        raise ExcAnalyzerError(t("commands.shared.keyring_required"))


def _migrate_legacy_key_file() -> None:
    """Migrate old local key file to OS credential store and remove file."""
    if not os.path.isfile(KEY_FILE):
        return
    try:
        with open(KEY_FILE, "r", encoding="utf-8") as f:
            encoded = f.read().strip()
        if encoded:
            decoded = base64.b64decode(encoded).decode("utf-8")
            keyring.set_password(KEYRING_SERVICE, KEYRING_USER, decoded)
    except Exception as e:
        from exc_analyzer.logging_utils import log
        log(f"Legacy key migration failed: {e}")
        return
    try:
        os.remove(KEY_FILE)
    except Exception as e:
        from exc_analyzer.logging_utils import log
        log(f"Failed to remove legacy key file: {e}")


def ensure_config_dir():
    if not os.path.exists(CONFIG_DIR):
        try:
            os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
            if os.name == 'nt':
                try:
                    import subprocess
                    current_user = os.environ.get("USERNAME") or getpass.getuser()
                    subprocess.run(['icacls', CONFIG_DIR, '/inheritance:r', '/grant:r', f'{current_user}:(OI)(CI)F'], 
                                   capture_output=True, check=False)
                except Exception as e:
                    from exc_analyzer.logging_utils import log
                    log(f"Windows ACL hardening failed: {e}")
            else:
                try:
                    os.chmod(CONFIG_DIR, 0o700)
                except Exception as e:
                    from exc_analyzer.logging_utils import log
                    log(f"Directory chmod failed: {e}")
        except Exception:
            os.makedirs(CONFIG_DIR, exist_ok=True)


def save_key(key: str, silent: bool = False):
    from exc_analyzer.print_utils import Print
    ensure_config_dir()
    _ensure_secure_store_available()
    keyring.set_password(KEYRING_SERVICE, KEYRING_USER, key)
    _migrate_legacy_key_file()
    if not silent:
        Print.info(t("commands.shared.config_saved_keyring"))
        from exc_analyzer.print_utils import safe_print
        safe_print("")


def load_key():
    if not KEYRING_AVAILABLE:
        return None
    try:
        _migrate_legacy_key_file()
        val = keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
        if val:
            return val
    except Exception as e:
        from exc_analyzer.logging_utils import log
        log(f"Key load from keyring failed: {e}")
        return None


def delete_key():
    _ensure_secure_store_available()
    removed = False
    try:
        existing = keyring.get_password(KEYRING_SERVICE, KEYRING_USER)
        if existing:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_USER)
            removed = True
    except Exception as e:
        from exc_analyzer.logging_utils import log
        log(f"Key deletion from keyring failed: {e}")
    if os.path.isfile(KEY_FILE):
        try:
            os.remove(KEY_FILE)
            removed = True
        except Exception:
            try:
                with open(KEY_FILE, 'w', encoding='utf-8') as f:
                    f.write('')
                os.remove(KEY_FILE)
                removed = True
            except Exception as e:
                from exc_analyzer.logging_utils import log
                log(f"Legacy key file cleanup failed: {e}")
    return removed


def secure_store_available() -> bool:
    return KEYRING_AVAILABLE


def validate_key(key):
    pass
