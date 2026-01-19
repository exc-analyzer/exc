#!/usr/bin/env python3
import os
import base64
from exc_analyzer.constants import CONFIG_DIR
from exc_analyzer.i18n import t
KEY_FILE = os.path.join(CONFIG_DIR, "build.sec")
try:
    import keyring
    KEYRING_AVAILABLE = True
except Exception:
    KEYRING_AVAILABLE = False
def ensure_config_dir():
    if not os.path.exists(CONFIG_DIR):
        try:
            os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
            if os.name == 'nt':
                try:
                    import subprocess
                    subprocess.run(['icacls', CONFIG_DIR, '/inheritance:r', '/grant:r', '%username%:(OI)(CI)F'], 
                                   capture_output=True, check=False)
                except Exception:
                    pass
            else:
                try:
                    os.chmod(CONFIG_DIR, 0o700)
                except Exception:
                    pass
        except Exception:
            os.makedirs(CONFIG_DIR, exist_ok=True)
def save_key(key: str, silent: bool = False):
    from exc_analyzer.print_utils import Print
    ensure_config_dir()
    if KEYRING_AVAILABLE:
        try:
            keyring.set_password("exc-analyzer", "github_token", key)
            if not silent:
                Print.info(t("commands.shared.config_saved_keyring"))
                from exc_analyzer.print_utils import safe_print
                safe_print("")
            return
        except Exception:
            pass
    encoded = base64.b64encode(key.encode('utf-8')).decode('utf-8')
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(KEY_FILE, flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(encoded)
    except Exception:
        with open(KEY_FILE, "w", encoding="utf-8") as f:
            f.write(encoded)
        try:
            os.chmod(KEY_FILE, 0o600)
        except Exception:
            Print.warn(t("commands.shared.config_perm_warning"))
    if not silent:
        Print.info(t("commands.shared.config_saved_local"))
        from exc_analyzer.print_utils import safe_print
        safe_print("")
def load_key():
    if KEYRING_AVAILABLE:
        try:
            val = keyring.get_password("exc-analyzer", "github_token")
            if val:
                return val
        except Exception:
            pass
    if not os.path.isfile(KEY_FILE):
        return None
    try:
        with open(KEY_FILE, "r", encoding="utf-8") as f:
            encoded = f.read()
            key = base64.b64decode(encoded).decode('utf-8')
            return key
    except Exception:
        return None
def delete_key():
    removed = False
    if KEYRING_AVAILABLE:
        try:
            existing = keyring.get_password("exc-analyzer", "github_token")
            if existing:
                keyring.delete_password("exc-analyzer", "github_token")
                removed = True
        except Exception:
            pass
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
            except Exception:
                pass
    return removed
def validate_key(key):
    pass
