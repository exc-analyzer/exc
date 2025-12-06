#!/usr/bin/env python3
import os
import requests
import time
import base64
from datetime import datetime, timedelta, timezone
from packaging.version import Version
from urllib.parse import quote
from exc_analyzer.print_utils import Print
from exc_analyzer.constants import CONFIG_DIR

# KEY_FILE inside centralized CONFIG_DIR
KEY_FILE = os.path.join(CONFIG_DIR, "build.sec")

# Optional keyring: prefer OS credential store when available
try:
    import keyring
    KEYRING_AVAILABLE = True
except Exception:
    KEYRING_AVAILABLE = False

def ensure_config_dir():
    if not os.path.exists(CONFIG_DIR):
        # create with restrictive permissions where possible
        try:
            os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
            try:
                os.chmod(CONFIG_DIR, 0o700)
            except Exception:
                pass
        except Exception:
            # fallback to simple make dirs
            os.makedirs(CONFIG_DIR, exist_ok=True)

# ---------------------
#  API Key Management 
# [save_key, load_key, delete_key, validate_key]
# ---------------------

def save_key(key: str):
    from exc_analyzer.print_utils import Print
    ensure_config_dir()
    # Prefer OS credential store if available
    if KEYRING_AVAILABLE:
        try:
            keyring.set_password("exc-analyzer", "github_token", key)
            Print.info("API key saved to OS credential store.")
            print("")
            return
        except Exception:
            # Fall back to file storage
            pass

    encoded = base64.b64encode(key.encode('utf-8')).decode('utf-8')
    # Atomic write with explicit mode where possible
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        # mode 0o600 ensures file perms on creation (Unix)
        fd = os.open(KEY_FILE, flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(encoded)
    except Exception:
        # fallback
        with open(KEY_FILE, "w", encoding="utf-8") as f:
            f.write(encoded)
        try:
            os.chmod(KEY_FILE, 0o600)
        except Exception:
            Print.warn("Could not set strict file permissions on this platform. Ensure the key file is protected.")

    Print.info("API key has been saved locally.")
    print("")

def load_key():
    # If keyring is available, try it first
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
    from exc_analyzer.print_utils import Print
    # Remove from keyring if present
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
                # Try to overwrite then remove as a last resort
                with open(KEY_FILE, 'w', encoding='utf-8') as f:
                    f.write('')
                os.remove(KEY_FILE)
                removed = True
            except Exception:
                pass

    print("")
    if removed:
        Print.info("API key deleted.")
    else:
        Print.warn("No saved API key found.")
    print("")

def fetch_github_user(key):
    headers = {
        "Authorization": f"token {key}",
        "Accept": "application/vnd.github.v3+json"
    }
    try:
        response = requests.get("https://api.github.com/user", headers=headers, timeout=8)
        if response.status_code == 200:
            return response.json().get("login")
    except requests.RequestException as e:
        Print.error(f"Key validation error: {e}")
    return None


def print_logo():
    logo = [
        "      Y88b   d88P ",
        "       Y88b d88P  ",
        "        Y88o88P   ",
        "         Y888P    ",
        "         d888b    ",
        "        d88888b   ",
        "       d88P Y88b  ",
        "      d88P   Y88b "
    ]
    print("")
    for line in logo:
        print(line)
        time.sleep(0.2)
    print("")


def validate_key(key):
    user = fetch_github_user(key)
    if user:
        print("")
        Print.success(f"Welcome {user}")
        print_logo()
        return True
    return False
