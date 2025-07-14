#!/usr/bin/env python3
import os
import requests
import time
import base64
from datetime import datetime, timedelta, timezone
from packaging.version import Version
from urllib.parse import quote
from exc_analyzer.print_utils import Print

# ---------------------
# Configuration Constants
# ---------------------

HOME_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME_DIR, ".exc")
KEY_FILE = os.path.join(CONFIG_DIR, "build.sec")

def ensure_config_dir():
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR, mode=0o700)

# ---------------------
#  API Key Management 
# [save_key, load_key, delete_key, validate_key]
# ---------------------

def save_key(key: str):
    from exc_analyzer.print_utils import Print
    ensure_config_dir()
    encoded = base64.b64encode(key.encode('utf-8')).decode('utf-8')
    with open(KEY_FILE, "w") as f:
        f.write(encoded)
    os.chmod(KEY_FILE, 0o600)
    Print.info("API key has been securely saved locally.")
    print("")

def load_key():
    if not os.path.isfile(KEY_FILE):
        return None
    try:
        with open(KEY_FILE, "r") as f:
            encoded = f.read()
            key = base64.b64decode(encoded).decode('utf-8')
            return key
    except Exception:
        return None

def delete_key():
    from exc_analyzer.print_utils import Print
    if os.path.isfile(KEY_FILE):
        os.remove(KEY_FILE)
        print("")
        Print.info("API key deleted.")
        print("")
    else:
        print("")
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
