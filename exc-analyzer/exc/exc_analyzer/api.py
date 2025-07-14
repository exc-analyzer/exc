import os
import requests
import time
import sys
import exc_analyzer
from datetime import datetime
from packaging.version import Version
from exc_analyzer.print_utils import Print
from exc_analyzer.config import load_key
from exc_analyzer import __version__ as local_version


def get_version_from_pyproject():
    try:
        init_path = os.path.join(os.path.dirname(__file__), "__init__.py")
        with open(init_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    delim = '"' if '"' in line else "'"
                    version = line.split(delim)[1]
                    return version
    except Exception:
        pass
    return None


def get_version_from_pypi():
    try:
        resp = requests.get("https://pypi.org/pypi/exc-analyzer/json", timeout=5)
        if resp.status_code == 200:
            return resp.json()["info"]["version"]
        else:
            Print.warn(f"PyPI responded with status code {resp.status_code}.")
    except Exception as e:
        Print.warn(f"Could not fetch version info from PyPI: {e}")
    return None


def notify_new_version():
    local_version = None
    try:
        # Öncelikle exc_analyzer modülünden al
        local_version = exc_analyzer.__version__
    except Exception:
        # Modül içinde yoksa, init.py dosyasından sürümü oku
        local_version = get_version_from_pyproject()

    if local_version is None:
        Print.warn("Local version info not found.")
        return

    latest_version = get_version_from_pypi()
    if latest_version is None:
        return

    try:
        local_v = Version(local_version)
        latest_v = Version(latest_version)
        if local_v < latest_v:
            print("")
            Print.info(f"Update available: {latest_version}")
            Print.action("Use: pip install -U exc-analyzer")
    except Exception as e:
        Print.warn(f"Version comparison failed: {e}")

# ---------------------
# API Request Functions
# ---------------------

def api_get(url, headers, params=None):
    from exc_analyzer.logging_utils import log
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=12)

        if resp.status_code == 403:
            reset = resp.headers.get('X-RateLimit-Reset')
            if reset:
                reset_time = int(reset)
                now = int(time.time())
                wait_sec = max(0, reset_time - now)
                wait_min = wait_sec // 60
                readable_time = datetime.utcfromtimestamp(reset_time).strftime('%Y-%m-%d %H:%M:%S UTC')
                Print.warn("GitHub API rate limit reached.")
                Print.info(f"Please wait {wait_min} minutes {wait_sec % 60} seconds (Reset time: {readable_time}) before retrying.")
            else:
                Print.warn("GitHub API rate limit exceeded. Please try again later."),
                print("")
            log("API rate limit exceeded.")
            sys.exit(1)

        resp.raise_for_status()
        return resp.json(), resp.headers

    except requests.HTTPError as e:
        status = getattr(e.response, 'status_code', '?')

        if status == 404:
            Print.error("The requested user, repository, or resource was not found.")
            Print.info("Please check the username or repository name for typos or existence.")
            print("")
        elif status == 403:
            Print.error("Access denied or rate limit exceeded.")
            Print.info("You might not have permission to access this resource or have hit the API rate limit.")
            print("")
        elif status == 401:
            Print.error("Authentication failed.")
            Print.info("Please verify your API token or authentication credentials.")
            print("")
        elif 500 <= status < 600:
            Print.error(f"Server error occurred (HTTP {status}). Please try again later.")
            print("")
        else:
            Print.error(f"Failed to receive a valid response from the server. (HTTP {status})")
            print("")

        log(f"HTTP error: {e}")
        sys.exit(1)


def get_auth_header():
    key = load_key()
    if not key:
        print("")
        Print.error("API key is missing.")
        Print.info("Use: exc key")
        print("")
        sys.exit(1)
    return {
        "Authorization": f"token {key}",
        "Accept": "application/vnd.github.v3+json"
    }

def get_all_pages(url, headers, params=None):
    results = []
    page = 1
    while True:
        if params is None:
            params = {}
        params.update({'per_page': 100, 'page': page})
        data, resp_headers = api_get(url, headers, params)
        if not isinstance(data, list):
            return data
        results.extend(data)
        if 'Link' in resp_headers:
            if 'rel="next"' not in resp_headers['Link']:
                break
        else:
            break
        page += 1
        time.sleep(0.15)
    return results
