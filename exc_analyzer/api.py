import os
import requests
import time
import threading
import exc_analyzer
from datetime import datetime
from packaging.version import Version
from exc_analyzer.print_utils import Print
from exc_analyzer.config import load_key
from exc_analyzer import __version__ as local_version
from exc_analyzer.errors import ExcAnalyzerError
from typing import Optional, Tuple
import sys
import json


CACHE_TTL_SECONDS = 30
MAX_RATE_LIMIT_WAIT = 60
MAX_API_RETRIES = 3

_response_cache: dict = {}


def clear_response_cache():
    """Testing helper: resets the in-memory HTTP cache."""
    _response_cache.clear()


def _cache_key(url: str, params: Optional[dict]) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
    if not params:
        return (url, tuple())
    return (url, tuple(sorted((str(k), str(v)) for k, v in params.items())))


def _get_cached_response(key):
    entry = _response_cache.get(key)
    if not entry:
        return None
    timestamp, payload = entry
    if time.time() - timestamp > CACHE_TTL_SECONDS:
        del _response_cache[key]
        return None
    return payload


def _store_cached_response(key, payload):
    _response_cache[key] = (time.time(), payload)


def _extract_rate_limit_wait(headers: dict) -> Optional[int]:
    if not headers:
        return None
    retry_after = headers.get('Retry-After')
    if retry_after:
        try:
            return max(0, int(float(retry_after)))
        except ValueError:
            pass
    reset = headers.get('X-RateLimit-Reset')
    if reset:
        try:
            reset_time = int(reset)
            wait_seconds = max(0, reset_time - int(time.time()))
            return wait_seconds
        except ValueError:
            pass
    remaining = headers.get('X-RateLimit-Remaining')
    if remaining == '0':
        return 5
    return None


def mask_sensitive(text: str) -> str:
    """Mask known sensitive patterns before logging/displaying."""
    try:
        import re
        # GitHub token patterns
        text = re.sub(r"ghp_[A-Za-z0-9]{36}", "ghp_********************", text)
        # generic hex-like API keys (simple)
        text = re.sub(r"(?i)(aws_secret_access_key\s*[:=]\s*)([A-Za-z0-9/+=]{16,})", r"\1***", text)
        return text
    except Exception:
        return text


def safe_get(url: str, headers: Optional[dict] = None, params: Optional[dict] = None, timeout: int = 10, max_bytes: int = 2_000_000, cacheable: bool = False):
    """Fetch URL safely with timeout and max content size.

    Returns a tuple: (text, headers, status_code).
    Does not raise on 403 so callers can inspect rate-limit headers.
    Raises for network errors or for responses with status >=500.
    """
    cache_key = None
    if cacheable:
        cache_key = _cache_key(url, params)
        cached = _get_cached_response(cache_key)
        if cached:
            return cached

    resp = requests.get(url, headers=headers, params=params, stream=True, timeout=timeout)
    status = getattr(resp, 'status_code', None)
    resp_headers = getattr(resp, 'headers', {}) or {}

    total = 0
    chunks = []
    for chunk in resp.iter_content(8192):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            # consume/close connection then raise
            resp.close()
            raise ValueError("Content too large")
        chunks.append(chunk)

    content = b"".join(chunks)
    try:
        text = content.decode('utf-8', errors='ignore')
    except Exception:
        text = content.decode(errors='ignore')

    # if server error, raise to let caller handle retries
    if status is not None and 500 <= status < 600:
        raise requests.HTTPError(f"Server error: {status}")

    payload = (text, resp_headers, status)
    if cacheable and status is not None and status < 400:
        _store_cached_response(cache_key, payload)
    return payload


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
    def _check():
        local_version = None
        try:
            # Öncelikle exc_analyzer modülünden al
            local_version = exc_analyzer.__version__
        except Exception:
            # Modül içinde yoksa, init.py dosyasından sürümü oku
            local_version = get_version_from_pyproject()

        if local_version is None:
            # Silent: don't spam warnings during background check
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
        except Exception:
            # ignore background errors
            pass

    # Run in background so startup isn't delayed
    t = threading.Thread(target=_check, daemon=True)
    t.start()

# ---------------------
# API Request Functions
# ---------------------

def api_get(url, headers, params=None, cacheable=True):
    from exc_analyzer.logging_utils import log
    attempt = 0
    while attempt < MAX_API_RETRIES:
        attempt += 1
        try:
            text, resp_headers, status = safe_get(
                url,
                headers=headers,
                params=params,
                timeout=12,
                cacheable=cacheable,
            )
        except requests.HTTPError as e:
            if attempt < MAX_API_RETRIES:
                wait = min(MAX_RATE_LIMIT_WAIT, 2 ** attempt)
                Print.warn(f"Server error (attempt {attempt}/{MAX_API_RETRIES}). Retrying in {wait}s...")
                time.sleep(wait)
                continue

            status = getattr(e.response, 'status_code', '?')
            log(f"HTTP error: {e}")
            Print.error(f"Failed to communicate with GitHub (HTTP {status}).")
            raise ExcAnalyzerError(f"HTTP error: {status}")

        if status == 403:
            wait_seconds = _extract_rate_limit_wait(resp_headers)
            if wait_seconds is not None and wait_seconds <= MAX_RATE_LIMIT_WAIT:
                Print.warn("GitHub API rate limit reached.")
                Print.info(f"Retrying automatically in {wait_seconds} seconds...")
                time.sleep(max(1, wait_seconds))
                continue

            if resp_headers.get('X-RateLimit-Remaining') == '0':
                reset = resp_headers.get('X-RateLimit-Reset')
                if reset:
                    try:
                        readable_time = datetime.utcfromtimestamp(int(reset)).strftime('%Y-%m-%d %H:%M:%S UTC')
                        Print.info(f"Limit resets at {readable_time}.")
                    except Exception:
                        pass
            Print.warn("GitHub API rate limit exceeded. Please try again later.")
            log("API rate limit exceeded.")
            raise ExcAnalyzerError("API rate limit exceeded")

        if status is not None and status >= 400:
            if status == 404:
                Print.error("The requested user, repository, or resource was not found.")
                Print.info("Please check the username or repository name for typos or existence.")
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

            log(f"HTTP error: status={status} url={url}")
            raise ExcAnalyzerError(f"HTTP error: {status}")

        try:
            data = json.loads(text) if text else None
        except Exception as e:
            log(f"Failed to parse JSON response: {e}")
            raise ExcAnalyzerError("Invalid JSON received from API")

        return data, resp_headers

    raise ExcAnalyzerError("API request exceeded retry budget")


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
        data, resp_headers = api_get(url, headers, params, cacheable=False)
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
