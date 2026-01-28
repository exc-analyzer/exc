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
from exc_analyzer.utils import mask_sensitive
from typing import Optional, Tuple
import sys
import json
from exc_analyzer.constants import CLIENT_ID, DEVICE_CODE_URL, ACCESS_TOKEN_URL, AUTH_SCOPES
DEFAULT_TIMEOUT = 10
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
            resp.close()
            raise ValueError("Content too large")
        chunks.append(chunk)
    content = b"".join(chunks)
    try:
        text = content.decode('utf-8', errors='ignore')
    except Exception:
        text = content.decode(errors='ignore')
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
    except Exception as e:
        from exc_analyzer.logging_utils import log
        log(f"Failed to read version from __init__.py: {e}")
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
            local_version = exc_analyzer.__version__
        except Exception:
            local_version = get_version_from_pyproject()
        if local_version is None:
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
            pass
    t = threading.Thread(target=_check, daemon=True)
    t.start()
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
                from exc_analyzer.i18n import t
                Print.warn(t("commands.shared.server_error_retry", attempt=attempt, max=MAX_API_RETRIES, wait=wait))
                time.sleep(wait)
                continue
            status = getattr(e.response, 'status_code', '?')
            log(f"HTTP error: {e}")
            Print.error(f"Failed to communicate with GitHub (HTTP {status}).")
            raise ExcAnalyzerError(f"HTTP error: {status}")
        from exc_analyzer.i18n import t
        if status == 403:
            wait_seconds = _extract_rate_limit_wait(resp_headers)
            if wait_seconds is not None and wait_seconds <= MAX_RATE_LIMIT_WAIT:
                Print.warn(t("commands.shared.rate_limit_reached"))
                Print.info(t("commands.shared.rate_limit_retry", wait=wait_seconds))
                time.sleep(max(1, wait_seconds))
                continue
            if resp_headers.get('X-RateLimit-Remaining') == '0':
                reset = resp_headers.get('X-RateLimit-Reset')
                if reset:
                    try:
                        readable_time = datetime.utcfromtimestamp(int(reset)).strftime('%Y-%m-%d %H:%M:%S UTC')
                        Print.info(t("commands.shared.rate_limit_resets", time=readable_time))
                    except Exception:
                        pass
            Print.warn(t("commands.shared.rate_limit_exceeded"))
            log("API rate limit exceeded.")
            raise ExcAnalyzerError("API rate limit exceeded")
        if status is not None and status >= 400:
            if status == 404:
                Print.error(t("commands.shared.resource_not_found"))
                Print.info(t("commands.shared.resource_check_typo"))
                print("")
            elif status == 401:
                Print.error(t("commands.shared.auth_failed"))
                Print.info(t("commands.shared.auth_check_creds"))
                print("")
            elif 500 <= status < 600:
                Print.error(t("commands.shared.server_error_http", status=status))
                print("")
            else:
                Print.error(t("commands.shared.invalid_response", status=status))
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
        from exc_analyzer.i18n import t
        print("")
        Print.error(t("commands.shared.api_key_missing"))
        Print.info(t("commands.shared.use_key_cmd"))
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
def fetch_github_user(key):
    """Fetch GitHub user information to validate key."""
    from exc_analyzer.i18n import t
    headers = {
        "Authorization": f"token {key}",
        "Accept": "application/vnd.github.v3+json"
    }
    try:
        response = requests.get("https://api.github.com/user", headers=headers, timeout=8)
        if response.status_code == 200:
            return response.json().get("login")
    except requests.RequestException as e:
        Print.error(t("commands.shared.key_validation_error", error=e))
    return None
def exchange_device_code():
    """Request a device code from GitHub."""
    headers = {"Accept": "application/json"}
    data = {"client_id": CLIENT_ID, "scope": AUTH_SCOPES}
    try:
        resp = requests.post(DEVICE_CODE_URL, headers=headers, data=data, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        from exc_analyzer.logging_utils import log
        log(f"Device code exchange failed: {e}")
        return None
def poll_for_token(device_code: str, interval: int):
    """Poll GitHub for the access token."""
    from exc_analyzer.i18n import t
    max_duration = 900
    start_time = time.time()
    expires_at = start_time + max_duration
    headers = {"Accept": "application/json"}
    data = {
        "client_id": CLIENT_ID, 
        "device_code": device_code,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
    }
    while time.time() < expires_at:
        try:
            resp = requests.post(ACCESS_TOKEN_URL, headers=headers, data=data, timeout=10)
            if resp.status_code == 200:
                result = resp.json()
                if "access_token" in result:
                    return result["access_token"]
                error = result.get("error")
                if error == "authorization_pending":
                    pass
                elif error == "slow_down":
                    interval += 5
                elif error == "expired_token":
                    Print.error(t("commands.login.token_expired"))
                    return None
                elif error == "access_denied":
                    Print.error(t("commands.login.access_denied"))
                    return None
                else:
                    Print.warn(f"GitHub Error: {error}")
                    return None
            else:
                Print.warn(f"Polling HTTP Error: {resp.status_code}")
        except Exception as e:
            pass
        time.sleep(interval)
    Print.error(t("commands.login.timeout"))
    return None
