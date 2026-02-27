"""High-performance async GitHub API client with connection pooling."""
import aiohttp
import asyncio
import time
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from exc_analyzer.config import load_key
from exc_analyzer.errors import ExcAnalyzerError
from exc_analyzer.i18n import t
MAX_CONCURRENT_REQUESTS = 10
RATE_LIMIT_THRESHOLD = 100
CRITICAL_RATE_LIMIT_THRESHOLD = 5
GRAPHQL_CACHE_TTL_SECONDS = 20
MAX_PROACTIVE_WAIT_SECONDS = 30


class AsyncGitHubAPI:
    """High-performance async GitHub API client with rate limit handling."""
    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.graphql_headers = {
            "Authorization": f"token {token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github.graphql"
        }
        self.remaining_quota = None
        self.reset_time = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self._request_count = 0
        self._graphql_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self.graphql_remaining = None
        self.graphql_reset_at = None
        self.graphql_last_cost = None

    @staticmethod
    def _safe_int(value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _safe_unix_timestamp(value, default=0):
        if value is None:
            return default
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return default
            try:
                return int(float(text))
            except ValueError:
                try:
                    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    return int(parsed.timestamp())
                except ValueError:
                    return default
        return default

    @staticmethod
    def _graphql_cache_key(query_body: Dict[str, Any]) -> str:
        try:
            return json.dumps(query_body, sort_keys=True, separators=(",", ":"))
        except TypeError:
            return str(query_body)

    def _graphql_cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        cached = self._graphql_cache.get(key)
        if not cached:
            return None
        timestamp, payload = cached
        if time.time() - timestamp > GRAPHQL_CACHE_TTL_SECONDS:
            del self._graphql_cache[key]
            return None
        return payload

    def _graphql_cache_put(self, key: str, payload: Dict[str, Any]):
        self._graphql_cache[key] = (time.time(), payload)

    def _update_graphql_rate_signals(self, response_payload: Dict[str, Any]):
        if not isinstance(response_payload, dict):
            return
        extensions = response_payload.get("extensions", {})
        if not isinstance(extensions, dict):
            return
        cost = extensions.get("cost", {})
        if not isinstance(cost, dict):
            return
        self.graphql_last_cost = self._safe_int(cost.get("requestedQueryCost"), self.graphql_last_cost or 0)
        self.graphql_remaining = self._safe_int(cost.get("remaining"), self.graphql_remaining or 0)
        self.graphql_reset_at = self._safe_unix_timestamp(cost.get("resetAt"), self.graphql_reset_at or 0)

    @staticmethod
    def _seconds_until_reset(reset_at: Optional[int]) -> int:
        if not reset_at:
            return 0
        return max(0, int(reset_at) - int(time.time()))

    @staticmethod
    def _emit_verbose_rate_guard(kind: str, remaining: int, wait_time: float):
        try:
            from . import print_utils
            if not print_utils.VERBOSE:
                return
            print_utils.print_info(
                t(
                    "commands.shared.rate_guard_wait",
                    kind=kind,
                    remaining=remaining,
                    wait=f"{wait_time:.1f}",
                )
            )
        except Exception:
            return

    async def _apply_proactive_throttle(self):
        if self.remaining_quota is None:
            return
        if self.remaining_quota <= CRITICAL_RATE_LIMIT_THRESHOLD:
            wait_time = self._seconds_until_reset(self.reset_time)
            if wait_time > 0:
                effective_wait = min(wait_time + 1, MAX_PROACTIVE_WAIT_SECONDS)
                self._emit_verbose_rate_guard("REST", self.remaining_quota, effective_wait)
                await asyncio.sleep(effective_wait)
                return
            self._emit_verbose_rate_guard("REST", self.remaining_quota, 2.0)
            await asyncio.sleep(2.0)
            return
        if self.remaining_quota <= 10:
            self._emit_verbose_rate_guard("REST", self.remaining_quota, 1.0)
            await asyncio.sleep(1.0)
        elif self.remaining_quota <= RATE_LIMIT_THRESHOLD:
            self._emit_verbose_rate_guard("REST", self.remaining_quota, 0.25)
            await asyncio.sleep(0.25)

    async def _apply_graphql_proactive_throttle(self):
        if self.graphql_remaining is None:
            return
        if self.graphql_remaining <= CRITICAL_RATE_LIMIT_THRESHOLD:
            wait_time = self._seconds_until_reset(self.graphql_reset_at)
            if wait_time > 0:
                effective_wait = min(wait_time + 1, MAX_PROACTIVE_WAIT_SECONDS)
                self._emit_verbose_rate_guard("GraphQL", self.graphql_remaining, effective_wait)
                await asyncio.sleep(effective_wait)
                return
            self._emit_verbose_rate_guard("GraphQL", self.graphql_remaining, 2.0)
            await asyncio.sleep(2.0)
            return
        if self.graphql_last_cost and self.graphql_remaining <= (self.graphql_last_cost + 1):
            wait_time = self._seconds_until_reset(self.graphql_reset_at)
            if wait_time > 0:
                effective_wait = min(wait_time + 1, MAX_PROACTIVE_WAIT_SECONDS)
                self._emit_verbose_rate_guard("GraphQL", self.graphql_remaining, effective_wait)
                await asyncio.sleep(effective_wait)
                return
        if self.graphql_remaining <= 20:
            self._emit_verbose_rate_guard("GraphQL", self.graphql_remaining, 0.5)
            await asyncio.sleep(0.5)

    def _adaptive_page_window(self) -> int:
        if self.remaining_quota is None:
            return 5
        if self.remaining_quota <= 100:
            return 1
        if self.remaining_quota <= 300:
            return 2
        return 5

    async def _maybe_wait_for_rate_limit_error(self, error_message: str, attempt: int, max_retries: int) -> bool:
        message = (error_message or "").lower()
        if "rate limit" not in message and "abuse" not in message:
            return False
        if attempt >= max_retries - 1:
            return False
        wait_time = 2 ** attempt
        if self.reset_time:
            reset_wait = max(1, self.reset_time - int(time.time()))
            wait_time = min(max(wait_time, reset_wait), 60)
        await asyncio.sleep(wait_time)
        return True
    async def __aenter__(self):
        """Enter async context manager."""
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS, limit_per_host=5)
        self.session = aiohttp.ClientSession(connector=connector)
        return self
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context manager and close session."""
        if self.session:
            await self.session.close()
    async def _request(self, method: str, url: str, **kwargs) -> Tuple[Any, int]:
        """Execute HTTP request with rate limit handling and automatic retry."""
        if not self.session:
            raise ExcAnalyzerError("Session not initialized. Use 'async with' context manager.")
        async with self.semaphore:
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    await self._apply_proactive_throttle()
                    async with self.session.request(
                        method, url, timeout=aiohttp.ClientTimeout(total=30), **kwargs
                    ) as resp:
                        self.remaining_quota = self._safe_int(resp.headers.get("X-RateLimit-Remaining"), self.remaining_quota or 0)
                        self.reset_time = self._safe_int(resp.headers.get("X-RateLimit-Reset"), self.reset_time or 0)
                        if resp.status in (403, 429) and self.remaining_quota == 0:
                            wait_time = max(1, self.reset_time - int(time.time()))
                            if wait_time <= 60:
                                await asyncio.sleep(wait_time + 1)
                                continue
                            else:
                                raise ExcAnalyzerError(
                                    "Rate limit exceeded. Please try again later."
                                )
                        if resp.status >= 500:
                            if attempt < max_retries - 1:
                                await asyncio.sleep(2 ** attempt)
                                continue
                            raise ExcAnalyzerError(f"Server error: {resp.status}")
                        try:
                            data = await resp.json()
                        except (json.JSONDecodeError, aiohttp.ContentTypeError):
                            data = {} if resp.status >= 400 else await resp.text()
                        self._request_count += 1
                        return data, resp.status
                except asyncio.TimeoutError:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)
                        continue
                    raise ExcAnalyzerError("Request timeout")
                except aiohttp.ClientError as e:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(1)
                        continue
                    raise ExcAnalyzerError(f"Connection error: {str(e)}")
            raise ExcAnalyzerError("Max retries exceeded")
    async def graphql_query(self, query_body: Dict[str, Any]) -> Dict:
        """Execute GraphQL query with error handling."""
        cache_key = self._graphql_cache_key(query_body)
        cached_payload = self._graphql_cache_get(cache_key)
        if cached_payload is not None:
            return cached_payload
        max_retries = 3
        for attempt in range(max_retries):
            await self._apply_graphql_proactive_throttle()
            data, status = await self._request(
                "POST",
                "https://api.github.com/graphql",
                headers=self.graphql_headers,
                json=query_body
            )
            if status not in (200, 201):
                raise ExcAnalyzerError(f"GraphQL error: HTTP {status}")
            if isinstance(data, dict) and "errors" in data:
                errors = data.get("errors", [])
                error_msg = errors[0].get("message", "Unknown error") if errors else "Unknown error"
                if await self._maybe_wait_for_rate_limit_error(error_msg, attempt, max_retries):
                    continue
                raise ExcAnalyzerError(f"GraphQL error: {error_msg}")
            payload = data.get("data", {}) if isinstance(data, dict) else {}
            self._update_graphql_rate_signals(data if isinstance(data, dict) else {})
            if isinstance(payload, dict):
                self._graphql_cache_put(cache_key, payload)
            return payload
        raise ExcAnalyzerError("GraphQL error: retries exhausted")
    async def fetch_json(self, url: str, params: Optional[Dict] = None) -> Dict:
        """Fetch JSON from REST API endpoint."""
        data, status = await self._request("GET", url, headers=self.headers, params=params)
        if status == 404:
            raise ExcAnalyzerError("Resource not found")
        if status == 401:
            raise ExcAnalyzerError("Authentication failed")
        if status >= 400:
            raise ExcAnalyzerError(f"API error: {status}")
        return data if isinstance(data, dict) else {}
    async def fetch_multiple(self, urls: List[str]) -> List[Dict]:
        """Fetch multiple URLs concurrently."""
        tasks = [self.fetch_json(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]
    async def fetch_paginated(
        self, url: str, per_page: int = 100, max_pages: Optional[int] = None
    ) -> List[Dict]:
        """Fetch paginated results with adaptive concurrent page fetching."""
        first_page, status = await self._request(
            "GET", url, headers=self.headers, params={"per_page": per_page, "page": 1}
        )
        if status != 200:
            return []
        if not isinstance(first_page, list):
            return [first_page] if first_page else []
        results = list(first_page)
        if len(first_page) < per_page:
            return results
        max_page_count = max_pages or 100
        current_page = 2
        while current_page <= max_page_count:
            window = min(self._adaptive_page_window(), max_page_count - current_page + 1)
            tasks = [
                asyncio.create_task(self._fetch_page(url, per_page, page_number))
                for page_number in range(current_page, current_page + window)
            ]
            page_results = await asyncio.gather(*tasks)
            should_stop = False
            for page_data in page_results:
                if not page_data or not isinstance(page_data, list):
                    should_stop = True
                    break
                results.extend(page_data)
                if len(page_data) < per_page:
                    should_stop = True
                    break
            if should_stop:
                break
            current_page += window
        return results
    async def _fetch_page(self, url: str, per_page: int, page: int) -> Optional[List]:
        """Fetch a single page of results."""
        try:
            data, status = await self._request(
                "GET", url, headers=self.headers, params={"per_page": per_page, "page": page}
            )
            return data if isinstance(data, list) else None
        except Exception:
            return None
    def get_quota_info(self) -> str:
        """Get current rate limit quota information."""
        if self.remaining_quota is not None:
            return t("commands.shared.quota_remaining", count=self.remaining_quota)
        return t("commands.shared.quota_unavailable")
async def get_async_client(token: Optional[str] = None) -> AsyncGitHubAPI:
    """Get async GitHub API client."""
    if not token:
        token = load_key()
        if not token:
            raise ExcAnalyzerError(f"{t('commands.shared.api_key_missing')} {t('commands.shared.use_key_cmd')}")
    return AsyncGitHubAPI(token)
def create_async_context(token: Optional[str] = None):
    """Create async context manager for API client."""
    if not token:
        token = load_key()
        if not token:
            raise ExcAnalyzerError(f"{t('commands.shared.api_key_missing')} {t('commands.shared.use_key_cmd')}")
    return AsyncGitHubAPI(token)
