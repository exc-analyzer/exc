"""High-performance async GitHub API client with connection pooling."""
import aiohttp
import asyncio
import time
import json
from typing import Optional, Dict, Any, List, Tuple
from exc_analyzer.print_utils import Print
from exc_analyzer.config import load_key
from exc_analyzer.errors import ExcAnalyzerError
from exc_analyzer.i18n import t
MAX_CONCURRENT_REQUESTS = 10
RATE_LIMIT_THRESHOLD = 100
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
                    async with self.session.request(
                        method, url, timeout=aiohttp.ClientTimeout(total=30), **kwargs
                    ) as resp:
                        self.remaining_quota = int(resp.headers.get("X-RateLimit-Remaining", 0))
                        self.reset_time = int(resp.headers.get("X-RateLimit-Reset", 0))
                        if resp.status == 403 and self.remaining_quota == 0:
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
        data, status = await self._request(
            "POST",
            "https://api.github.com/graphql",
            headers=self.graphql_headers,
            json=query_body
        )
        if status not in (200, 201):
            raise ExcAnalyzerError(f"GraphQL error: HTTP {status}")
        if isinstance(data, dict):
            if "errors" in data:
                errors = data.get("errors", [])
                error_msg = errors[0].get("message", "Unknown error") if errors else "Unknown error"
                raise ExcAnalyzerError(f"GraphQL error: {error_msg}")
        return data.get("data", {})
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
        """Fetch paginated results with concurrent page fetching."""
        first_page, status = await self._request(
            "GET", url, headers=self.headers, params={"per_page": per_page, "page": 1}
        )
        if status != 200:
            return []
        if not isinstance(first_page, list):
            return [first_page] if first_page else []
        results = list(first_page)
        page_tasks = []
        for page in range(2, (max_pages or 100) + 1):
            if len(page_tasks) >= 5:
                done, pending = await asyncio.wait(page_tasks, return_when=asyncio.FIRST_COMPLETED)
                page_tasks = list(pending)
                for task in done:
                    page_data = await task
                    if page_data and isinstance(page_data, list):
                        results.extend(page_data)
                    else:
                        return results  
            task = asyncio.create_task(
                self._fetch_page(url, per_page, page)
            )
            page_tasks.append(task)
        for task in page_tasks:
            page_data = await task
            if page_data and isinstance(page_data, list) and len(page_data) > 0:
                results.extend(page_data)
            else:
                break
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
