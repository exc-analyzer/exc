from types import SimpleNamespace
import pytest
from exc_analyzer import api
def test_safe_get_uses_cache(monkeypatch):
    api.clear_response_cache()
    call_count = {"value": 0}
    class FakeResponse:
        status_code = 200
        headers = {}
        @staticmethod
        def iter_content(_chunk_size):
            yield b"{}"
        def close(self):
            pass
    def fake_requests_get(*args, **kwargs):
        call_count["value"] += 1
        return FakeResponse()
    monkeypatch.setattr(api, "requests", SimpleNamespace(get=fake_requests_get))
    first = api.safe_get("https://api.github.com/test", headers={}, cacheable=True)
    second = api.safe_get("https://api.github.com/test", headers={}, cacheable=True)
    assert call_count["value"] == 1
    assert first == second
def test_api_get_retries_on_rate_limit(monkeypatch):
    api.clear_response_cache()
    calls = {"value": 0}
    def fake_safe_get(url, headers=None, params=None, timeout=10, max_bytes=2_000_000, cacheable=True):
        calls["value"] += 1
        if calls["value"] == 1:
            return ("{}", {"Retry-After": "1", "X-RateLimit-Remaining": "0"}, 403)
        return ("{\"ok\": true}", {}, 200)
    sleeps = []
    monkeypatch.setattr(api, "safe_get", fake_safe_get)
    monkeypatch.setattr(api.time, "sleep", lambda seconds: sleeps.append(seconds))
    data, _ = api.api_get("https://api.github.com/test", headers={}, cacheable=False)
    assert calls["value"] == 2
    assert sleeps == [1]
    assert data == {"ok": True}


def test_get_auth_header_exits_when_secure_store_unavailable(monkeypatch):
    monkeypatch.setattr(api, "secure_store_available", lambda: False)

    with pytest.raises(SystemExit) as exc:
        api.get_auth_header()

    assert exc.value.code == 1
