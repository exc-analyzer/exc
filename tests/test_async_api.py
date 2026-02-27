import asyncio
import time

from exc_analyzer.async_api import AsyncGitHubAPI


def test_graphql_query_uses_short_ttl_cache(monkeypatch):
    client = AsyncGitHubAPI("token")
    calls = {"count": 0}

    async def fake_request(method, url, **kwargs):
        calls["count"] += 1
        return ({"data": {"viewer": {"login": "alice"}}}, 200)

    monkeypatch.setattr(client, "_request", fake_request)

    query = {"query": "query { viewer { login } }", "variables": {}}

    first = asyncio.run(client.graphql_query(query))
    second = asyncio.run(client.graphql_query(query))

    assert first == {"viewer": {"login": "alice"}}
    assert second == first
    assert calls["count"] == 1


def test_graphql_query_updates_rate_signals_from_extensions(monkeypatch):
    client = AsyncGitHubAPI("token")

    async def fake_request(method, url, **kwargs):
        return (
            {
                "data": {"viewer": {"login": "alice"}},
                "extensions": {
                    "cost": {
                        "requestedQueryCost": 3,
                        "remaining": 4997,
                        "resetAt": 1730000000,
                    }
                },
            },
            200,
        )

    monkeypatch.setattr(client, "_request", fake_request)

    result = asyncio.run(client.graphql_query({"query": "query { viewer { login } }", "variables": {}}))

    assert result == {"viewer": {"login": "alice"}}
    assert client.graphql_last_cost == 3
    assert client.graphql_remaining == 4997
    assert client.graphql_reset_at == 1730000000


def test_apply_proactive_throttle_waits_when_rest_quota_critical(monkeypatch):
    client = AsyncGitHubAPI("token")
    client.remaining_quota = 1
    client.reset_time = int(time.time()) + 120
    sleep_calls = []

    async def fake_sleep(seconds):
        sleep_calls.append(seconds)

    monkeypatch.setattr("exc_analyzer.async_api.asyncio.sleep", fake_sleep)

    asyncio.run(client._apply_proactive_throttle())

    assert sleep_calls == [30]


def test_graphql_query_waits_before_request_when_quota_critical(monkeypatch):
    client = AsyncGitHubAPI("token")
    client.graphql_remaining = 1
    client.graphql_reset_at = int(time.time()) + 2
    events = []

    async def fake_sleep(seconds):
        events.append(("sleep", seconds))

    async def fake_request(method, url, **kwargs):
        events.append(("request", method))
        return ({"data": {"viewer": {"login": "alice"}}}, 200)

    monkeypatch.setattr("exc_analyzer.async_api.asyncio.sleep", fake_sleep)
    monkeypatch.setattr(client, "_request", fake_request)

    result = asyncio.run(client.graphql_query({"query": "query { viewer { login } }", "variables": {}}))

    assert result == {"viewer": {"login": "alice"}}
    assert events[0][0] == "sleep"
    assert events[1][0] == "request"


def test_verbose_rate_guard_message_emitted(monkeypatch):
    client = AsyncGitHubAPI("token")
    client.remaining_quota = 2
    client.reset_time = int(time.time()) + 120
    messages = []

    async def fake_sleep(seconds):
        return None

    monkeypatch.setattr("exc_analyzer.async_api.asyncio.sleep", fake_sleep)
    monkeypatch.setattr("exc_analyzer.print_utils.VERBOSE", True)
    monkeypatch.setattr("exc_analyzer.print_utils.print_info", lambda msg: messages.append(msg))

    asyncio.run(client._apply_proactive_throttle())

    assert messages
    assert "remaining" in messages[0].lower()
