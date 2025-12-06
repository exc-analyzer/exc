from types import SimpleNamespace

from exc_analyzer.commands import analysis


def test_cmd_analysis_outputs_summary(monkeypatch, capsys):
    repo_data = {
        "full_name": "exc/example",
        "description": "Example repository for tests",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "stargazers_count": 10,
        "forks_count": 2,
        "watchers_count": 5,
        "default_branch": "main",
        "license": {"name": "MIT"},
        "open_issues_count": 1,
    }
    languages = {"Python": 1000}
    commits = [
        {"author": {"login": "alice"}},
        {"author": {"login": "alice"}},
        {"author": {"login": "bob"}},
    ]
    contributors = [
        {"login": "alice", "contributions": 50},
        {"login": "bob", "contributions": 30},
    ]

    monkeypatch.setattr(analysis, "get_auth_header", lambda: {"Authorization": "token fake"})

    def fake_api_get(url, headers, params=None):
        if url.endswith("/languages"):
            return languages, {}
        return repo_data, {}

    monkeypatch.setattr(analysis, "api_get", fake_api_get)

    def fake_get_all_pages(url, headers, params=None):
        if "commits" in url:
            return commits
        if "contributors" in url:
            return contributors
        return []

    monkeypatch.setattr(analysis, "get_all_pages", fake_get_all_pages)

    class FakeResponse:
        status_code = 200
        headers = {}
        links = {}

        @staticmethod
        def json():
            return [{"id": 1}]

    monkeypatch.setattr(analysis.requests, "get", lambda url, headers=None: FakeResponse())

    args = SimpleNamespace(repo="exc/example")
    analysis.cmd_analysis(args)
    out = capsys.readouterr().out
    assert "Repository Information" in out
    assert "Languages" in out
    assert "Total Commits" in out
    assert "Top Contributors" in out
