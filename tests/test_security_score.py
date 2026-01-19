from types import SimpleNamespace
from exc_analyzer.commands import security_score
from exc_analyzer.i18n import set_language
def test_cmd_security_score_flags_risks(monkeypatch, capsys):
    set_language('en')
    repo_data = {
        "license": None,
        "has_issues": False,
        "has_wiki": False,
        "has_projects": False,
        "open_issues_count": 120,
        "default_branch": "main",
    }
    monkeypatch.setattr(security_score, "get_auth_header", lambda: {"Authorization": "token fake"})
    monkeypatch.setattr(security_score, "api_get", lambda url, headers: (repo_data, {}))
    def fake_requests_get(url, headers=None):
        class Response:
            def __init__(self, status_code, payload=None):
                self.status_code = status_code
                self._payload = payload or []
                self.headers = {}
            def json(self):
                return self._payload
        if url.endswith("SECURITY.md"):
            return Response(404)
        if "/branches/" in url:
            return Response(404)
        if "dependabot" in url:
            return Response(404)
        if "code-scanning" in url:
            return Response(200, [{"id": 1}])
        raise AssertionError(f"Unexpected URL: {url}")
    monkeypatch.setattr(security_score.requests, "get", fake_requests_get)
    args = SimpleNamespace(repo="exc/example")
    security_score.cmd_security_score(args)
    out = capsys.readouterr().out
    assert "SECURITY SCORE" in out
    assert "License" in out
    assert "None" in out
    assert "Branch Protection" in out
