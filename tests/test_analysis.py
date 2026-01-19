from types import SimpleNamespace
from exc_analyzer.commands import analysis
def test_cmd_analysis_outputs_summary(monkeypatch, capsys, mock_async_client, mock_key_loader):
    repo_data = {
        "full_name": "exc/example",
        "description": "Example repository for tests",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "stargazers_count": 10,
        "forks_count": 2,
        "default_branch": "main",
        "license": {"name": "MIT"},
        "open_issues_count": 1,
    }
    contributors = [
         {"login": "alice", "contributions": 50},
         {"login": "bob", "contributions": 30},
    ]
    languages = {
        "edges": [
            {"node": {"name": "Python"}, "size": 1000}
        ]
    }
    MockClientClass = mock_async_client(
        repo_data=repo_data, 
        contributors_data=contributors,
        languages_data=languages
    )
    mock_client_instance = MockClientClass()
    monkeypatch.setattr(analysis, "create_async_context", lambda token: mock_client_instance)
    args = SimpleNamespace(repo="exc/example")
    analysis.cmd_analysis(args)
    out = capsys.readouterr().out
    assert "Repository Information" in out
    assert "Languages" in out
    assert "Completed" in out
