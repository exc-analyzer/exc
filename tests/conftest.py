"""Test configuration ensuring local package takes precedence over installed copies."""
from __future__ import annotations
import sys
from pathlib import Path
import pytest
from types import SimpleNamespace
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_STR = str(PROJECT_ROOT)
if PROJECT_STR not in sys.path:
    sys.path.insert(0, PROJECT_STR)
@pytest.fixture
def mock_async_client():
    """Returns a mock async client class factory."""
    def create_mock_client(repo_data=None, contributors_data=None, quota_info="Remaining requests: 5000", languages_data=None):
        repo_data = repo_data or {}
        contributors_data = contributors_data or []
        languages_data = languages_data or {"edges": []}
        class MockAsyncClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            async def graphql_query(self, query):
                return {
                    "repository": {
                        "description": repo_data.get("description", "Test Description"),
                        "createdAt": repo_data.get("created_at", "2024-01-01T00:00:00Z"),
                        "updatedAt": repo_data.get("updated_at", "2024-01-01T00:00:00Z"),
                        "stargazerCount": repo_data.get("stargazers_count", 0),
                        "forkCount": repo_data.get("forks_count", 0),
                        "defaultBranchRef": {"name": repo_data.get("default_branch", "main")},
                        "licenseInfo": {"name": repo_data.get("license", {}).get("name", "MIT")},
                        "issues": {"totalCount": repo_data.get("open_issues_count", 0)},
                        "pullRequests": {"totalCount": 0},
                        "languages": languages_data
                    }
                }
            async def fetch_paginated(self, url, per_page=100, max_pages=None):
                return contributors_data
            def get_quota_info(self):
                return quota_info
        return MockAsyncClient
    return create_mock_client
@pytest.fixture
def mock_key_loader(monkeypatch):
    """Mocks load_key to return a fake token."""
    from exc_analyzer.commands import analysis
    monkeypatch.setattr(analysis, "load_key", lambda: "fake_token")
