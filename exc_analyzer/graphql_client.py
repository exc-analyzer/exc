"""GitHub GraphQL API client for batch queries and high-performance analysis."""
from typing import Optional, Dict, Any
class GraphQLClient:
    """GitHub GraphQL API batch query builder for high-performance analysis."""
    REPO_ANALYSIS_QUERY = """
    query RepoAnalysis($owner: String!, $name: String!) {
      repository(owner: $owner, name: $name) {
        description
        createdAt
        updatedAt
        stargazerCount
        forkCount
        defaultBranchRef {
          name
        }
        licenseInfo {
          name
        }
        issues {
          totalCount
        }
        pullRequests {
          totalCount
        }
        primaryLanguage {
          name
        }
        languages(first: 20) {
          edges {
            node {
              name
            }
            size
          }
        }
      }
    }
    """
    COMMITS_QUERY = """
    query CommitHistory($owner: String!, $name: String!, $ref: String!, $first: Int!) {
      repository(owner: $owner, name: $name) {
        ref(qualifiedName: $ref) {
          target {
            ... on Commit {
              history(first: $first) {
                pageInfo {
                  endCursor
                  hasNextPage
                }
                edges {
                  node {
                    oid
                    message
                    author {
                      name
                      user {
                        login
                      }
                    }
                    committedDate
                    additions
                    deletions
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    CONTRIBUTORS_QUERY = """
    query Contributors($owner: String!, $name: String!, $first: Int!) {
      repository(owner: $owner, name: $name) {
        defaultBranchRef {
          target {
            ... on Commit {
              history(first: $first) {
                edges {
                  node {
                    author {
                      user {
                        login
                        name
                      }
                      date
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    @staticmethod
    def build_repo_query(owner: str, name: str) -> Dict[str, Any]:
        """Build GraphQL query for repository analysis."""
        return {
            "query": GraphQLClient.REPO_ANALYSIS_QUERY,
            "variables": {
                "owner": owner,
                "name": name
            }
        }
    @staticmethod
    def build_commits_query(owner: str, name: str, ref: str, first: int = 100, after: Optional[str] = None) -> Dict[str, Any]:
        """Build GraphQL query for commit history with pagination."""
        query = """
        query CommitHistory($owner: String!, $name: String!, $ref: String!, $first: Int!, $after: String) {
          repository(owner: $owner, name: $name) {
            ref(qualifiedName: $ref) {
              target {
                ... on Commit {
                  history(first: $first, after: $after) {
                    pageInfo {
                      endCursor
                      hasNextPage
                    }
                    edges {
                      node {
                        oid
                        message
                        author {
                          name
                          user {
                            login
                          }
                        }
                        committedDate
                        additions
                        deletions
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        return {
            "query": query,
            "variables": {
                "owner": owner,
                "name": name,
                "ref": ref,
                "first": first,
                "after": after
            }
        }
    @staticmethod
    def build_contributors_query(owner: str, name: str, first: int = 100) -> Dict[str, Any]:
        """Build GraphQL query for contributors."""
        return {
            "query": GraphQLClient.CONTRIBUTORS_QUERY,
            "variables": {
                "owner": owner,
                "name": name,
                "first": first
            }
        }
    @staticmethod
    def build_search_commits_query(query_string: str) -> Dict[str, Any]:
        """Build GraphQL query for commit search."""
        return {
            "query": """
            query SearchCommits($query: String!, $first: Int!) {
              search(query: $query, type: ISSUE, first: $first) {
                issueCount
              }
            }
            """,
            "variables": {
                "query": query_string,
                "first": 100
            }
        }
