"""Repository analysis command - optimized with async GraphQL queries."""
import asyncio
from datetime import datetime, timedelta, timezone
from ..print_utils import Print
from ..async_api import create_async_context
from ..graphql_client import GraphQLClient
from ..helpers import print_bw, print_bw_list, format_friendly_date
from ..config import load_key
from ..i18n import t
async def _analyze_repo_async(repo_full_name: str, token: str, show_rate_limit: bool = False):
    """Async repository analysis using GraphQL and concurrent requests."""
    from ..spinner import spinner
    async with create_async_context(token) as client:
        since_date = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        owner, repo_name = repo_full_name.split("/")
        default_branch = "main"  
        try:
            with spinner(t("commands.analysis_output.repo_info"), color='96'):
                repo_query = GraphQLClient.build_repo_query(owner, repo_name)
                repo_data = await client.graphql_query(repo_query)
            if "repository" not in repo_data:
                Print.error(t("commands.shared.repo_not_found"))
                return
            repo_info = repo_data["repository"]
            default_branch = repo_info.get("defaultBranchRef", {}).get("name", "main")
            print("")
            from exc_analyzer.print_utils import safe_print, colorize
            safe_print(colorize(f"[*] {t('commands.analysis_output.repo_info')}", '96'))
            desc = repo_info.get("description") or "No description."
            desc = (desc[:77] + " ...") if len(desc) > 80 else desc
            info_fields = [
                (t("commands.analysis_output.labels.name"), repo_full_name),
                (t("commands.analysis_output.labels.desc"), desc),
                (t("commands.analysis_output.labels.created"), format_friendly_date(repo_info.get("createdAt"), include_relative=True)),
                (t("commands.analysis_output.labels.updated"), format_friendly_date(repo_info.get("updatedAt"), include_relative=True)),
                (t("commands.analysis_output.labels.stars"), repo_info.get("stargazerCount")),
                (t("commands.analysis_output.labels.forks"), repo_info.get("forkCount")),
                (t("commands.analysis_output.labels.default_branch"), default_branch),
                (t("commands.analysis_output.labels.license"), repo_info.get("licenseInfo", {}).get("name") if repo_info.get("licenseInfo") else "None"),
                (t("commands.analysis_output.labels.open_issues"), repo_info.get("issues", {}).get("totalCount")),
            ]
            for i, (label, value) in enumerate(info_fields):
                print_bw(label, value, use_white=(i % 2 == 0))
            print("")
            safe_print(colorize(f"[*] {t('commands.analysis_output.languages')}", '96'))
            languages = {}
            for edge in repo_info.get("languages", {}).get("edges", []):
                lang_name = edge.get("node", {}).get("name", t("commands.shared.unknown"))
                lang_size = edge.get("size", 0)
                languages[lang_name] = lang_size
            if languages:
                total_bytes = sum(languages.values())
                lang_items = [
                    f"  {lang:<15}: {(count / total_bytes * 100):.2f}%" 
                    for lang, count in languages.items()
                ]
                print_bw_list(lang_items, lambda x: x)
            print("")
            safe_print(colorize(f"[*] {t('commands.analysis_output.commit_stats')}", '96'))
            commits_query = GraphQLClient.build_commits_query(
                owner,
                repo_name,
                default_branch,
                first=100
            )
            commits_data = await client.graphql_query(commits_query)
            commits_list = []
            if "repository" in commits_data:
                repo_ref = commits_data.get("repository", {}).get("ref")
                if repo_ref:
                    target = repo_ref.get("target", {})
                    history = target.get("history", {})
                    edges = history.get("edges", [])
                    for edge in edges:
                        node = edge.get("node", {})
                        author = node.get("author")
                        if author is None:
                            author_name = t("commands.shared.anonymous")
                        else:
                            user = author.get("user") if isinstance(author, dict) else None
                            author_name = (user.get("login") if user else None) or author.get("name") or t("commands.shared.anonymous") if isinstance(author, dict) else t("commands.shared.anonymous")
                        commits_list.append({
                            "sha": node.get("oid", "")[:7],
                            "author": author_name,
                            "message": node.get("message", ""),
                            "date": node.get("committedDate", "")
                        })
            print_bw(t("commands.analysis_output.analyzed_commits", count=len(commits_list)), len(commits_list))
            committers = {}
            for c in commits_list:
                author = c.get("author", t("commands.shared.anonymous"))
                committers[author] = committers.get(author, 0) + 1
            sorted_committers = sorted(committers.items(), key=lambda x: x[1], reverse=True)[:5]
            if sorted_committers:
                print(f"\n  {t('commands.analysis_output.top_committers')}")
                print_bw_list(
                    sorted_committers,
                    lambda item: f"   - {item[0]:<15}: {item[1]} commits"
                )
            print("")
            safe_print(colorize(f"[*] {t('commands.analysis_output.contributors')}", '96'))
            contributors_url = f"https://api.github.com/repos/{repo_full_name}/contributors"
            contributors = await client.fetch_paginated(contributors_url, per_page=100, max_pages=2)
            print_bw(t("commands.analysis_output.total_contributors"), len(contributors))
            if contributors:
                print(f"\n  {t('commands.analysis_output.top_contributors')}")
                top_contributors = sorted(
                    contributors,
                    key=lambda c: c.get("contributions", 0),
                    reverse=True
                )[:5]
                print_bw_list(
                    top_contributors,
                    lambda c: f"   - {c.get('login', t('commands.shared.anonymous')):<15}: {c.get('contributions')} contributions"
                )
            print("")
            safe_print(colorize(f"[*] {t('commands.analysis_output.issues_prs')}", '96'))
            print_bw(t("commands.analysis_output.open_issues"), repo_info.get("issues", {}).get("totalCount"))
            print_bw(t("commands.analysis_output.total_prs"), repo_info.get("pullRequests", {}).get("totalCount"), use_white=False)
            print("")
            Print.info(t("commands.analysis_output.completed"))
            print("")
            if show_rate_limit:
                Print.info(client.get_quota_info())
                print("")
        except Exception as e:
            Print.error(f"Analysis failed: {str(e)}")
def cmd_analysis(args):
    """Repository analysis command with async optimization."""
    from ..print_utils import _write_output
    if not args.repo:
        print("")
        _write_output("")
        Print.error(t("commands.shared.missing_owner_repo"))
        Print.info(t("commands.analysis.usage"))
        print("")
        _write_output("")
        return
    repo_full_name = args.repo.strip()
    if "/" not in repo_full_name or len(repo_full_name.split("/")) != 2:
        print("")
        _write_output("")
        Print.error(t("commands.shared.invalid_repo_format"))
        print("")
        return
    token = load_key()
    if not token:
        print("")
        _write_output("")
        Print.error(t("commands.shared.api_key_missing"))
        Print.info(t("commands.shared.use_key_cmd"))
        print("")
        _write_output("")
        return
    try:
        show_rate = getattr(args, 'show_rate_limit', False)
        asyncio.run(_analyze_repo_async(repo_full_name, token, show_rate))
    except KeyboardInterrupt:
        print("")
        _write_output("")
        Print.warn(t("commands.shared.scan_cancelled"))
    except Exception as e:
        Print.error(t("commands.shared.error_occurred", error=str(e)))
