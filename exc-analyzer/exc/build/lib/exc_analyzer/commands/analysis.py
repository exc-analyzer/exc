# analysis.py
import requests
import re
from datetime import datetime, timedelta, timezone
from ..print_utils import Print
from ..api import api_get, get_auth_header, get_all_pages
from ..helpers import print_bw, print_bw_list

def cmd_analysis(args):
    if not args.repo:
        print("")
        Print.error("Owner and Repository are Missing.")
        Print.info("Usage: exc analysis <owner/repo>")
        print("")
        return

    headers = get_auth_header()
    repo_full_name = args.repo.strip()
    print("")
    Print.success("Repository Information")

    # Repository Info
    repo_url = f"https://api.github.com/repos/{repo_full_name}"
    repo_data, _ = api_get(repo_url, headers)

    desc = repo_data.get('description') or "No description."
    desc = (desc[:77] + " ...") if len(desc) > 80 else desc

    info_fields = [
        ("Name", repo_data.get('full_name')),
        ("Description", desc),
        ("Created At", repo_data.get('created_at')),
        ("Last Updated", repo_data.get('updated_at')),
        ("Stars", repo_data.get('stargazers_count')),
        ("Forks", repo_data.get('forks_count')),
        ("Watchers", repo_data.get('watchers_count')),
        ("Default Branch", repo_data.get('default_branch')),
        ("License", repo_data.get('license')['name'] if repo_data.get('license') else "None"),
        ("Open Issues", repo_data.get('open_issues_count')),
    ]

    for i, (label, value) in enumerate(info_fields):
        print_bw(label, value, use_white=(i % 2 == 0))

    # Languages
    langs_url = repo_url + "/languages"
    langs_data, _ = api_get(langs_url, headers)
    total_bytes = sum(langs_data.values())
    print("")
    Print.success("Languages")
    lang_items = [
        f"  {lang:<15}: {(count / total_bytes * 100):.2f}%" for lang, count in langs_data.items()
    ]
    print_bw_list(lang_items, lambda x: x)

    # Commit Activity
    print("")
    Print.success("Commit Statistics (Last 12 Months)")

    since_date = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
    default_branch = repo_data.get('default_branch')
    commits_url = f"https://api.github.com/repos/{repo_full_name}/commits"
    commits = get_all_pages(commits_url, headers, {'sha': default_branch, 'since': since_date})

    print_bw("Total Commits", len(commits))

    # Top Committers
    committers = {}
    for c in commits:
        author = c.get('author')
        if author and author.get('login'):
            login = author['login']
            committers[login] = committers.get(login, 0) + 1

    sorted_committers = sorted(committers.items(), key=lambda x: x[1], reverse=True)[:5]

    if sorted_committers:
        print("\n  Top Committers")
        print_bw_list(
            sorted_committers,
            lambda item: f"   - {item[0]:<15}: {item[1]} commits"
        )

    # Contributors
    print("")
    Print.success("Contributors")

    contributors_url = f"https://api.github.com/repos/{repo_full_name}/contributors"
    contributors = get_all_pages(contributors_url, headers)

    print_bw("Total Contributors", len(contributors))

    print("\n  Top Contributors")
    print_bw_list(
        contributors[:5],
        lambda c: f"   - {c.get('login') or 'Anonymous':<15}: {c.get('contributions')} contributions"
    )

    # Issues & PRs
    print("")
    Print.success("Issues and Pull Requests")
    print_bw("Open Issues", repo_data.get('open_issues_count'))

    pr_url = f"https://api.github.com/repos/{repo_full_name}/pulls?state=all&per_page=1"
    pr_resp = requests.get(pr_url, headers=headers)

    if pr_resp.status_code == 200:
        if 'Link' in pr_resp.headers and 'last' in pr_resp.links:
            last_url = pr_resp.links['last']['url']
            match = re.search(r'page=(\d+)', last_url)
            pr_count = int(match.group(1)) if match else "Unknown"
        else:
            pr_count = len(pr_resp.json())
        print_bw("Total PRs", pr_count, use_white=False)
    else:
        print_bw("Total PRs", "Failed to retrieve", use_white=False)

    print("")    
    Print.info("Completed.")
    print("")
