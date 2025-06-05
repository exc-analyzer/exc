#!/usr/bin/env python3
import argparse
import os
import sys
import requests
import json
from datetime import datetime, timedelta, timezone
import time
import base64
import getpass
import re

# ---------------------
# Constants and Settings
# ---------------------

HOME_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME_DIR, ".exc")
KEY_FILE = os.path.join(CONFIG_DIR, "apikey.sec")

# ---------------------
# Helper Functions
# ---------------------

def ensure_config_dir():
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR, mode=0o700)

def save_key(key: str):
    ensure_config_dir()
    encoded = base64.b64encode(key.encode('utf-8')).decode('utf-8')
    with open(KEY_FILE, "w") as f:
        f.write(encoded)
    os.chmod(KEY_FILE, 0o600)
    print("[!] API key securely saved.")

def load_key():
    if not os.path.isfile(KEY_FILE):
        return None
    try:
        with open(KEY_FILE, "r") as f:
            encoded = f.read()
            key = base64.b64decode(encoded).decode('utf-8')
            return key
    except Exception:
        return None

def delete_key():
    if os.path.isfile(KEY_FILE):
        os.remove(KEY_FILE)
        print("[!] API key deleted.")
    else:
        print("[!] No saved API key found.")

def validate_key(key):
    headers = {
        "Authorization": f"token {key}",
        "Accept": "application/vnd.github.v3+json"
    }
    try:
        r = requests.get("https://api.github.com/user", headers=headers, timeout=8)
        if r.status_code == 200:
            user = r.json().get("login")
            print(f"[!] Key validated. API User: {user}")
            return True
        else:
            print(f"[!] Key validation failed! Error code: {r.status_code}")
            return False
    except requests.RequestException as e:
        print(f"[!] Key validation error: {e}")
        return False

def api_get(url, headers, params=None):
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=12)
        if resp.status_code == 403:
            print("[!] API rate limit exceeded. Please wait.")
            sys.exit(1)
        resp.raise_for_status()
        return resp.json(), resp.headers
    except requests.RequestException as e:
        print(f"[!] API request error: {e}")
        sys.exit(1)

def get_auth_header():
    key = load_key()
    if not key:
        print("[!] API key is missing. Use:")
        print("    exc key <your_api_key>")
        sys.exit(1)
    return {
        "Authorization": f"token {key}",
        "Accept": "application/vnd.github.v3+json"
    }

def get_all_pages(url, headers, params=None):
    results = []
    page = 1
    while True:
        if params is None:
            params = {}
        params.update({'per_page': 100, 'page': page})
        data, resp_headers = api_get(url, headers, params)
        if not isinstance(data, list):
            return data
        results.extend(data)
        if 'Link' in resp_headers:
            if 'rel="next"' not in resp_headers['Link']:
                break
        else:
            break
        page += 1
        time.sleep(0.15)
    return results

# ---------------------
# Command Functions
# ---------------------

def cmd_key(args):
    if args.reset:
        delete_key()
        return
    
    key = args.key
    if not key:
        print("\nTo authenticate with GitHub, you need a personal access token.")
        print("If you don’t have one, create it at: https://github.com/settings/personal-access-tokens\n")
        print("")
        key = getpass.getpass("Enter your GitHub API key (input hidden): ").strip()
    if not key:
        print("[!] API key cannot be empty.")
        return
    
    if validate_key(key):
        save_key(key)
    else:
        print("[!] Invalid API key, not saved.")

def cmd_analysis(args):
    headers = get_auth_header()
    repo_full_name = args.repo.strip()
    
    print(f"\n==== EXC Repository Analysis ====\n")

    # Repo info
    repo_url = f"https://api.github.com/repos/{repo_full_name}"
    repo_data, _ = api_get(repo_url, headers)
    print("[*] Repository Info")
    print("")
    print(f"{repo_data.get('full_name')}")
    print("")

    print(f"- Description")
    print("")
    print(f"{repo_data.get('description')}")
    print("")
    
    print(f"- Created: {repo_data.get('created_at')}")
    print("")
    
    print(f"- Updated: {repo_data.get('updated_at')}")
    print("")
    
    print(f"- Stars: {repo_data.get('stargazers_count')}")
    print("")
    
    print(f"- Forks: {repo_data.get('forks_count')}")
    print("")
    
    print(f"- Watchers: {repo_data.get('watchers_count')}")
    print("")

    print(f"- Default branch: {repo_data.get('default_branch')}")
    print("")

    print(f"- License: {repo_data.get('license')['name'] if repo_data.get('license') else 'None'}")
    print("")

    print(f"- Open issues: {repo_data.get('open_issues_count')}")
    print("")
    print("\n" + "─" * 40 + "\n")

    # Languages
    langs_url = repo_url + "/languages"
    langs_data, _ = api_get(langs_url, headers)
    total_bytes = sum(langs_data.values())

    print("\n[*] Languages:")
    print("")
    for lang, bytes_count in langs_data.items():
        percent = (bytes_count / total_bytes) * 100 if total_bytes else 0
        print(f"- {lang}: {percent:.2f}%")
    print("\n" + "─" * 40)


    # Commit stats (last year)
    print("\n[*] Commit stats:\n")

    default_branch = repo_data.get('default_branch')
    since_date = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
    commits_url = f"https://api.github.com/repos/{repo_full_name}/commits"
    commits = get_all_pages(commits_url, headers, {'sha': default_branch, 'since': since_date})

    print(f"Total commits: [{len(commits)}]\n")

    # Committers
    committers = {}
    for c in commits:
        author = c.get('author')
        if author and author.get('login'):
            login = author['login']
            committers[login] = committers.get(login, 0) + 1

    sorted_committers = sorted(committers.items(), key=lambda x: x[1], reverse=True)

    print("- Top committers:")
    for login, count in sorted_committers[:5]:
        print(f" - {login}: {count} commits")

    print("\n" + "─" * 40 + "\n")

    # Contributors
    print("[*] Contributors\n")

    contributors_url = f"https://api.github.com/repos/{repo_full_name}/contributors"
    contributors = get_all_pages(contributors_url, headers)

    print(f"- Total contributors: [{len(contributors)}]\n")
    print("- Top contributors:")
    for c in contributors[:5]:
        login = c.get('login') or "Anonymous"
        contrib_count = c.get('contributions')
        print(f" - {login}: {contrib_count} contributions")

    print("\n" + "─" * 40 + "\n")

    # Issues/PRs
    print("\n[*] Issues and Pull Requests:")
    print("")
    print(f"- Open issues: {repo_data.get('open_issues_count')}")

    pr_url = f"https://api.github.com/repos/{repo_full_name}/pulls?state=all&per_page=1"
    pr_resp = requests.get(pr_url, headers=headers)
    if pr_resp.status_code == 200:
        if 'Link' in pr_resp.headers and 'last' in pr_resp.links:
            last_url = pr_resp.links['last']['url']
            m = re.search(r'page=(\d+)', last_url)
            if m:
                pr_count = int(m.group(1))
                print(f"- Total Pull Requests: {pr_count}")
            else:
                print("Could not calculate PR count.")
        else:
            pr_list = pr_resp.json()
            print(f"- Total Pull Requests: {len(pr_list)}")
    else:
        print("Failed to get PR count.")

    print("\n--- Analysis complete ---\n")

def cmd_user_a(args):
    headers = get_auth_header()
    user = args.username.strip()
    
    print(f"\n==== EXC User Analysis ====")
    print("")
    print(f"Target User [{user}]\n")

    # User info
    user_url = f"https://api.github.com/users/{user}"
    user_data, _ = api_get(user_url, headers)

    print("[*] Information")
    print("")
    print(f"Name: {user_data.get('name')}")
    print(f"Username: {user_data.get('login')}")
    print(f"Bio: {user_data.get('bio')}")
    print(f"Location: {user_data.get('location')}")
    print(f"Company: {user_data.get('company')}")
    print(f"Account created: {user_data.get('created_at')}")
    print(f"Followers: {user_data.get('followers')}")
    print(f"Following: {user_data.get('following')}")
    print(f"Public repos: {user_data.get('public_repos')}")
    print(f"Public gists: {user_data.get('public_gists')}")
    print("\n" + "─" * 40 + "\n")
    # User repos
    repos_url = f"https://api.github.com/users/{user}/repos"
    repos = get_all_pages(repos_url, headers)

    print("\n[*] User's top starred repos:")
    repos_sorted = sorted(repos, key=lambda r: r.get('stargazers_count', 0), reverse=True)
    for repo in repos_sorted[:5]:
        print("")
        print(f" ⭐ {repo.get('stargazers_count')} - {repo.get('name')}")

    print("\n--- Analysis complete ---\n")

# =========
# Security
# =========

def cmd_scan_secrets(args):
    """Scan repository commits for leaked secrets"""
    headers = get_auth_header()
    repo = args.repo.strip()
    
    # Secret patterns to detect
    SECRET_PATTERNS = {
        'AWS Key': r'AKIA[0-9A-Z]{16}',
        'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
        'SSH Private': r'-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----',
        'API Key': r'(?i)(api|access)[_ -]?key["\']?[:=] ?["\'][0-9a-zA-Z]{20,40}'
    }
    
    print(f"\n[*] Scanning last {args.limit} commits in [{repo}] for secrets.")
    print("")
    print("- Processing… this may take a few minutes.")
    
    # Get commit history
    commit_limit = args.limit
    commits_url = f"https://api.github.com/repos/{repo}/commits?per_page={commit_limit}"
    commits, _ = api_get(commits_url, headers)
    
    found_secrets = False
    
    for commit in commits:
        commit_data, _ = api_get(commit['url'], headers)
        files = commit_data.get('files', [])
        
        for file in files:
            if file['status'] != 'added': continue
            
            # Get file content
            content_url = file['raw_url']
            try:
                content = requests.get(content_url).text
                for secret_type, pattern in SECRET_PATTERNS.items():
                    if re.search(pattern, content):
                        print(f"\n[!] {secret_type} found in {file['filename']}")
                        print(f"Commit: {commit['html_url']}")
                        print(f"Date: {commit['commit']['author']['date']}")
                        found_secrets = True
            except:
                continue
    
    if not found_secrets:
        print("\n[!] No secrets found in scanned commits")
        print("")

def cmd_contrib_impact(args):
    """Measure contributor impact using line changes"""
    headers = get_auth_header()
    repo = args.repo.strip()
    
    # Get contributor stats
    stats_url = f"https://api.github.com/repos/{repo}/stats/contributors"
    contributors = get_all_pages(stats_url, headers)
    
    print(f"\n[*] Contributor Impact Analysis for {repo}")
    print("")
    print("(Score = Total lines added * 0.7 - Total lines deleted * 0.3)")
    
    results = []
    for contributor in contributors:
        login = contributor['author']['login']
        total_add = sum(w['a'] for w in contributor['weeks'])
        total_del = sum(w['d'] for w in contributor['weeks'])
        score = (total_add * 0.7) - (total_del * 0.3)
        results.append((login, score, total_add, total_del))
    
    # Sort by impact score
    print("\nTop contributors by impact:")
    for login, score, adds, dels in sorted(results, key=lambda x: x[1], reverse=True)[:10]:
        print(f"\n{login}")
        print(f"Impact Score: {score:.1f}")
        print(f"Lines added: {adds} | ➖ Lines deleted: {dels}")

def cmd_file_history(args):
    """Track changes to a specific file"""
    headers = get_auth_header()
    repo = args.repo.strip()
    filepath = args.filepath.strip()
    
    print(f"\n[*] Change History for [{filepath}] in [{repo}]")
    
    # Get file commits
    commits_url = f"https://api.github.com/repos/{repo}/commits?path={filepath}&per_page=5"
    commits = get_all_pages(commits_url, headers)
    
    print(f"\n[!] Last {len(commits)} modifications:\n")
    
    for commit in commits:
        commit_data, _ = api_get(commit['url'], headers)
        print(f"[+] {commit_data['commit']['message'].splitlines()[0]}")
        print(f"[+] {commit_data['commit']['author']['name']}")
        print(f"[+] {commit_data['commit']['author']['date']}")
        print(f"[+] {commit['html_url']}\n")

# ---------------------
# Main Program
# ---------------------

def print_custom_help():
    help_text = """
   ▄████████ ▀████    ▐████▀  ▄████████ 
  ███    ███   ███▌   ████▀  ███    ███ 
  ███    █▀     ███  ▐███    ███    █▀  
 ▄███▄▄▄        ▀███▄███▀    ███        
▀▀███▀▀▀        ████▀██▄     ███
  ███    █▄    ▐███  ▀███    ███    █▄  
  ███    ███  ▄███     ███▄  ███    ███ 
  ██████████ ████       ███▄ ████████▀ 

[*] USAGE EXAMPLES:
    ╭─────────────────────────────────────────────────────────────────╮
    │ API Key Management:                                             │
    │    exc key                           # Secure key input         │
    │    exc key --reset or -r             # Reset stored key         │
    ├─────────────────────────────────────────────────────────────────┤
    │ Repository Analysis:                                            │
    │    exc analysis owner/repo           # Full repository analysis │
    │    exc scan-secrets owner/repo       # Find leaked credentials  │
    │    exc file-history owner/repo path  # File change history      │
    ├─────────────────────────────────────────────────────────────────┤
    │ User Analysis:                                                  │
    │    exc user-a username               # User profile analysis    │
    ╰─────────────────────────────────────────────────────────────────╯

[*] ADVANCED OPTIONS:
    For detailed information about each module:
    exc <module> --help or -h
"""
    print(help_text)
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        prog="exc",
        usage="",
        description="",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    
    subparsers = parser.add_subparsers(dest="command")

    # Key command
    key_parser = subparsers.add_parser(
    "key",
    description=(
        "----- KEY COMMAND -----\n"
        "Manage GitHub API keys.\n\n"
        "Use this command to securely input and store your GitHub API key. "
        "When you run 'exc key', you will be prompted to enter your API key, "
        "and your input will be hidden for security purposes.\n\n"
        "Example:\n"
        "  exc key\n\n"
        "You will be asked to enter your GitHub API key securely (input is not shown).\n"
        "--------------------------"
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter
)
    key_parser.add_argument("key", nargs="?", help=argparse.SUPPRESS)
    key_parser.add_argument("-r", "--reset", action="store_true", help=argparse.SUPPRESS)
    key_parser.set_defaults(func=cmd_key)

    # Analysis command
    analysis_parser = subparsers.add_parser(
    "analysis",
    description=(
        "----- ANALYSİS COMMAND -----\n"
        "Performs a full repository analysis, including code quality, security patterns, dependencies, "
        "and other metrics. Useful for getting a high-level overview of the project's health.\n\n"
        "Usage: exc analysis <owner/repo>\n"
        "----------------------------------"
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter
)
    analysis_parser.add_argument("repo", help=argparse.SUPPRESS)
    analysis_parser.set_defaults(func=cmd_analysis)

    # User analysis command
    user_parser = subparsers.add_parser(
    "user-a",
    description=(
        "----- USER ANALYSİS COMMAND -----\n"
        "Analyzes the contribution profile of a specific user in the repository. Provides insights into "
        "commit patterns, code ownership, and areas of expertise.\n\n"
        "Usage: exc user-a <github_username>\n"
        "----------------------------------"
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter
)
    user_parser.add_argument("username", help=argparse.SUPPRESS)
    user_parser.set_defaults(func=cmd_user_a)

    # Scan secrets command
    scan_parser = subparsers.add_parser(
    "scan-secrets",
    description=(
        "----- SCAN SECRETS COMMAND -----\n"
        "Scans the last 100 commits of the specified repository for potential secrets such as hardcoded API keys, "
        "AWS credentials, SSH private keys, tokens, and other sensitive data that may have been accidentally committed.\n\n"
        "Usage: scan-secrets <owner/repo>\n"
        "----------------------------------"
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter
)
    scan_parser.add_argument("repo", help=argparse.SUPPRESS)
    scan_parser.add_argument("-l", "--limit", type=int, default=10,
                         help="Number of recent commits to scan (default: 10)")
    scan_parser.set_defaults(func=cmd_scan_secrets)

    # File history command
    file_parser = subparsers.add_parser(
    "file-history",
    description=(
        "----- FILE HISTORY COMMAND -----\n"
        "Displays the full change history of a specific file within a Git repository. "
        "Includes commit hashes, authors, timestamps, and commit messages where the file was modified.\n\n"
        "Useful for auditing changes, tracking ownership, or understanding the evolution of a file.\n\n"
        "Usage: exc file-history <owner/repo> <path_to_file>\n"
        "----------------------------------"
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter
)
    file_parser.add_argument("repo", help=argparse.SUPPRESS)
    file_parser.add_argument("filepath", help=argparse.SUPPRESS)
    file_parser.set_defaults(func=cmd_file_history)


    # Help flag
    parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)

    args, unknown = parser.parse_known_args()

    if args.help or not args.command:
        print_custom_help()

    if hasattr(args, "func"):
        args.func(args)
    else:
        print_custom_help()

if __name__ == "__main__":
    main()