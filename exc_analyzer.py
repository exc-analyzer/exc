#!/usr/bin/env python3
import argparse
import sys
import os
import platform
import shutil
import stat
def setup_linux_desktop_shortcut():
    """
    pipx ile kurulu exc-analyzer için masaüstü uygulama menüsüne .desktop kısayolu ve ikonunu otomatik ekler.
    """
    try:
        # Sadece Linux ve masaüstü ortamı için
        if platform.system() != "Linux":
            return
        # pipx ile kurulu olup olmadığını anlamak için sys.argv[0] veya __file__ yolu pipx dizininde mi bakılır
        pipx_home = os.environ.get("PIPX_HOME", os.path.expanduser("~/.local/pipx"))
        if pipx_home not in sys.argv[0] and "pipx" not in sys.argv[0]:
            return
        # .desktop dosyası ve ikon yolu
        desktop_dir = os.path.expanduser("~/.local/share/applications")
        icon_dir = os.path.expanduser("~/.local/share/icons")
        os.makedirs(desktop_dir, exist_ok=True)
        os.makedirs(icon_dir, exist_ok=True)
        desktop_file = os.path.join(desktop_dir, "exc-analyzer.desktop")
        icon_file = os.path.join(icon_dir, "exc-analyzer.png")
        # İkonu paket içinden çıkar (importlib.resources ile)
        try:
            import importlib.resources as pkg_resources
        except ImportError:
            import importlib_resources as pkg_resources
        try:
            # exc_analyzer.png dosyasının exc_analyzer modülünde olduğunu varsayıyoruz
            with pkg_resources.files("exc_analyzer").joinpath("exc-analyzer.png").open("rb") as src, open(icon_file, "wb") as dst:
                shutil.copyfileobj(src, dst)
        except Exception:
            # Alternatif: build/lib/exc_analyzer.png veya exc_analyzer.png kökteyse
            possible_paths = [
                os.path.join(os.path.dirname(__file__), "exc-analyzer.png"),
                os.path.join(os.path.dirname(__file__), "build", "lib", "exc-analyzer.png"),
            ]
            for p in possible_paths:
                if os.path.isfile(p):
                    shutil.copyfile(p, icon_file)
                    break
        # .desktop dosyası içeriği
        exec_path = shutil.which("exc") or sys.argv[0]
        desktop_content = f"""
        [Desktop Entry]
        Type=Application
        Name=EXC Analyzer
        Comment=GitHub Security & Intelligence Toolkit
        Exec={exec_path}
        Icon={icon_file}
        Terminal=true
        Categories=Development;Security;
        """.strip() + "\n"
        # Eğer .desktop dosyası yoksa veya eskiyse oluştur
        need_write = True
        if os.path.isfile(desktop_file):
            try:
                with open(desktop_file, "r") as f:
                    if f"Exec={exec_path}" in f.read():
                        need_write = False
            except Exception:
                pass
        if need_write:
            with open(desktop_file, "w") as f:
                f.write(desktop_content)
            os.chmod(desktop_file, os.stat(desktop_file).st_mode | stat.S_IXUSR)
    except Exception:
        pass
import os
import sys
import requests
import json
from datetime import datetime, timedelta, timezone
import time
import base64
import getpass
import re
import difflib
from packaging.version import Version
import toml
from urllib.parse import quote


# ---------------------
# Constants and Settings
# ---------------------

HOME_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME_DIR, ".exc")
KEY_FILE = os.path.join(CONFIG_DIR, "apikey.sec")

def get_version_from_pyproject():
    try:
        pyproject_path = os.path.join(os.path.dirname(__file__), 'pyproject.toml')
        if os.path.isfile(pyproject_path):
            data = toml.load(pyproject_path)
            return data.get('project', {}).get('version') or data.get('tool', {}).get('poetry', {}).get('version')
    except Exception as e:
        log(f"pyproject.toml version read error: {e}")
    return None

def get_version_from_pypi():
    try:
        import requests
        resp = requests.get("https://pypi.org/pypi/exc-analyzer/json", timeout=5)
        if resp.status_code == 200:
            return resp.json()["info"]["version"]
    except Exception as e:
        log(f"PyPI version fetch error: {e}")
    return None

__version__ = get_version_from_pypi() or "1.0.0"

# Automatic version check (for notification)
def notify_new_version():
    try:
        import requests
        from packaging.version import Version
        resp = requests.get("https://pypi.org/pypi/exc-analyzer/json", timeout=5)
        if resp.status_code == 200:
            latest = resp.json()["info"]["version"]
            local_v = Version(__version__)
            latest_v = Version(latest)
            if local_v < latest_v:
                Print.warn(f"A new version is available: {latest} (You have {__version__})")
                Print.info("Upgrade: pip install -U exc-analyzer")
            # Only warn if outdated, silent if up-to-date
    except Exception as e:
        log(f"Version notify error: {e}")

# Terminal color support check
import sys
import platform

def supports_color():
    plat = sys.platform
    supported_platform = plat != 'Pocket PC' and (plat != 'win32' or 'ANSICON' in os.environ or 'WT_SESSION' in os.environ or 'TERM' in os.environ)
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    return supported_platform and is_a_tty

COLOR_ENABLED = supports_color()

def colorize(text, color_code):
    if COLOR_ENABLED:
        return f"\033[{color_code}m{text}\033[0m"
    return text

# Colorful and icon-based print helpers (updated)
class Print:
    @staticmethod
    def success(msg):
        print(colorize(f"[✔ ] {msg}", '92'))
    @staticmethod
    def error(msg):
        print(colorize(f"[✖ ] {msg}", '91'))
    @staticmethod
    def warn(msg):
        print(colorize(f"[!] {msg}", '93'))
    @staticmethod
    def info(msg):
        print(colorize(f"[➜ ] {msg}", '96'))
    @staticmethod
    def star(msg):
        print(colorize(f"[★ ] {msg}", '95'))

# Verbose/logging
VERBOSE = False
LOG_FILE = os.path.join(CONFIG_DIR, "exc.log")
# Log file rotation (max 1MB)
def log(msg):
    if VERBOSE:
        Print.info(msg)
    try:
        if os.path.isfile(LOG_FILE) and os.path.getsize(LOG_FILE) > 1024*1024:
            os.remove(LOG_FILE)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception as e:
        if VERBOSE:
            Print.warn(f"Log file error: {e}")

def check_latest_version():
    try:
        import requests
        from packaging.version import Version
        resp = requests.get("https://pypi.org/pypi/exc-analyzer/json", timeout=5)
        if resp.status_code == 200:
            latest = resp.json()["info"]["version"]
            local_v = Version(__version__)
            latest_v = Version(latest)
            if local_v < latest_v:
                Print.warn(f"A new version is available: {latest} (You have {__version__})")
                Print.info("Upgrade: pip install -U exc-analyzer")
            elif local_v > latest_v:
                Print.warn(f"You are running a development version ({__version__}) not yet released on PyPI (latest: {latest})")
    except Exception as e:
        log(f"Version check error: {e}")

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
    print("")
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
            reset = resp.headers.get('X-RateLimit-Reset')
            if reset:
                reset_time = int(reset)
                now = int(time.time())
                wait_sec = max(0, reset_time - now)
                wait_min = wait_sec // 60
                Print.warn(f"GitHub API rate limit exceeded. Please wait {wait_min} min {wait_sec%60} sec until {datetime.utcfromtimestamp(reset_time).strftime('%Y-%m-%d %H:%M:%S UTC')}")
            else:
                Print.warn("API rate limit exceeded. Please wait.")
            log("API rate limit exceeded.")
            sys.exit(1)
        resp.raise_for_status()
        return resp.json(), resp.headers
    except requests.HTTPError as e:
        Print.error(f"HTTP error: {e} (status: {getattr(e.response, 'status_code', '?')})")
        if hasattr(e, 'response') and e.response is not None:
            Print.warn(f"Response: {e.response.text}")
            if 'X-RateLimit-Remaining' in e.response.headers:
                Print.warn(f"Rate limit remaining: {e.response.headers['X-RateLimit-Remaining']}")
        log(f"HTTP error: {e}")
        sys.exit(1)
    except requests.RequestException as e:
        Print.error(f"Request error: {type(e).__name__}: {e}")
        log(f"Request error: {e}")
        sys.exit(1)
    except Exception as e:
        Print.error(f"Unexpected error: {type(e).__name__}: {e}")
        log(f"Unexpected error: {e}")
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

def print_table(data, headers=None):
    try:
        from tabulate import tabulate
        print(tabulate(data, headers=headers, tablefmt="fancy_grid"))
    except ImportError:
        print("Repository | File | URL")
        print("-"*60)
        for repo, path, url in data:
            print(f"{repo} | {path} | {url}")

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
    if not args.repo:
        Print.error("Missing required argument: <owner/repo>")
        print("\nUsage: exc analysis <owner/repo>")
        print("Example: exc analysis torvalds/linux")
        print("\nPerforms a full repository analysis, including code quality, security patterns, dependencies, and other metrics.")
        return
    
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
    if not args.username:
        Print.error("Missing required argument: <github_username>")
        print("\nUsage: exc user-a <github_username>")
        print("Example: exc user-a octocat")
        print("\nAnalyzes the contribution profile of a specific user, including commit patterns, code ownership, and top repositories.")
        return
    
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
    if not args.repo:
        Print.error("Missing required argument: <owner/repo>")
        print("\nUsage: exc scan-secrets <owner/repo> [-l N]")
        print("Example: exc scan-secrets torvalds/linux -l 50")
        print("\nScans the last N commits (default 10) for secrets like API keys, AWS credentials, SSH keys, and tokens.")
        return
    
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
    if not args.repo or not args.filepath:
        Print.error("Missing required arguments: <owner/repo> <path_to_file>")
        print("\nUsage: exc file-history <owner/repo> <path_to_file>")
        print("Example: exc file-history torvalds/linux kernel/sched/core.c")
        print("\nDisplays the full change history of a specific file, including commit hashes, authors, timestamps, and messages.")
        return
    
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

# New module command functions

def cmd_dork_scan(args):
    if not args.query:
        Print.error("Missing required argument: <dork_query>")
        print("Example: exc dork-scan brgkdm")
        print("\nScans public GitHub code for sensitive keywords or patterns (dorking). Useful for finding exposed secrets or config files.")
        return
    headers = get_auth_header()
    query = ' '.join(args.query).strip()
    num = args.num or 10
    if num > 100:
        num = 100
    ext = args.ext
    fname = args.filename
    Print.info(f"Searching GitHub for: {query} (max {num})")
    url = f"https://api.github.com/search/code?q={quote(query)}&per_page={num}"
    data, _ = api_get(url, headers)
    results = []
    for item in data.get('items', []):
        repo = item['repository']['full_name']
        path = item['path']
        html_url = item['html_url']
        if ext and not path.endswith(f'.{ext}'):
            continue
        if fname and fname not in path:
            continue
        results.append((repo, path, html_url))
    if results:
        # Set column widths
        repo_w = max(len(r) for r, _, _ in results + [("Repository", "", "")]) + 2
        file_w = max(len(p) for _, p, _ in results + [("", "File", "")]) + 2
        # Color function
        def c(text, code):
            return f"\033[{code}m{text}\033[0m"
        # Header
        print(f"{c('Repository', '96').ljust(repo_w)}{c('File', '93').ljust(file_w)}")
        print("-" * (repo_w + file_w))
        # Rows
        for repo, path, url in results:
            simge = c('[+]', '93')
            repo_str = c(repo.ljust(repo_w), '92')
            file_str = c(path.ljust(file_w), '96')
            url_str = c(url, '94')
            print(f"{simge} {repo_str}{file_str}")
            print(f"    {url_str}")
            print()
        Print.info(f"Total shown: {len(results)}")
    else:
        Print.warn("No results found.")

def cmd_advanced_secrets(args):
    if not args.repo:
        Print.error("Missing required argument: <owner/repo>")
        print("\nUsage: exc advanced-secrets <owner/repo> [-l N]")
        print("Example: exc advanced-secrets torvalds/linux -l 30")
        print("\nScans the repository files and last N commits for a wide range of secret patterns (API keys, tokens, config files, etc.).")
        return
    headers = get_auth_header()
    repo = args.repo.strip()
    commit_limit = getattr(args, 'limit', 20)
    Print.info(f"Scanning repo files and last {commit_limit} commits for secrets: {repo}")
    # Secret patterns
    SECRET_PATTERNS = {
        'AWS Key': r'AKIA[0-9A-Z]{16}',
        'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
        'Slack Token': r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
        'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
        'Heroku API Key': r'heroku[a-z0-9]{32}',
        'Discord Token': r'[MN][A-Za-z\d]{23}\\.[\\w-]{6}\\.[\\w-]{27}',
        'Stripe Key': r'sk_live_[0-9a-zA-Z]{24}',
        'Mailgun Key': r'key-[0-9a-zA-Z]{32}',
        'API Key': r'(?i)(api|access)[_ -]?key["\']?[:=] ?["\'][0-9a-zA-Z]{20,40}',
        'Config File': r'(config|settings|secret|credentials|env)(\\.json|\\.yml|\\.yaml|\\.py|\\.env)'
    }
    found = []
    # 1. Search in repo files
    url = f"https://api.github.com/repos/{repo}/git/trees/HEAD?recursive=1"
    data, _ = api_get(url, headers)
    for f in data.get('tree', []):
        if f['type'] == 'blob':
            fname = f['path']
            if any(ext in fname for ext in ['.env', 'config', 'secret', 'credential', '.json', '.yml', '.yaml', '.py']):
                file_url = f"https://raw.githubusercontent.com/{repo}/HEAD/{fname}"
                try:
                    content = requests.get(file_url, timeout=8).text
                    for name, pattern in SECRET_PATTERNS.items():
                        if re.search(pattern, content):
                            found.append([fname, name, file_url, 'file'])
                except Exception:
                    continue
    # 2. Search in last N commits' modified files
    commits_url = f"https://api.github.com/repos/{repo}/commits?per_page={commit_limit}"
    commits, _ = api_get(commits_url, headers)
    for commit in commits:
        commit_data, _ = api_get(commit['url'], headers)
        files = commit_data.get('files', [])
        for file in files:
            if file['status'] not in ['added', 'modified']:
                continue
            content_url = file.get('raw_url')
            if not content_url:
                continue
            try:
                content = requests.get(content_url, timeout=8).text
                for name, pattern in SECRET_PATTERNS.items():
                    if re.search(pattern, content):
                        found.append([file['filename'], name, content_url, f"commit: {commit['sha'][:7]}"])
            except Exception:
                continue
    if found:
        print_table(found, headers=["File", "Type", "URL", "Source"])
        Print.info(f"Total findings: {len(found)}")
    else:
        Print.success("No secrets found in scanned files or commits.")

def cmd_security_score(args):
    if not args.repo:
        Print.error("Missing required argument: <owner/repo>")
        print("\nUsage: exc security-score <owner/repo>")
        print("Example: exc security-score torvalds/linux")
        print("\nCalculates a security score for the repository based on open issues, branch protection, security.md, license, dependabot, code scanning, and more.")
        return
    headers = get_auth_header()
    repo = args.repo.strip()
    Print.info(f"Calculating security score for: {repo}")
    repo_url = f"https://api.github.com/repos/{repo}"
    repo_data, _ = api_get(repo_url, headers)
    score = 100
    table = []
    # License
    if not repo_data.get('license'):
        score -= 10
        table.append(["License", "❌ None", "-10"])
    else:
        table.append(["License", "✔ Present", "0"])
    # Issues
    if not repo_data.get('has_issues'):
        score -= 10
        table.append(["Issues Enabled", "❌ No", "-10"])
    else:
        table.append(["Issues Enabled", "✔ Yes", "0"])
    # Wiki
    if not repo_data.get('has_wiki'):
        score -= 5
        table.append(["Wiki Enabled", "❌ No", "-5"])
    else:
        table.append(["Wiki Enabled", "✔ Yes", "0"])
    # Projects
    if not repo_data.get('has_projects'):
        score -= 5
        table.append(["Projects Enabled", "❌ No", "-5"])
    else:
        table.append(["Projects Enabled", "✔ Yes", "0"])
    # Open issue count
    open_issues = repo_data.get('open_issues_count', 0)
    if open_issues > 50:
        score -= 10
        table.append(["Open Issues", f"{open_issues}", "-10"])
    elif open_issues > 10:
        score -= 5
        table.append(["Open Issues", f"{open_issues}", "-5"])
    else:
        table.append(["Open Issues", f"{open_issues}", "0"])
    # SECURITY.md
    sec_url = f"https://api.github.com/repos/{repo}/contents/SECURITY.md"
    sec_resp = requests.get(sec_url, headers=headers)
    if sec_resp.status_code != 200:
        score -= 10
        table.append(["SECURITY.md", "❌ Missing", "-10"])
    else:
        table.append(["SECURITY.md", "✔ Present", "0"])
    # Branch protection (default branch)
    default_branch = repo_data.get('default_branch')
    prot_url = f"https://api.github.com/repos/{repo}/branches/{default_branch}/protection"
    prot_resp = requests.get(prot_url, headers=headers)
    if prot_resp.status_code == 200:
        table.append(["Branch Protection", "✔ Enabled", "0"])
    else:
        score -= 10
        table.append(["Branch Protection", "❌ Not enabled", "-10"])
    # Dependabot config
    dep_url = f"https://api.github.com/repos/{repo}/contents/.github/dependabot.yml"
    dep_resp = requests.get(dep_url, headers=headers)
    if dep_resp.status_code == 200:
        table.append(["Dependabot Config", "✔ Present", "0"])
    else:
        score -= 5
        table.append(["Dependabot Config", "❌ Missing", "-5"])
    # Code scanning alerts
    scan_url = f"https://api.github.com/repos/{repo}/code-scanning/alerts"
    scan_resp = requests.get(scan_url, headers=headers)
    if scan_resp.status_code == 200:
        alerts = scan_resp.json()
        if isinstance(alerts, list) and len(alerts) > 0:
            score -= 10
            table.append(["Code Scanning Alerts", f"{len(alerts)} open", "-10"])
        else:
            table.append(["Code Scanning Alerts", "0 open", "0"])
    else:
        table.append(["Code Scanning Alerts", "N/A", "0"])
    # Manually draw ASCII grid for table alignment
    headers_row = ["Criteria", "Status", "Score Impact"]
    rows = [headers_row] + table
    col_widths = [max(len(str(row[i])) for row in rows) for i in range(3)]
    def draw_line():
        return "+" + "+".join(["-" * (w + 2) for w in col_widths]) + "+"
    def draw_row(row):
        return "| " + " | ".join(str(row[i]).ljust(col_widths[i]) for i in range(3)) + " |"
    print(draw_line())
    print(draw_row(headers_row))
    print(draw_line())
    for row in table:
        print(draw_row(row))
        print(draw_line())
    Print.star(f"Security Score: {score}/100")
    if score >= 90:
        Print.success("Excellent security hygiene!")
    elif score >= 75:
        Print.info("Good, but can be improved.")
    else:
        Print.warn("Security posture is weak! Review the issues above.")

def cmd_commit_anomaly(args):
    if not args.repo:
        Print.error("Missing required argument: <owner/repo>")
        print("\nUsage: exc commit-anomaly <owner/repo>")
        print("Example: exc commit-anomaly torvalds/linux")
        print("\nAnalyzes commit messages and PRs for suspicious or risky activity.")
        return
    headers = get_auth_header()
    repo = args.repo.strip()
    Print.info(f"Analyzing commit/PR activity for: {repo}")
    url = f"https://api.github.com/repos/{repo}/commits?per_page=30"
    commits, _ = api_get(url, headers)
    risky = []
    SUSPICIOUS = ["fix bug", "temp", "test", "remove security", "debug", "hack", "bypass", "password", "secret"]
    for c in commits:
        msg = c['commit']['message'].lower()
        if any(word in msg for word in SUSPICIOUS):
            risky.append([c['sha'][:7], msg[:40], c['commit']['author']['date']])
    if risky:
        print_table(risky, headers=["SHA", "Message", "Date"])
    else:
        Print.success("No suspicious commit messages found.")

def cmd_user_anomaly(args):
    if not args.username:
        Print.error("Missing required argument: <github_username>")
        print("\nUsage: exc user-anomaly <github_username>")
        print("Example: exc user-anomaly octocat")
        print("\nDetects unusual activity or anomalies in a user's GitHub activity.")
        return
    headers = get_auth_header()
    user = args.username.strip()
    Print.info(f"Checking user activity for: {user}")
    url = f"https://api.github.com/users/{user}/events/public?per_page=30"
    events, _ = api_get(url, headers)
    hours = [int(e['created_at'][11:13]) for e in events if 'created_at' in e]
    if not hours:
        Print.warn("No recent activity found.")
        return
    from collections import Counter
    hour_counts = Counter(hours)
    most_common = hour_counts.most_common(1)[0]
    if most_common[1] > 10:
        Print.warn(f"Unusual activity: {most_common[1]} events at hour {most_common[0]}")
    else:
        Print.success("No unusual activity detected.")

def cmd_content_audit(args):
    if not args.repo:
        Print.error("Missing required argument: <owner/repo>")
        print("\nUsage: exc content-audit <owner/repo>")
        print("Example: exc content-audit torvalds/linux")
        print("\nAudits repository for license, security.md, code of conduct, contributing.md, and documentation quality.")
        return
    headers = get_auth_header()
    repo = args.repo.strip()
    Print.info(f"Auditing repo content: {repo}")
    files = [
        ("LICENSE", "License file"),
        ("SECURITY.md", "Security policy"),
        ("CODE_OF_CONDUCT.md", "Code of Conduct"),
        ("CONTRIBUTING.md", "Contributing Guide"),
        ("README.md", "README")
    ]
    table = []
    for fname, desc in files:
        url = f"https://api.github.com/repos/{repo}/contents/{fname}"
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            content = resp.json().get('content', '')
            if content:
                # Quality check: line count and keywords
                import base64
                try:
                    decoded = base64.b64decode(content).decode(errors='ignore')
                except Exception:
                    decoded = ''
                lines = decoded.count('\n')
                if lines < 5:
                    table.append([desc, fname, '✔ Present', '⚠️ Too short'])
                elif fname == 'README.md' and len(decoded) < 100:
                    table.append([desc, fname, '✔ Present', '⚠️ Too short'])
                else:
                    table.append([desc, fname, '✔ Present', 'OK'])
            else:
                table.append([desc, fname, '✔ Present', '⚠️ Empty'])
        else:
            table.append([desc, fname, '❌ Missing', '-'])
    print_table(table, headers=["Type", "File", "Status", "Quality"])
    missing = [row for row in table if row[2] == '❌ Missing']
    if missing:
        Print.warn(f"Missing: {', '.join(row[1] for row in missing)}")
    else:
        Print.success("All key content files are present!")

def cmd_actions_audit(args):
    if not args.repo:
        Print.error("Missing required argument: <owner/repo>")
        print("\nUsage: exc actions-audit <owner/repo>")
        print("Example: exc actions-audit torvalds/linux")
        print("\nAnalyzes .github/workflows CI files for security risks and best practices.")
        return
    headers = get_auth_header()
    repo = args.repo.strip()
    Print.info(f"Auditing GitHub Actions workflows in: {repo}")
    url = f"https://api.github.com/repos/{repo}/contents/.github/workflows"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        Print.warn("No workflows found.")
        return
    workflows = resp.json()
    table = []
    max_name = 32
    max_url = 40
    for wf in workflows:
        wf_url = wf.get('download_url')
        name = wf.get('name') or wf.get('path')
        # Short display
        short_name = (name[:max_name-3] + '...') if len(name) > max_name else name
        short_url = (wf_url[:max_url-3] + '...') if wf_url and len(wf_url) > max_url else wf_url
        try:
            content = requests.get(wf_url, timeout=8).text
            risky = bool(re.search(r'(curl|wget|bash|sh|powershell|python|node)', content, re.I))
            secrets = bool(re.search(r'secret', content, re.I))
            uses_latest = bool(re.search(r'@latest', content, re.I))
            if risky:
                table.append([short_name, short_url, '⚠️ Risky script', 'Check for shell/code exec'])
            elif uses_latest:
                table.append([short_name, short_url, '⚠️ Uses @latest', 'Pin versions'])
            elif secrets:
                table.append([short_name, short_url, '⚠️ Uses secrets', 'Review secret usage'])
            else:
                table.append([short_name, short_url, 'OK', 'No obvious risk'])
        except Exception:
            table.append([short_name, short_url, 'Error', 'Could not fetch'])
    # Shorten table headers as well
    headers_row = ["Workflow", "URL", "Status", "Note"]
    col_widths = [max(len(str(row[i])) for row in ([headers_row]+table)) for i in range(4)]
    def draw_line():
        return "+" + "+".join(["-" * (w + 2) for w in col_widths]) + "+"
    def draw_row(row):
        return "| " + " | ".join(str(row[i]).ljust(col_widths[i]) for i in range(4)) + " |"
    print(draw_line())
    print(draw_row(headers_row))
    print(draw_line())
    for row in table:
        print(draw_row(row))
        print(draw_line())
    risky_count = sum(1 for row in table if '⚠️' in row[2])
    if risky_count:
        Print.warn(f"{risky_count} workflow(s) need review!")
    else:
        Print.success("No risky workflows detected.")

# ---------------------
# Main Program
# ---------------------

class SilentArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # Extract attempted command from message
        words = message.split()
        attempted = None
        if 'invalid choice:' in message:
            try:
                attempted = message.split('invalid choice:')[1].split('(')[0].strip().strip("'")
            except Exception:
                attempted = None
        # List of valid commands and their aliases
        commands = {
            'key': ['k', 'kei', 'kee', 'ky', 'kk', 'keey', 'keyy', 'ket', 'keu', 'keg', 'ker'],
            'user-a': ['u', 'user', 'usera', 'user-audit', 'usr', 'userr', 'usra', 'usr-a'],
            'analysis': ['a', 'ana', 'analys', 'analyzis', 'analiz', 'anlys', 'anyl', 'anali', 'analy'],
            'scan-secrets': ['scan', 'secrets', 'scn', 'scret', 'scrt', 'ss', 's-scan', 'scretscan', 'secscan'],
            'file-history': ['file', 'fileh', 'flhist', 'histfile', 'fh', 'filehist', 'filehis', 'f-history'],
            'dork-scan': ['dork', 'dorkscan', 'drk', 'ds', 'dscan', 'dorks', 'd-sc'],
            'advanced-secrets': ['advsec', 'advsecrets', 'advscrt', 'as', 'adv-s', 'advs', 'advsercet'],
            'security-score': ['secscore', 'sscore', 'sec-score', 'securiscore', 'securityscor', 'ssec', 'securscore'],
            'commit-anomaly': ['commanom', 'commitanom', 'c-anom', 'c-anomaly', 'ca', 'cm-anom', 'comm-anom'],
            'user-anomaly': ['useranom', 'usranom', 'u-anom', 'user-anom', 'ua', 'useranomaly'],
            'content-audit': ['audit', 'contentaudit', 'cntaudit', 'caudit', 'cnt-aud', 'cont-audit'],
            'actions-audit': ['workflow-audit', 'waudit', 'actaudit', 'actionaudit', 'wf-audit', 'wkaudit']
        }
        all_cmds = list(commands.keys()) + [alias for v in commands.values() for alias in v]
        suggestion = None
        if attempted:
            attempted_lower = attempted.lower()
            # Find closest match (case-insensitive)
            matches = difflib.get_close_matches(attempted_lower, all_cmds, n=1, cutoff=0.5)
            if matches:
                # Map alias to main command if needed
                for main, aliases in commands.items():
                    if matches[0] == main or matches[0] in aliases:
                        suggestion = main
                        break
        print(f"\033[91m[!] Invalid command or argument!\033[0m")
        if suggestion:
            print(f"\033[93m[?] Did you mean: exc {suggestion}\033[0m")
        print(f"\033[93m[*] For correct usage, see: exc --help or exc <module> --help\033[0m")
        sys.exit(2)

def print_custom_help():
    cyan = '96' if COLOR_ENABLED else None
    yellow = '93' if COLOR_ENABLED else None
    bold = '1' if COLOR_ENABLED else None
    def c(text, code):
        return colorize(text, code) if code else text
    print("""
┏━━━━[ EXC ANALYZER ]━━━━┓
┃ github.com/exc-analyzer┃
┗━━━━━━━━━━━━━━━━━━━━━━━━┛
""")
    print("Common Usage:")
    print(c("  exc key {your_api_key}                ", cyan) + c("# Manage GitHub API key", yellow))
    print(c("  exc analysis <owner/repo>             ", cyan) + c("# Analyze a repository", yellow))
    print(c("  exc scan-secrets <owner/repo>         ", cyan) + c("# Scan for leaked secrets", yellow))
    print(c("  exc file-history <owner/repo> <file>  ", cyan) + c("# Show file change history", yellow))
    print(c("  exc user-a <username>                 ", cyan) + c("# Analyze a GitHub user", yellow))
    print("")
    print("Security & Intelligence:")
    print(c("  exc dork-scan <dork_query>            ", cyan) + c("# GitHub dorking for secrets/configs", yellow))
    print(c("  exc advanced-secrets <owner/repo>     ", cyan) + c("# Advanced secret/config scan", yellow))
    print(c("  exc security-score <owner/repo>       ", cyan) + c("# Repo security scoring", yellow))
    print(c("  exc commit-anomaly <owner/repo>       ", cyan) + c("# Commit/PR anomaly detection", yellow))
    print(c("  exc user-anomaly <username>           ", cyan) + c("# User activity anomaly detection", yellow))
    print(c("  exc content-audit <owner/repo>        ", cyan) + c("# Audit repo content/docs", yellow))
    print(c("  exc actions-audit <owner/repo>        ", cyan) + c("# Audit GitHub Actions/CI security", yellow))
    print("")
    print("General Options:")
    print(c("  --version  (-v)    Show version & update info", cyan))
    print(c("  --verbose  (-V)    Verbose/debug output", cyan))
    print(c("  --reset    (-r)    API Key Reset", cyan))
    print("")
    print(c("For detailed help: exc <command> --help", yellow))
    print("")
    sys.exit(0)

def main():
    global VERBOSE
    notify_new_version()  # Notify only if a new version is available
    # Version & verbose flags
    if "--version" in sys.argv or "-v" in sys.argv:
        print(f"EXC Analyzer v{__version__}")
        check_latest_version()
        sys.exit(0)
    if "--verbose" in sys.argv or "-V" in sys.argv:
        VERBOSE = True
        Print.warn("Verbose mode enabled.")
        # Remove so argparse doesn't complain
        sys.argv = [a for a in sys.argv if a not in ["--verbose", "-V"]]
    parser = SilentArgumentParser(
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
        description="Manage GitHub API keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    key_parser.add_argument("key", nargs="?", help=argparse.SUPPRESS)
    key_parser.add_argument("-r", "--reset", action="store_true", help=argparse.SUPPRESS)
    key_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def key_help(args):
        print("""
\033[96mUsage: exc key [API_KEY] [-r|--reset]\033[0m

Manage your GitHub API key securely.

\033[93mExamples:\033[0m
  exc key                # Securely input and save your API key
  exc key --reset        # Delete the stored API key

If you run 'exc key' without an argument, you will be prompted to enter your key securely (input is hidden).
""")
        sys.exit(0)
    key_parser.set_defaults(func=cmd_key, help_func=key_help)

    # Analysis command
    analysis_parser = subparsers.add_parser(
        "analysis",
        description="Repository analysis: code, security, dependencies, stats.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    analysis_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    analysis_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def analysis_help(args):
        print("""
\033[96mUsage: exc analysis <owner/repo>\033[0m

Performs a detailed analysis of a GitHub repository: code quality, security, dependencies, and statistics.

\033[93mExample:\033[0m
  exc analysis torvalds/linux
""")
        sys.exit(0)
    analysis_parser.set_defaults(func=cmd_analysis, help_func=analysis_help)

    # User analysis command
    user_parser = subparsers.add_parser(
        "user-a",
        description="Analyze a GitHub user's profile and repositories.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    user_parser.add_argument("username", nargs="?", help=argparse.SUPPRESS)
    user_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def user_help(args):
        print("""
\033[96mUsage: exc user-a <github_username>\033[0m

Analyzes a user's contribution profile: commit patterns, code ownership, and top repositories.

\033[93mExample:\033[0m
  exc user-a octocat
""")
        sys.exit(0)
    user_parser.set_defaults(func=cmd_user_a, help_func=user_help)

    # Scan secrets command
    scan_parser = subparsers.add_parser(
        "scan-secrets",
        description="Scan recent commits for leaked secrets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    scan_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    scan_parser.add_argument("-l", "--limit", type=int, default=10, help="Number of recent commits to scan (default: 10)")
    scan_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def scan_help(args):
        print("""
\033[96mUsage: exc scan-secrets <owner/repo> [-l N]\033[0m

Scans the last N commits (default 10) for secrets like API keys, AWS credentials, SSH keys, and tokens.

\033[93mExample:\033[0m
  exc scan-secrets torvalds/linux -l 50

\033[93mOptions:\033[0m
  -l, --limit   Number of recent commits to scan (default: 10)
""")
        sys.exit(0)
    scan_parser.set_defaults(func=cmd_scan_secrets, help_func=scan_help)

    # File history command
    file_parser = subparsers.add_parser(
        "file-history",
        description="Show the change history of a file in a repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    file_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    file_parser.add_argument("filepath", nargs="?", help=argparse.SUPPRESS)
    file_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def file_help(args):
        print("""
\033[96mUsage: exc file-history <owner/repo> <path_to_file>\033[0m

Displays the full change history of a specific file (commit, author, date, message).

\033[93mExample:\033[0m
  exc file-history torvalds/linux kernel/sched/core.c
""")
        sys.exit(0)
    file_parser.set_defaults(func=cmd_file_history, help_func=file_help)

    # Dork scan command
    dork_parser = subparsers.add_parser(
        "dork-scan",
        description="Scan GitHub for sensitive keywords or patterns (dorking).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    dork_parser.add_argument("query", nargs="*", help=argparse.SUPPRESS)
    dork_parser.add_argument("-n", "--num", type=int, default=10, help="Number of results to show (max 100)")
    dork_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def dork_help(args):
        print("""
\033[96mUsage: exc dork-scan <dork_query> [options]\033[0m

Scan public GitHub code for sensitive keywords, secrets, or configuration files using advanced dorking techniques.

\033[93mExamples:\033[0m
  exc dork-scan brgkdm

\033[93mOptions:\033[0m
  <dork_query>         The search query (can be multiple words, quoted if needed)
  -n, --num N          Number of results to show (default: 10, max: 100)
  -h, --help           Show this help message and exit

\033[93mDescription:\033[0m
  This command allows you to search public GitHub repositories for exposed secrets, API keys, tokens, or sensitive files
  using custom search queries (dorks). You can combine keywords, file extensions, and filename filters for more precise results.

\033[93mTips:\033[0m
  - Use quotes for multi-word queries (e.g. "sensitive key")
  - Results include repository, file path, and direct link to the file on GitHub

\033[96mFor more info: https://github.com/exc-analyzer/exc\033[0m
""")
        sys.exit(0)
    dork_parser.set_defaults(func=cmd_dork_scan, help_func=dork_help)

    # Advanced secrets command
    advsec_parser = subparsers.add_parser(
        "advanced-secrets",
        description="Scan repo for a wide range of secret patterns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    advsec_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    advsec_parser.add_argument("-l", "--limit", type=int, default=20, help="Number of recent commits to scan (default: 20)")
    advsec_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def advsec_help(args):
        print("""
\033[96mUsage: exc advanced-secrets <owner/repo> [-l N]\033[0m

Scans repository files and the last N commits for a wide range of secret patterns (API keys, tokens, config files, etc.).

\033[93mOptions:\033[0m
  -l, --limit   Number of recent commits to scan (default: 20)

\033[93mExample:\033[0m
  exc advanced-secrets torvalds/linux -l 30
""")
        sys.exit(0)
    advsec_parser.set_defaults(func=cmd_advanced_secrets, help_func=advsec_help)

    # Security score command
    secscore_parser = subparsers.add_parser(
        "security-score",
        description="Calculate a security score for the repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    secscore_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    secscore_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def secscore_help(args):
        print("""
\033[96mUsage: exc security-score <owner/repo>\033[0m

Calculates a security score for the repository based on open issues, branch protection, security.md, license, dependabot, code scanning, and more.

\033[93mExample:\033[0m
  exc security-score torvalds/linux
""")
        sys.exit(0)
    secscore_parser.set_defaults(func=cmd_security_score, help_func=secscore_help)

    # Commit anomaly command
    commanom_parser = subparsers.add_parser(
        "commit-anomaly",
        description="Analyze commit/PR activity for anomalies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    commanom_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    commanom_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def commanom_help(args):
        print("""
\033[96mUsage: exc commit-anomaly <owner/repo>\033[0m

Analyzes commit messages and PRs for suspicious or risky activity.

\033[93mExample:\033[0m
  exc commit-anomaly torvalds/linux
""")
        sys.exit(0)
    commanom_parser.set_defaults(func=cmd_commit_anomaly, help_func=commanom_help)

    # User anomaly command
    useranom_parser = subparsers.add_parser(
        "user-anomaly",
        description="Detect unusual activity in a user's GitHub activity.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    useranom_parser.add_argument("username", nargs="?", help=argparse.SUPPRESS)
    useranom_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def useranom_help(args):
        print("""
\033[96mUsage: exc user-anomaly <github_username>\033[0m

Detects unusual activity or anomalies in a user's GitHub activity.

\033[93mExample:\033[0m
  exc user-anomaly octocat
""")
        sys.exit(0)
    useranom_parser.set_defaults(func=cmd_user_anomaly, help_func=useranom_help)

    # Content audit command
    content_parser = subparsers.add_parser(
        "content-audit",
        description="Audit repo for license, security.md, docs, etc.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    content_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    content_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def content_help(args):
        print("""
\033[96mUsage: exc content-audit <owner/repo>\033[0m

Audits the repository for license, security.md, code of conduct, contributing.md, and documentation quality.

\033[93mExample:\033[0m
  exc content-audit torvalds/linux
""")
        sys.exit(0)
    content_parser.set_defaults(func=cmd_content_audit, help_func=content_help)

    # Actions audit command
    actions_parser = subparsers.add_parser(
        "actions-audit",
        description="Audit GitHub Actions/CI workflows for security.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    actions_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    actions_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def actions_help(args):
        print("""
\033[96mUsage: exc actions-audit <owner/repo>\033[0m

Analyzes GitHub Actions/CI workflow files for security risks and best practices.

\033[93mExample:\033[0m
  exc actions-audit torvalds/linux
""")
        sys.exit(0)
    actions_parser.set_defaults(func=cmd_actions_audit, help_func=actions_help)

    # Help flag
    parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)

    try:
        if len(sys.argv) > 1:
            sys.argv[1] = sys.argv[1].lower()
        args, unknown = parser.parse_known_args()
    except SystemExit:
        return

    # Special help control for commands
    if hasattr(args, 'help') and args.help:
        if hasattr(args, 'help_func'):
            args.help_func(args)
        else:
            print_custom_help()
    if args.command == "dork-scan" and not args.query:
        print_custom_help()
    # Execute the command function
    if hasattr(args, 'func'):
        try:
            args.func(args)
        except Exception as e:
            Print.error(f"Error executing command: {e}")
            log(f"Command error: {e}")
            sys.exit(1)
    else:
        print_custom_help()

if __name__ == "__main__":
    setup_linux_desktop_shortcut()
    main()