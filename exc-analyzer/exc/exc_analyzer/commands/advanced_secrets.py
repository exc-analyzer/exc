# advanced_secrets.py
import requests
import re
from ..print_utils import Print
from ..api import api_get, get_auth_header
from ..helpers import print_table

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
