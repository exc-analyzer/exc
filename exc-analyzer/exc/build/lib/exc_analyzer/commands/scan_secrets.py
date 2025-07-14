# scan_secrets.py
import requests
import re
from ..print_utils import Print
from ..api import api_get, get_auth_header

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
