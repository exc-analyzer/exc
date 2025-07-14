# file_history.py
import requests
from ..print_utils import Print
from ..api import api_get, get_auth_header, get_all_pages

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
