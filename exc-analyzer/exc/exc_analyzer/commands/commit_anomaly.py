# commit_anomaly.py
from ..print_utils import Print
from ..api import api_get, get_auth_header
from ..helpers import print_table

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
