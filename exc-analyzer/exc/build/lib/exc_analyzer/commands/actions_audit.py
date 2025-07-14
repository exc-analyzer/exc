# actions_audit.py
import requests
import re
from ..print_utils import Print
from ..api import get_auth_header

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
