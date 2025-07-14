# security_score.py
import requests
from ..print_utils import Print
from ..api import api_get, get_auth_header

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
    Print.action(f"Security Score: {score}/100")
    if score >= 90:
        Print.success("Excellent security hygiene!")
    elif score >= 75:
        Print.info("Good, but can be improved.")
    else:
        Print.warn("Security posture is weak! Review the issues above.")
