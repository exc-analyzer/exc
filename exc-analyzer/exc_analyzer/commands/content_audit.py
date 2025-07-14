# content_audit.py
import requests
import base64
from ..print_utils import Print
from ..api import get_auth_header
from ..helpers import print_table

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
