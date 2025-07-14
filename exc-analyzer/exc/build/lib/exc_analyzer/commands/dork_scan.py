# dork_scan.py
from urllib.parse import quote
from ..print_utils import Print
from ..api import api_get, get_auth_header

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
