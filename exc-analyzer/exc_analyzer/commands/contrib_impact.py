# contrib_impact.py
import requests
from ..print_utils import Print
from ..api import get_auth_header, get_all_pages

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
