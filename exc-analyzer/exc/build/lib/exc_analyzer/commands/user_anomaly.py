# user_anomaly.py
from ..print_utils import Print
from ..api import api_get, get_auth_header
from collections import Counter

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
