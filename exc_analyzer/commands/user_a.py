# user_a.py
from ..print_utils import Print
from ..api import api_get, get_auth_header, get_all_pages

def cmd_user_a(args):
    if not args.username:
        Print.error("Owner Missing.")
        Print.info("\nUsage: exc user-a <github_username>")
        return
    
    headers = get_auth_header()
    user = args.username.strip()
    
    print("")

    # User info
    user_url = f"https://api.github.com/users/{user}"
    user_data, _ = api_get(user_url, headers)
    def print_colored_info(label, value, use_light=True):
        color = "\033[97m" if use_light else "\033[90m"
        reset = "\033[0m"
        print(f"{color}{label:<17}: {value}{reset}")

    Print.success("User Information")

    user_info = [
    ("Name",            user_data.get('name')),
    ("Username",        user_data.get('login')),
    ("Bio",             user_data.get('bio')),
    ("Location",        user_data.get('location')),
    ("Company",         user_data.get('company')),
    ("Account created", user_data.get('created_at')),
    ("Followers",       user_data.get('followers')),
    ("Following",       user_data.get('following')),
    ("Public repos",    user_data.get('public_repos')),
    ("Public gists",    user_data.get('public_gists')),
]

    for i, (label, value) in enumerate(user_info):
        print_colored_info(label, value, use_light=(i % 2 == 0))

    # User repos
    repos_url = f"https://api.github.com/users/{user}/repos"
    repos = get_all_pages(repos_url, headers)

    def print_bw_repo(index, repo, use_white=True):
        color = "\033[97m" if use_white else "\033[90m"
        reset = "\033[0m"
        name = repo.get('name')
        stars = repo.get('stargazers_count', 0)
        print(f"{color}{index+1:>2}. * {stars:<4} - {name}{reset}")

    print("")
    Print.success("User's Top Starred Repositories:")

    repos_sorted = sorted(repos, key=lambda r: r.get('stargazers_count', 0), reverse=True)

    for i, repo in enumerate(repos_sorted[:5]):
        print_bw_repo(i, repo, use_white=(i % 2 == 0))

    print("")
    Print.info(f"Completed.")
    print("")
