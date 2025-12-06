# user_a.py
from ..print_utils import Print
from ..api import api_get, get_auth_header, get_all_pages
from ..i18n import t

def cmd_user_a(args):
    if not args.username:
        Print.error(t("commands.user_a.missing_username"))
        Print.info(t("commands.user_a.usage"))
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

    Print.success(t("commands.user_a.sections.user_info"))

    user_info = [
        (t("commands.user_a.labels.name"), user_data.get('name')),
        (t("commands.user_a.labels.username"), user_data.get('login')),
        (t("commands.user_a.labels.bio"), user_data.get('bio')),
        (t("commands.user_a.labels.location"), user_data.get('location')),
        (t("commands.user_a.labels.company"), user_data.get('company')),
        (t("commands.user_a.labels.account_created"), user_data.get('created_at')),
        (t("commands.user_a.labels.followers"), user_data.get('followers')),
        (t("commands.user_a.labels.following"), user_data.get('following')),
        (t("commands.user_a.labels.public_repos"), user_data.get('public_repos')),
        (t("commands.user_a.labels.public_gists"), user_data.get('public_gists')),
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
    Print.success(t("commands.user_a.sections.top_repos"))

    repos_sorted = sorted(repos, key=lambda r: r.get('stargazers_count', 0), reverse=True)

    for i, repo in enumerate(repos_sorted[:5]):
        print_bw_repo(i, repo, use_white=(i % 2 == 0))

    print("")
    Print.info(t("commands.user_a.completed"))
    print("")
