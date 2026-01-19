"""Optimized user analysis with async concurrent requests."""
import asyncio
import asyncio
from ..print_utils import print_success, print_info, print_error, print_cancelled, safe_print, _write_output
from ..async_api import create_async_context
from ..i18n import t
from ..config import load_key
async def _analyze_user_async(user: str, token: str, show_rate_limit: bool = False):
    """Async user analysis with concurrent requests."""
    from ..spinner import spinner
    async with create_async_context(token) as client:
        try:
            safe_print("")
            _write_output("")
            with spinner(t("commands.user_a.sections.user_info"), color='96'):
                user_url = f"https://api.github.com/users/{user}"
                repos_url = f"https://api.github.com/users/{user}/repos"
                user_data, repos = await asyncio.gather(
                    client.fetch_json(user_url),
                    client.fetch_paginated(repos_url, per_page=100)
                )
            def print_colored_info(label, value, use_light=True):
                color = "\033[97m" if use_light else "\033[90m"
                reset = "\033[0m"
                output = f"{color}{label:<17}: {value}{reset}"
                safe_print(output)
                _write_output(f"{label:<17}: {value}")
            def print_plus(msg):
                """Print message with [+] prefix in green."""
                from ..print_utils import Print
                safe_print(Print.colorize(f"[+] {msg}", '92'))
                _write_output(f"[+] {msg}")
            print_plus(t("commands.user_a.sections.user_info"))
            def _v(val):
                return val if val else t("commands.shared.none_value")
            from ..helpers import format_friendly_date
            user_info = [
                (t("commands.user_a.labels.name"), _v(user_data.get('name'))),
                (t("commands.user_a.labels.username"), _v(user_data.get('login'))),
                (t("commands.user_a.labels.bio"), _v(user_data.get('bio'))),
                (t("commands.user_a.labels.location"), _v(user_data.get('location'))),
                (t("commands.user_a.labels.company"), _v(user_data.get('company'))),
                (t("commands.user_a.labels.account_created"), format_friendly_date(_v(user_data.get('created_at')), include_relative=True)),
                (t("commands.user_a.labels.followers"), user_data.get('followers')),  
                (t("commands.user_a.labels.following"), user_data.get('following')),  
                (t("commands.user_a.labels.public_repos"), user_data.get('public_repos')), 
                (t("commands.user_a.labels.public_gists"), user_data.get('public_gists')), 
            ]
            for i, (label, value) in enumerate(user_info):
                print_colored_info(label, value, use_light=(i % 2 == 0))
            def print_bw_repo(index, repo, use_white=True):
                color = "\033[97m" if use_white else "\033[90m"
                reset = "\033[0m"
                name = repo.get('name')
                stars = repo.get('stargazers_count', 0)
                output = f"{color}{index+1:>2}. * {stars:<4} - {name}{reset}"
                safe_print(output)
                _write_output(f"{index+1:>2}. * {stars:<4} - {name}")
            safe_print("")
            _write_output("")
            print_plus(t("commands.user_a.sections.top_repos"))
            repos_sorted = sorted(repos, key=lambda r: r.get('stargazers_count', 0), reverse=True)
            for i, repo in enumerate(repos_sorted[:5]):
                print_bw_repo(i, repo, use_white=(i % 2 == 0))
            safe_print("")
            _write_output("")
            print_plus(t("commands.user_a.completed"))
            safe_print("")
            _write_output("")
            if show_rate_limit:
                print_info(client.get_quota_info())
                safe_print("")
                _write_output("")
        except Exception as e:
            print_error(f"Analysis failed: {str(e)}")
def cmd_user_a(args):
    """User analysis command - optimized with async concurrent requests."""
    from ..print_utils import _write_output
    if not args.username:
        print_error(t("commands.user_a.missing_username"))
        print_info(t("commands.user_a.usage"))
        return
    user = args.username.strip()
    token = load_key()
    if not token:
        safe_print("")
        _write_output("")
        print_error(t("commands.shared.api_key_missing"))
        print_info(t("commands.shared.use_key_cmd"))
        safe_print("")
        _write_output("")
        return
    try:
        show_rate = getattr(args, 'show_rate_limit', False)
        asyncio.run(_analyze_user_async(user, token, show_rate))
    except KeyboardInterrupt:
        safe_print("")
        _write_output("")
        print_cancelled(t("commands.shared.scan_cancelled"))
    except Exception as e:
        print_error(t("commands.shared.error_occurred", error=str(e)))
