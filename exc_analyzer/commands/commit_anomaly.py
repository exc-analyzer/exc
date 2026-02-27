"""Commit anomaly detection with improved visual output."""
from ..print_utils import Print, _write_output, safe_print
from ..api import api_get, get_auth_header
from ..helpers import format_friendly_date
from ..spinner import spinner
from ..i18n import t
def cmd_commit_anomaly(args):
    if not args.repo:
        Print.error(t("commands.shared.missing_repo", default="Missing required argument: <owner/repo>"))
        _write_output(f"\n{t('commands.commit_anomaly.usage')}")
        return
    headers = get_auth_header()
    repo = args.repo.strip()
    if "/" not in repo or len(repo.split("/")) != 2:
        print()
        _write_output("")
        Print.error(t("commands.shared.invalid_repo_format"))
        print()
        return
    with spinner(t("commands.commit_anomaly.analyzing", repo=repo), color='96'):
        url = f"https://api.github.com/repos/{repo}/commits?per_page=30"
        commits, _ = api_get(url, headers)
    print()
    _write_output("")
    risky = []
    SUSPICIOUS = ["fix bug", "temp", "test", "remove security", "debug", "hack", "bypass", "password", "secret"]
    for c in commits:
        msg = c['commit']['message'].lower()
        original_msg = c['commit']['message']
        matched_words = [word for word in SUSPICIOUS if word in msg]
        if matched_words:
            c_date = format_friendly_date(c['commit']['author']['date'], include_relative=True)
            author = c['commit']['author']['name']
            sha = c['sha'][:7]
            risky.append({
                'sha': sha,
                'message': original_msg,
                'author': author,
                'date': c_date,
                'matched': matched_words
            })
    _print_anomalies(repo, risky)
def _print_anomalies(repo, risky):
    """Print commit anomalies in a visual, user-friendly format."""
    safe_print("")
    _write_output("")
    sep = "═" * 60
    safe_print(Print.colorize(sep, '96'))
    _write_output(sep)
    header_text = f"  {t('commands.commit_anomaly.header')}: {repo}"
    safe_print(Print.colorize(header_text, '97'))
    _write_output(header_text)
    safe_print(Print.colorize(sep, '96'))
    _write_output(sep)
    safe_print("")
    _write_output("")
    if not risky:
        msg = f"  [OK] {t('commands.commit_anomaly.none_found')}"
        safe_print(Print.colorize(msg, '92'))
        _write_output(msg)
        safe_print("")
        _write_output("")
        sep = "═" * 60
        safe_print(Print.colorize(sep, '96'))
        _write_output(sep)
        safe_print("")
        _write_output("")
        return
    count_text = t("commands.commit_anomaly.found_count", count=len(risky))
    safe_print(Print.colorize(f"  [!] {count_text}", '93'))
    _write_output(f"  [!] {count_text}")
    safe_print("")
    _write_output("")
    for i, commit in enumerate(risky, 1):
        commit_header = f"  [{i}] Commit: {commit['sha']}"
        safe_print(Print.colorize(commit_header, '93'))
        _write_output(commit_header)
        msg_lines = commit['message'].split('\n')
        msg_first = msg_lines[0]
        if len(msg_first) > 65:
            msg_first = msg_first[:62] + "..."
        msg_line = f"      Message: {msg_first}"
        safe_print(Print.colorize(msg_line, '97'))
        _write_output(msg_line)
        author_line = f"      Author:  {commit['author']}"
        safe_print(Print.colorize(author_line, '96'))
        _write_output(author_line)
        date_line = f"      Date:    {commit['date']}"
        safe_print(Print.colorize(date_line, '96'))
        _write_output(date_line)
        keywords = ", ".join(commit['matched'])
        keywords_line = f"      {t('commands.commit_anomaly.keywords')}: {keywords}"
        safe_print(Print.colorize(keywords_line, '91'))
        _write_output(keywords_line)
        if i < len(risky):
            safe_print("")
            _write_output("")
    safe_print("")
    _write_output("")
    safe_print(Print.colorize(sep, '96'))
    _write_output(sep)
    safe_print("")
    _write_output("")
