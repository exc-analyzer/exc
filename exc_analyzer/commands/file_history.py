from datetime import datetime
from ..print_utils import Print, _write_output, safe_print
from ..api import api_get, get_auth_header
from ..spinner import spinner
from ..i18n import t


def _format_commit_date(commit_data):
    try:
        raw_date = commit_data['author']['date']
        dt = datetime.strptime(raw_date, "%Y-%m-%dT%H:%M:%SZ")
        return dt.strftime("%Y-%m-%d")
    except (KeyError, TypeError, ValueError):
        raw_date = str(commit_data.get('author', {}).get('date', ''))
        return raw_date[:10] if raw_date else "-"


def _search_file_in_repo(repo, filename, headers):
    """
    Search for a file in the repository using GitHub Code Search API.
    Returns the full path if found, otherwise None.
    """
    search_url = f"https://api.github.com/search/code?q=filename:{filename}+repo:{repo}"
    try:
        result, _ = api_get(search_url, headers)
        if result and isinstance(result, dict) and result.get('total_count', 0) > 0:
            items = result.get('items', [])
            if items:
                return items[0].get('path')
    except Exception as e:
        from ..logging_utils import log
        log(f"File search in repo failed: {e}")
    return None


def cmd_file_history(args):
    if not args.repo or not args.filepath:
        Print.error(t("commands.shared.missing_args"))
        _write_output(f"\n{t('commands.file_history.usage')}")
        return
    headers = get_auth_header()
    repo = args.repo.strip()
    if "/" not in repo or len(repo.split("/")) != 2:
        print()
        _write_output("")
        Print.error(t("commands.shared.invalid_repo_format"))
        print()
        return
    filepath = args.filepath.strip()
    if "/" not in filepath:
        with spinner(t("commands.file_history.searching", filename=filepath, repo=repo), color='96'):
            found_path = _search_file_in_repo(repo, filepath, headers)
        if found_path:
            filepath = found_path
            safe_print("")
            Print.info(t("commands.file_history.found_at", path=filepath))
        else:
            safe_print("")
            Print.error(t("commands.file_history.not_found", filename=filepath))
            safe_print("")
            return
    limit = args.limit
    if limit > 50:
        safe_print("")
        Print.error(t("commands.file_history.limit_exceeded", requested=limit, max=50))
        safe_print("")
        return
    safe_print("")
    with spinner(t("commands.file_history.header", filepath=filepath, repo=repo), color='96'):
        commits_url = f"https://api.github.com/repos/{repo}/commits?path={filepath}&per_page={limit}"
        commits_raw, _ = api_get(commits_url, headers)
    commits = commits_raw if isinstance(commits_raw, list) else []
    commits = commits[:limit]
    from ..helpers import TablePrinter
    columns = [
        {'header': t("commands.file_history.table_header.sha"), 'width': 7, 'color': '96'},     
        {'header': t("commands.file_history.table_header.date"), 'width': 10, 'color': '93'},   
        {'header': t("commands.file_history.table_header.author"), 'width': 18, 'color': '92'}, 
        {'header': t("commands.file_history.table_header.message"), 'width': None, 'color': '97'} 
    ]
    printer = TablePrinter(columns)
    printer.print_header()
    for idx, commit in enumerate(commits):
        commit_data = commit['commit']
        style = "2;" if idx % 2 == 1 else ""
        sha_val = commit['sha'][:7]
        date_val = _format_commit_date(commit_data)
        author_val = commit_data['author']['name']
        raw_msg = commit_data['message'].splitlines()[0]
        printer.print_row([sha_val, date_val, author_val, raw_msg], style_prefix=style)
    safe_print("")
    footer_msg = t("commands.file_history.footer", count=len(commits))
    safe_print(Print.colorize(footer_msg, '92'))
    safe_print("")
    _write_output(f"\n{footer_msg}")
