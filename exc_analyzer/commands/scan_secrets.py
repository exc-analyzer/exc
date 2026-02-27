"""Optimized secret scanning with concurrent file processing."""
import asyncio
import re
from ..print_utils import print_info, print_warning, print_error, print_success, print_cancelled, safe_print
from ..async_api import create_async_context
from ..config import load_key
from ..i18n import t
SECRET_PATTERNS = {
    'AWS Key': r'AKIA[0-9A-Z]{16}',
    'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
    'SSH Private': r'-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----',
    'API Key': r'(?i)(api|access)[_ -]?key["\']?[:=] ?["\'][0-9a-zA-Z]{20,40}'
}
async def _scan_secrets_async(repo: str, token: str, limit: int = 10, show_rate_limit: bool = False):
    """Async secret scanning with concurrent file downloads."""
    from ..print_utils import _write_output
    from ..spinner import spinner
    async with create_async_context(token) as client:
        try:
            with spinner(t("commands.scan_secrets.scanning", limit=limit, repo=repo), color='96'):
                commits_url = f"https://api.github.com/repos/{repo}/commits"
                commits = await client.fetch_paginated(commits_url, per_page=limit, max_pages=1)
            if not commits:
                print_warning(t("commands.scan_secrets.no_commits"))
                return
            found_secrets = []
            tasks = []
            for commit in commits[:limit]:
                commit_url = commit.get('url')
                if commit_url:
                    task = asyncio.create_task(_check_commit(client, commit, repo))
                    tasks.append(task)
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    found_secrets.extend(result)
            found_count = len(found_secrets)
            if found_secrets:
                safe_print("")
                _write_output("")
                from ..helpers import TablePrinter
                columns = [
                    {'header': t("commands.scan_secrets.table_header.type"), 'width': 15, 'color': '96'},   
                    {'header': t("commands.scan_secrets.table_header.date"), 'width': 10, 'color': '93'},   
                    {'header': t("commands.scan_secrets.table_header.author"), 'width': 18, 'color': '92'}, 
                    {'header': t("commands.scan_secrets.table_header.file"), 'width': None, 'color': '97'}, 
                ]
                printer = TablePrinter(columns)
                printer.print_header()
                for idx, secret in enumerate(found_secrets):
                    style = "2;" if idx % 2 == 1 else ""
                    d_raw = secret.get('date', 'N/A')
                    date_val = d_raw[:10] if isinstance(d_raw, str) and len(d_raw) >= 10 else str(d_raw)
                    row_data = [
                        secret.get('type', 'N/A'),
                        date_val,
                        secret.get('author', 'N/A'),
                        secret.get('file', 'N/A')
                    ]
                    printer.print_row(row_data, style_prefix=style)
                safe_print("")
                print_info(t("commands.scan_secrets.secret_found", count=found_count))
                safe_print("")
                _write_output("")
            else:
                safe_print("")
                print_success(t("commands.scan_secrets.none_found"))
                safe_print("")
            if show_rate_limit:
                safe_print("")
                _write_output("")
                print_info(client.get_quota_info())
                safe_print("")
                _write_output("")
        except Exception as e:
            print_error(f"Scan failed: {str(e)}")
async def _check_commit(client, commit: dict, repo: str) -> list:
    """Check a single commit for secrets."""
    secrets = []
    try:
        commit_url = commit.get('url')
        if not commit_url:
            return secrets
        commit_data = await client.fetch_json(commit_url)
        files = commit_data.get('files', [])
        sem = asyncio.Semaphore(10)
        file_tasks = []
        async def _check_with_sem(client, file, commit, repo):
            async with sem:
                return await _check_file(client, file, commit, repo)
        for file in files:
            if file.get('status') == 'added':
                task = asyncio.create_task(_check_with_sem(client, file, commit, repo))
                file_tasks.append(task)
        file_results = await asyncio.gather(*file_tasks, return_exceptions=True)
        for result in file_results:
            if isinstance(result, list):
                secrets.extend(result)
        return secrets
    except Exception:
        return secrets
async def _check_file(client, file: dict, commit: dict, repo: str) -> list:
    """Check a single file for secrets."""
    secrets = []
    try:
        content_url = file.get('raw_url')
        if not content_url:
            return secrets
        content = await client.fetch_json(content_url) if content_url.startswith('https://api') else None
        if not content:
            try:
                async with client.session.get(content_url, timeout=10) as resp:
                    if resp.status == 200:
                        content = await resp.text()
            except Exception:
                return secrets
        for secret_type, pattern in SECRET_PATTERNS.items():
            if isinstance(content, str) and re.search(pattern, content):
                secrets.append({
                    'type': secret_type,
                    'file': file.get('filename'),
                    'commit': commit.get('html_url'),
                    'date': commit.get('commit', {}).get('author', {}).get('date')
                })
                break
        return secrets
    except Exception:
        return secrets
def cmd_scan_secrets(args):
    """Scan recent commits for secrets - optimized with async processing."""
    from ..print_utils import _write_output
    if not args.repo:
        print_error(t("commands.shared.missing_repo"))
        _write_output(f"\n{t('commands.scan_secrets.usage')}")
        _write_output(t("commands.shared.usage_hint", command="scan-secrets", args="torvalds/linux -l 50"))
        return
    repo = args.repo.strip()
    if "/" not in repo or len(repo.split("/")) != 2:
        safe_print("")
        _write_output("")
        print_error(t("commands.shared.invalid_repo_format"))
        safe_print("")
        return
    limit = args.limit if hasattr(args, 'limit') else 10
    if limit > 50:
        safe_print("")
        print_error(t("commands.scan_secrets.limit_exceeded", requested=limit, max=50))
        safe_print("")
        return

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
        safe_print("")
        _write_output("")
        show_rate = getattr(args, 'show_rate_limit', False)
        asyncio.run(_scan_secrets_async(repo, token, limit, show_rate))
    except KeyboardInterrupt:
        safe_print("")
        _write_output("")
        print_cancelled(t("commands.shared.scan_cancelled"))
    except Exception as e:
        print_error(t("commands.shared.error_occurred", error=str(e)))
