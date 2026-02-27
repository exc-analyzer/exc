"""Advanced secret scanning with concurrent file processing."""
import asyncio
import re
from ..i18n import t
from ..print_utils import Print
from ..async_api import create_async_context
from ..config import load_key
SECRET_PATTERNS = {
    'AWS Key': r'AKIA[0-9A-Z]{16}',
    'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
    'Slack Token': r'xox[baprs]-([0-9a-zA-Z]{10,48})?',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Heroku API Key': r'heroku[a-z0-9]{32}',
    'Discord Token': r'[MN][A-Za-z\d]{23}\.[\\w-]{6}\.[\\w-]{27}',
    'Stripe Key': r'sk_live_[0-9a-zA-Z]{24}',
    'Mailgun Key': r'key-[0-9a-zA-Z]{32}',
    'API Key': r'(?i)(api|access)[_ -]?key["\']?[:=] ?["\'][0-9a-zA-Z]{20,40}',
    'Config File': r'(config|settings|secret|credentials|env)(\.json|\.yml|\.yaml|\.py|\.env)'
}
async def _scan_advanced_secrets_async(repo: str, token: str, commit_limit: int = 20, show_rate_limit: bool = False):
    """Advanced secret scanning with concurrent file processing."""
    from ..print_utils import _write_output, safe_print
    from ..spinner import spinner
    async with create_async_context(token) as client:
        Print.info(t("commands.advanced_secrets.scanning_repo", limit=commit_limit, repo=repo))
        safe_print("")
        _write_output("")
        found = []
        try:
            with spinner(t("commands.advanced_secrets.scanning_files"), color='96'):
                tree_url = f"https://api.github.com/repos/{repo}/git/trees/HEAD?recursive=1"
                tree_data = await client.fetch_json(tree_url)
                tree_items = tree_data.get('tree', [])
            suspect_files = []
            for item in tree_items:
                if item['type'] == 'blob':
                    path = item.get('path', '')
                    if any(ext in path.lower() for ext in ['.env', 'config', 'secret', 'credential', '.json', '.yml', '.yaml', '.py']):
                        suspect_files.append(item)
            sem = asyncio.Semaphore(10)
            file_tasks = []
            async def _scan_with_sem(url, path, source):
                async with sem:
                    return await _scan_file(url, path, source)
            for file_item in suspect_files[:50]:  
                raw_url = f"https://raw.githubusercontent.com/{repo}/HEAD/{file_item['path']}"
                task = asyncio.create_task(_scan_with_sem(raw_url, file_item['path'], 'file'))
                file_tasks.append(task)
            file_results = await asyncio.gather(*file_tasks, return_exceptions=True)
            found.extend([item for r in file_results if isinstance(r, list) for item in r])
            Print.info(t("commands.advanced_secrets.scanning_commits"))
            commits_url = f"https://api.github.com/repos/{repo}/commits"
            commits = await client.fetch_paginated(commits_url, per_page=commit_limit, max_pages=1)
            commit_tasks = []
            for commit in commits[:commit_limit]:
                task = asyncio.create_task(_scan_commit(client, commit, repo))
                commit_tasks.append(task)
            commit_results = await asyncio.gather(*commit_tasks, return_exceptions=True)
            found.extend([item for result in commit_results if result for item in result])
            safe_print("")
            _write_output("")
            if found:
                Print.info(t("commands.advanced_secrets.total_findings", count=len(found)))
                print()
                _write_output(f"\n{t('commands.advanced_secrets.total_findings', count=len(found))}\n")
                for path, secret_type, url, source in found:
                    header = f"[+] {path} "
                    safe_print(Print.colorize(header, '94'), end="")
                    safe_print(Print.colorize(f"({secret_type})", '93'))
                    _write_output(f"[+] {path} ({secret_type})")
                    source_line = f"    {t('commands.advanced_secrets.output.source')}: {source}"
                    safe_print(Print.colorize(source_line, '97'))
                    _write_output(source_line)
                    link_label = "    -> "
                    safe_print(Print.colorize(link_label, '90'), end="") 
                    safe_print(Print.colorize(url, '33'))
                    _write_output(f"    -> {url}")
                    _write_output(f"    {url}")
                    print()
                    _write_output("")
            else:
                Print.success(t("commands.advanced_secrets.none_found"))
            safe_print("")
            _write_output("")
            if show_rate_limit:
                Print.info(client.get_quota_info())
                safe_print("")
                _write_output("")
        except Exception as e:
            Print.error(f"Scan failed: {str(e)}")
async def _scan_file(url: str, path: str, source: str) -> list:
    """Scan a single file for secrets."""
    results = []
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    for secret_type, pattern in SECRET_PATTERNS.items():
                        if re.search(pattern, content):
                            results.append([path, secret_type, url, source])
                            break
    except Exception as e:
        from ..logging_utils import log
        log(f"Failed to scan file {url}: {e}")
    return results
async def _scan_commit(client, commit: dict, repo: str) -> list:
    """Scan a commit for secrets."""
    results = []
    try:
        commit_url = commit.get('url')
        if not commit_url:
            return results
        commit_data = await client.fetch_json(commit_url)
        files = commit_data.get('files', [])
        sem = asyncio.Semaphore(10)
        file_tasks = []
        async def _scan_with_sem(url, path, source):
            async with sem:
                return await _scan_file(url, path, source)
        for file in files:
            if file.get('status') in ['added', 'modified']:
                raw_url = file.get('raw_url')
                if raw_url:
                    source = f"commit: {commit.get('sha', '')[:7]}"
                    task = asyncio.create_task(_scan_with_sem(raw_url, file.get('filename'), source))
                    file_tasks.append(task)
        file_results = await asyncio.gather(*file_tasks, return_exceptions=True)
        for result in file_results:
            if isinstance(result, list):
                results.extend(result)
        return results
    except Exception:
        return results
def cmd_advanced_secrets(args):
    """Advanced secret scanning - optimized with concurrent processing."""
    from ..print_utils import _write_output
    if not args.repo:
        Print.error(t("commands.shared.missing_repo"))
        _write_output(f"\n{t('commands.advanced_secrets.usage')}")
        return
    repo = args.repo.strip()
    if "/" not in repo or len(repo.split("/")) != 2:
        print("")
        _write_output("")
        Print.error(t("commands.shared.invalid_repo_format"))
        print("")
        return
    commit_limit = getattr(args, 'limit', 20)
    token = load_key()
    if not token:
        print("")
        _write_output("")
        Print.error(t("commands.shared.api_key_missing"))
        Print.info(t("commands.shared.use_key_cmd"))
        print("")
        _write_output("")
        return
    try:
        print("")
        _write_output("")
        show_rate = getattr(args, 'show_rate_limit', False)
        asyncio.run(_scan_advanced_secrets_async(repo, token, commit_limit, show_rate))
    except KeyboardInterrupt:
        print("")
        Print.warn(t("commands.shared.scan_cancelled"))
    except Exception as e:
        Print.error(t("commands.shared.error_occurred", error=str(e)))
