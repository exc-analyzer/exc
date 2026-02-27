"""Content audit with improved visual output."""
import base64
import json
from ..print_utils import Print, _write_output, safe_print
from ..api import get_auth_header, DEFAULT_TIMEOUT, safe_get
from ..spinner import spinner
from ..i18n import t
def cmd_content_audit(args):
    if not args.repo:
        Print.error(t("commands.shared.missing_repo", default="Missing required argument: <owner/repo>"))
        _write_output(f"\n{t('commands.content_audit.usage')}")
        return
    headers = get_auth_header()
    repo = args.repo.strip()
    if "/" not in repo or len(repo.split("/")) != 2:
        print()
        _write_output("")
        Print.error(t("commands.shared.invalid_repo_format"))
        print()
        return
    files = [
        ("LICENSE", t("commands.content_audit.files.license")),
        ("SECURITY.md", t("commands.content_audit.files.security")),
        ("CODE_OF_CONDUCT.md", t("commands.content_audit.files.coc")),
        ("CONTRIBUTING.md", t("commands.content_audit.files.contributing")),
        ("README.md", t("commands.content_audit.files.readme"))
    ]
    results = []
    with spinner(t("commands.content_audit.auditing", repo=repo), color='96'):
        s_present = t("commands.content_audit.status.present")
        s_missing = t("commands.content_audit.status.missing")
        s_too_short = t("commands.content_audit.status.too_short")
        s_empty = t("commands.content_audit.status.empty")
        s_ok = t("commands.content_audit.status.ok")
        for fname, desc in files:
            url = f"https://api.github.com/repos/{repo}/contents/{fname}"
            text, _, status = safe_get(url, headers=headers, timeout=DEFAULT_TIMEOUT, cacheable=True)
            if status == 200:
                data = json.loads(text) if text else {}
                content = data.get('content', '') if isinstance(data, dict) else ''
                if content:
                    try:
                        decoded = base64.b64decode(content).decode(errors='ignore')
                    except Exception:
                        decoded = ''
                    lines = decoded.count('\n')
                    if lines < 5:
                        quality = s_too_short
                        passed = False
                    elif fname == 'README.md' and len(decoded) < 100:
                        quality = s_too_short
                        passed = False
                    else:
                        quality = s_ok
                        passed = True
                    results.append({
                        'file': fname,
                        'desc': desc,
                        'status': s_present,
                        'quality': quality,
                        'exists': True,
                        'passed': passed
                    })
                else:
                    results.append({
                        'file': fname,
                        'desc': desc,
                        'status': s_present,
                        'quality': s_empty,
                        'exists': True,
                        'passed': False
                    })
            else:
                results.append({
                    'file': fname,
                    'desc': desc,
                    'status': s_missing,
                    'quality': '-',
                    'exists': False,
                    'passed': False
                })
    print()
    _write_output("")
    _print_audit_results(repo, results)
def _print_audit_results(repo, results):
    """Print content audit results in a visual, user-friendly format."""
    safe_print("")
    _write_output("")
    sep = "═" * 60
    safe_print(Print.colorize(sep, '96'))
    _write_output(sep)
    header_text = f"  {t('commands.content_audit.header')}: {repo}"
    safe_print(Print.colorize(header_text, '97'))
    _write_output(header_text)
    safe_print(Print.colorize(sep, '96'))
    _write_output(sep)
    safe_print("")
    _write_output("")
    total = len(results)
    present = sum(1 for r in results if r['exists'])
    missing = total - present
    stats_text = f"  {t('commands.content_audit.stats', present=present, total=total)}"
    if missing == 0:
        safe_print(Print.colorize(stats_text, '92'))
    else:
        safe_print(Print.colorize(stats_text, '93'))
    _write_output(stats_text)
    safe_print("")
    _write_output("")
    for i, result in enumerate(results, 1):
        if result['exists'] and result['passed']:
            status_label = f"[{t('commands.content_audit.labels.ok')}]"
            label_color = '92'  
        elif result['exists'] and not result['passed']:
            status_label = f"[{t('commands.content_audit.labels.warn')}]"
            label_color = '93'  
        else:
            status_label = f"[{t('commands.content_audit.labels.missing')}]"
            label_color = '91'  
        file_header = f"  {status_label} {result['file']}"
        safe_print(Print.colorize(file_header, label_color))
        _write_output(file_header)
        desc_line = f"         {t('commands.content_audit.labels.type')}: {result['desc']}"
        safe_print(Print.colorize(desc_line, '97'))
        _write_output(desc_line)
        status_line = f"         {t('commands.content_audit.labels.status')}: {result['status']}"
        if result['exists']:
            safe_print(Print.colorize(status_line, '96'))
        else:
            safe_print(Print.colorize(status_line, '91'))
        _write_output(status_line)
        if result['exists']:
            quality_line = f"         {t('commands.content_audit.labels.quality')}: {result['quality']}"
            if result['passed']:
                safe_print(Print.colorize(quality_line, '92'))
            else:
                safe_print(Print.colorize(quality_line, '93'))
            _write_output(quality_line)
        if i < len(results):
            safe_print("")
            _write_output("")
    safe_print("")
    _write_output("")
    safe_print(Print.colorize(sep, '96'))
    _write_output(sep)
    safe_print("")
    _write_output("")
