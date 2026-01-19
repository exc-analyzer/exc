"""GitHub Actions audit with improved visual output."""
import requests
import re
from ..print_utils import Print, _write_output, safe_print
from ..api import get_auth_header
from ..spinner import spinner
def cmd_actions_audit(args):
    from ..i18n import t
    if not args.repo:
        Print.error(t("commands.shared.missing_repo", default="Missing required argument: <owner/repo>"))
        _write_output(f"\n{t('commands.actions_audit.usage')}")
        _write_output(f"{t('commands.actions_audit.example')}")
        _write_output(f"\n{t('commands.actions_audit.description')}")
        return
    headers = get_auth_header()
    repo = args.repo.strip()
    if "/" not in repo or len(repo.split("/")) != 2:
        print()
        _write_output("")
        Print.error(t("commands.shared.invalid_repo_format"))
        print()
        return
    with spinner(t("commands.actions_audit.auditing", repo=repo), color='96'):
        url = f"https://api.github.com/repos/{repo}/contents/.github/workflows"
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            print()
            _write_output("")
            Print.warn(t("commands.actions_audit.no_workflows"))
            return
        workflows = resp.json()
        results = []
        for wf in workflows:
            wf_url = wf.get('download_url')
            name = wf.get('name') or wf.get('path')
            try:
                content = requests.get(wf_url, timeout=8).text
                risky = bool(re.search(r'(curl|wget|bash|sh|powershell|python|node)', content, re.I))
                secrets = bool(re.search(r'secret', content, re.I))
                uses_latest = bool(re.search(r'@latest', content, re.I))
                if risky:
                    status = "risky"
                    message = t("commands.actions_audit.risky_script")
                    note = t("commands.actions_audit.check_exec")
                elif uses_latest:
                    status = "warning"
                    message = t("commands.actions_audit.uses_latest")
                    note = t("commands.actions_audit.pin_versions")
                elif secrets:
                    status = "info"
                    message = t("commands.actions_audit.uses_secrets")
                    note = t("commands.actions_audit.review_secrets")
                else:
                    status = "ok"
                    message = t("commands.actions_audit.ok")
                    note = t("commands.actions_audit.no_risk")
                results.append({
                    'name': name,
                    'url': wf_url,
                    'status': status,
                    'message': message,
                    'note': note
                })
            except Exception:
                results.append({
                    'name': name,
                    'url': wf_url,
                    'status': 'error',
                    'message': t("commands.actions_audit.error_fetch"),
                    'note': t("commands.actions_audit.could_not_fetch")
                })
    print()
    _write_output("")
    _print_audit_results(repo, results)
def _print_audit_results(repo, results):
    """Print actions audit results in a visual, user-friendly format."""
    from ..i18n import t
    safe_print("")
    _write_output("")
    sep = "═" * 60
    safe_print(Print.colorize(sep, '96'))
    _write_output(sep)
    header_text = f"  {t('commands.actions_audit.header')}: {repo}"
    safe_print(Print.colorize(header_text, '97'))
    _write_output(header_text)
    safe_print(Print.colorize(sep, '96'))
    _write_output(sep)
    safe_print("")
    _write_output("")
    total = len(results)
    risky_count = sum(1 for r in results if r['status'] == 'risky')
    warning_count = sum(1 for r in results if r['status'] == 'warning')
    ok_count = sum(1 for r in results if r['status'] == 'ok')
    stats_text = f"  {t('commands.actions_audit.stats', total=total, risky=risky_count)}"
    if risky_count > 0:
        safe_print(Print.colorize(stats_text, '91'))
    elif warning_count > 0:
        safe_print(Print.colorize(stats_text, '93'))
    else:
        safe_print(Print.colorize(stats_text, '92'))
    _write_output(stats_text)
    safe_print("")
    _write_output("")
    for i, result in enumerate(results, 1):
        if result['status'] == 'risky':
            status_label = f"[{t('commands.actions_audit.labels.risky')}]"
            label_color = '91'  
        elif result['status'] == 'warning':
            status_label = f"[{t('commands.actions_audit.labels.warning')}]"
            label_color = '93'  
        elif result['status'] == 'ok':
            status_label = f"[{t('commands.actions_audit.labels.ok')}]"
            label_color = '92'  
        else:
            status_label = f"[{t('commands.actions_audit.labels.error')}]"
            label_color = '90'  
        wf_header = f"  {status_label} {result['name']}"
        safe_print(Print.colorize(wf_header, label_color))
        _write_output(wf_header)
        msg_line = f"         {t('commands.actions_audit.labels.status')}: {result['message']}"
        safe_print(Print.colorize(msg_line, '97'))
        _write_output(msg_line)
        note_line = f"         {t('commands.actions_audit.labels.note')}: {result['note']}"
        if result['status'] == 'risky':
            safe_print(Print.colorize(note_line, '91'))
        elif result['status'] == 'warning':
            safe_print(Print.colorize(note_line, '93'))
        else:
            safe_print(Print.colorize(note_line, '96'))
        _write_output(note_line)
        link_line_prefix = "         -> "
        safe_print(Print.colorize(link_line_prefix, '90'), end="")
        safe_print(Print.colorize(result['url'], '33'))
        _write_output(f"         -> {result['url']}")
        if i < len(results):
            safe_print("")
            _write_output("")
    safe_print("")
    _write_output("")
    safe_print(Print.colorize(sep, '96'))
    _write_output(sep)
    safe_print("")
    _write_output("")
