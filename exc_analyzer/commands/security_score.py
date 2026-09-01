"""Security score calculation with improved visual output."""
import requests
from ..print_utils import print_error, _write_output, safe_print, Print
from ..api import api_get, get_auth_header, DEFAULT_TIMEOUT
from ..spinner import spinner

def _content_exists(repo, headers, paths):
    """Return True if found, False if every path 404s, None if unreadable."""
    saw_unexpected = False
    for path in paths:
        url = f"https://api.github.com/repos/{repo}/contents/{path}"
        try:
            resp = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        except requests.RequestException:
            saw_unexpected = True
            continue
        if resp.status_code == 200:
            return True
        if resp.status_code != 404:
            saw_unexpected = True
    return None if saw_unexpected else False

def cmd_security_score(args):
    from ..i18n import t
    if not args.repo:
        print_error(t("commands.shared.missing_repo"))
        _write_output(f"\n{t('commands.security_score.usage')}")
        _write_output(f"{t('commands.shared.example_header')} {t('commands.security_score.examples')[0]}")
        return
    headers = get_auth_header()
    repo = args.repo.strip()
    if "/" not in repo or len(repo.split("/")) != 2:
        safe_print("")
        _write_output("")
        print_error(t("commands.shared.invalid_repo_format"))
        safe_print("")
        return
    with spinner(t("commands.security_score.calculating", repo=repo), color='96'):
        repo_url = f"https://api.github.com/repos/{repo}"
        repo_data, _ = api_get(repo_url, headers)
    safe_print("")
    _write_output("")
    score = 100
    issues = []
    s_present = t("commands.security_score.status.present")
    s_missing = t("commands.security_score.status.missing")
    s_enabled = t("commands.security_score.status.enabled")
    s_disabled = t("commands.security_score.status.disabled")
    s_unknown = t("commands.security_score.status.unknown")
    s_not_configured = t("commands.security_score.status.not_configured")
    is_admin = bool((repo_data.get('permissions') or {}).get('admin'))
    s_yes = t("commands.security_score.status.yes")
    s_no = t("commands.security_score.status.no")
    crit_license = t("commands.security_score.criteria.license")
    if not repo_data.get('license'):
        score -= 10
        issues.append((crit_license, t("commands.security_score.status.none"), -10, False))
    else:
        issues.append((crit_license, s_present, 0, True))
    crit_issues = t("commands.security_score.criteria.issues")
    if not repo_data.get('has_issues'):
        score -= 10
        issues.append((crit_issues, s_no, -10, False))
    else:
        issues.append((crit_issues, s_yes, 0, True))
    crit_wiki = t("commands.security_score.criteria.wiki")
    if not repo_data.get('has_wiki'):
        score -= 5
        issues.append((crit_wiki, s_no, -5, False))
    else:
        issues.append((crit_wiki, s_yes, 0, True))
    crit_projects = t("commands.security_score.criteria.projects")
    if not repo_data.get('has_projects'):
        score -= 5
        issues.append((crit_projects, s_no, -5, False))
    else:
        issues.append((crit_projects, s_yes, 0, True))
    crit_open = t("commands.security_score.criteria.open_issues")
    open_issues = repo_data.get('open_issues_count', 0)
    if open_issues > 50:
        score -= 10
        issues.append((crit_open, f"{open_issues}", -10, False))
    elif open_issues > 10:
        score -= 5
        issues.append((crit_open, f"{open_issues}", -5, False))
    else:
        issues.append((crit_open, f"{open_issues}", 0, True))
    crit_sec = t("commands.security_score.criteria.security_md")
    has_security = _content_exists(
        repo,
        headers,
        ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"),
    )
    if has_security is None:
        issues.append((crit_sec, s_unknown, 0, None))
    elif has_security:
        issues.append((crit_sec, s_present, 0, True))
    else:
        score -= 10
        issues.append((crit_sec, s_missing, -10, False))
    crit_bp = t("commands.security_score.criteria.branch_prot")
    default_branch = repo_data.get('default_branch')
    prot_url = f"https://api.github.com/repos/{repo}/branches/{default_branch}/protection"
    try:
        prot_resp = requests.get(prot_url, headers=headers, timeout=DEFAULT_TIMEOUT)
    except requests.RequestException:
        prot_resp = None
    if prot_resp is not None and prot_resp.status_code == 200:
        issues.append((crit_bp, s_enabled, 0, True))
    elif is_admin and prot_resp is not None and prot_resp.status_code == 404:
        score -= 10
        issues.append((crit_bp, s_disabled, -10, False))
    else:
        issues.append((crit_bp, s_unknown, 0, None))
    crit_dep = t("commands.security_score.criteria.dependabot")
    has_dependabot = _content_exists(
        repo,
        headers,
        (".github/dependabot.yml", ".github/dependabot.yaml"),
    )
    if has_dependabot is None:
        issues.append((crit_dep, s_unknown, 0, None))
    elif has_dependabot:
        issues.append((crit_dep, s_present, 0, True))
    else:
        score -= 5
        issues.append((crit_dep, s_missing, -5, False))
    crit_cs = t("commands.security_score.criteria.code_scanning")
    scan_url = f"https://api.github.com/repos/{repo}/code-scanning/alerts"
    try:
        scan_resp = requests.get(scan_url, headers=headers, timeout=DEFAULT_TIMEOUT)
    except requests.RequestException:
        scan_resp = None
    if scan_resp is not None and scan_resp.status_code == 200:
        alerts = scan_resp.json()
        if isinstance(alerts, list) and len(alerts) > 0:
            score -= 10
            issues.append((crit_cs, f"{len(alerts)} {t('commands.security_score.status.open')}", -10, False))
        else:
            issues.append((crit_cs, "0", 0, True))
    elif is_admin and scan_resp is not None and scan_resp.status_code == 404:
        issues.append((crit_cs, s_not_configured, 0, None))
    else:
        issues.append((crit_cs, s_unknown, 0, None))
    _print_security_score(repo, score, issues)

def _print_security_score(repo, score, issues):
    """Print security score in a visual, user-friendly format."""
    from ..i18n import t
    from ..helpers import TablePrinter
    if score >= 90:
        score_color = '92'
        verdict = t("commands.security_score.verdict.excellent")
        verdict_color = '92'
    elif score >= 75:
        score_color = '93'
        verdict = t("commands.security_score.verdict.good")
        verdict_color = '93'
    else:
        score_color = '91'
        verdict = t("commands.security_score.verdict.weak")
        verdict_color = '91'
    safe_print("")
    safe_print(Print.colorize("═" * 60, '96'))
    header_text = f"  {t('commands.security_score.score_header')}: {repo}"
    safe_print(Print.colorize(header_text, '97'))
    safe_print(Print.colorize("═" * 60, '96'))
    safe_print("")
    score_text = f"    {score}/100"
    safe_print(Print.colorize(score_text, score_color))
    safe_print(Print.colorize(f"    {verdict}", verdict_color))
    safe_print("")
    columns = [
        {'header': t("commands.security_score.headers.criteria"), 'width': 35},
        {'header': t("commands.security_score.headers.status"), 'width': 25},
        {'header': t("commands.security_score.headers.impact"), 'width': 15, 'align': 'right'}
    ]
    printer = TablePrinter(columns)
    printer.print_header()
    for criteria, status, impact, passed in issues:
        if passed is None:
            color = '90'
            impact_str = ""
        elif passed:
            color = '92'
            impact_str = ""
        else:
            color = '91'
            impact_str = f"({impact})" if impact < 0 else ""
        printer.print_row([criteria, status, impact_str], color_override=color)
    safe_print("")
    unknown_count = sum(1 for entry in issues if entry[3] is None)
    if unknown_count:
        note = t("commands.security_score.not_scored_note", count=unknown_count)
        safe_print(Print.colorize(f"  {note}", '90'))
        safe_print("")
    safe_print(Print.colorize("═" * 60, '96'))
    safe_print("")
