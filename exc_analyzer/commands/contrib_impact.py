from ..print_utils import Print
from ..api import get_auth_header, get_all_pages
from ..i18n import t
def cmd_contrib_impact(args):
    """Measure contributor impact using line changes"""
    from ..print_utils import _write_output, safe_print
    headers = get_auth_header()
    repo = args.repo.strip()
    if "/" not in repo or len(repo.split("/")) != 2:
        safe_print("")
        Print.error(t("commands.shared.invalid_repo_format"))
        safe_print("")
        return
    stats_url = f"https://api.github.com/repos/{repo}/stats/contributors"
    contributors = get_all_pages(stats_url, headers)
    safe_print("")
    header_msg = t("commands.contrib_impact.header", repo=repo)
    Print.info(header_msg.strip())
    formula_msg = t("commands.contrib_impact.formula")
    safe_print(Print.colorize(f"  {formula_msg}", '90')) 
    _write_output(formula_msg)
    results = []
    if contributors:
        for contributor in contributors:
            if not contributor or not contributor.get('author'):
                continue
            login = contributor['author']['login']
            total_add = sum(w['a'] for w in contributor['weeks'])
            total_del = sum(w['d'] for w in contributor['weeks'])
            score = (total_add * 0.7) - (total_del * 0.3)
            results.append((login, score, total_add, total_del))
    if not results:
        safe_print("")
        Print.warn(t("commands.shared.none_found")) 
        safe_print("")
        return
    safe_print("")
    Print.success(t("commands.contrib_impact.top_header").strip())
    for login, score, adds, dels in sorted(results, key=lambda x: x[1], reverse=True)[:10]:
        safe_print("")
        user_line = f"  {login}"
        safe_print(Print.colorize(user_line, '1;97')) 
        _write_output(user_line)
        score_val = f"{score:.1f}"
        score_txt = t("commands.contrib_impact.score_display", score=score_val)
        Print.info(score_txt)
        stats_txt = t("commands.contrib_impact.stats_display", adds=adds, dels=dels)
        safe_print(f"      {stats_txt}")
        _write_output(f"      {stats_txt}")
    safe_print("")
