import sys
import os
import argparse
import difflib
from datetime import datetime
from exc_analyzer.logging_utils import log
from exc_analyzer.print_utils import Print, COLOR_ENABLED, colorize, set_verbose, close_output_file, _write_output, print_error
from exc_analyzer.config import load_key, delete_key
from exc_analyzer.api import notify_new_version, get_version_from_pyproject
from exc_analyzer.i18n import t, set_language, get_active_language, DEFAULT_LANGUAGE
from exc_analyzer.preferences import get_language_preference, set_language_preference
from exc_analyzer.commands.login import cmd_login
from exc_analyzer.commands.logout import cmd_logout
from exc_analyzer.commands.analysis import cmd_analysis
from exc_analyzer.commands.user_a import cmd_user_a
from exc_analyzer.commands.scan_secrets import cmd_scan_secrets
from exc_analyzer.commands.file_history import cmd_file_history
from exc_analyzer.commands.dork_scan import cmd_dork_scan
from exc_analyzer.commands.advanced_secrets import cmd_advanced_secrets
from exc_analyzer.commands.security_score import cmd_security_score
from exc_analyzer.commands.commit_anomaly import cmd_commit_anomaly
from exc_analyzer.commands.user_anomaly import cmd_user_anomaly
from exc_analyzer.commands.content_audit import cmd_content_audit
from exc_analyzer.commands.actions_audit import cmd_actions_audit
class SilentArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        if 'invalid choice:' in message:
            words = message.split()
            attempted = None
            try:
                attempted = message.split('invalid choice:')[1].split('(')[0].strip().strip("'")
            except Exception:
                attempted = None
            commands = {
                'login': ['l', 'log', 'signin', 'sign-in', 'auth'],
                'logout': ['lo', 'log-out', 'signout', 'sign-out', 'exit', 'leave'],
                'user-a': ['u', 'user', 'usera', 'user-audit', 'usr', 'userr', 'usra', 'usr-a'],
                'analysis': ['a', 'ana', 'analys', 'analyzis', 'analiz', 'anlys', 'anyl', 'anali', 'analy'],
                'scan-secrets': ['scan', 'secrets', 'scn', 'scret', 'scrt', 'ss', 's-scan', 'scretscan', 'secscan'],
                'file-history': ['file', 'fileh', 'flhist', 'histfile', 'fh', 'filehist', 'filehis', 'f-history'],
                'dork-scan': ['dork', 'dorkscan', 'drk', 'ds', 'dscan', 'dorks', 'd-sc'],
                'advanced-secrets': ['advsec', 'advsecrets', 'advscrt', 'as', 'adv-s', 'advs', 'advsercet'],
                'security-score': ['secscore', 'sscore', 'sec-score', 'securiscore', 'securityscor', 'ssec', 'securscore'],
                'commit-anomaly': ['commanom', 'commitanom', 'c-anom', 'c-anomaly', 'ca', 'cm-anom', 'comm-anom'],
                'user-anomaly': ['useranom', 'usranom', 'u-anom', 'user-anom', 'ua', 'useranomaly'],
                'content-audit': ['audit', 'contentaudit', 'cntaudit', 'caudit', 'cnt-aud', 'cont-audit'],
                'actions-audit': ['workflow-audit', 'waudit', 'actaudit', 'actionaudit', 'wf-audit', 'wkaudit']
            }
            all_cmds = list(commands.keys()) + [alias for v in commands.values() for alias in v]
            suggestion = None
            if attempted:
                attempted_lower = attempted.lower()
                matches = difflib.get_close_matches(attempted_lower, all_cmds, n=1, cutoff=0.5)
                if matches:
                    for main, aliases in commands.items():
                        if matches[0] == main or matches[0] in aliases:
                            suggestion = main
                            break
            print("")
            Print.error(t("cli.invalid_command"))
            if suggestion:
                print("")
                suggestion_text = t("cli.invalid_command_suggestion", command=suggestion)
                Print.info(suggestion_text)
                print("")
            print("")
        else:
            print("")
            Print.error(message) 
            print("")
        sys.exit(2)
class HelpPrinter:
    """Standardized help message printer."""
    @staticmethod
    def print_help(usage_key, desc_key, examples_key=None, options_key=None, details_key=None, tips_key=None, footer_key=None):
        print("")
        print(colorize(t(usage_key), '96'))
        print("")
        desc = t(desc_key)
        if "https://" in desc:
            words = desc.split()
            colored_words = []
            for w in words:
                if w.startswith("https://"):
                    colored_words.append(colorize(w, '1;94;4'))
                else:
                    colored_words.append(w)
        print(desc)
        if examples_key:
            HelpPrinter._print_section(examples_key, "commands.shared.example_header", "commands.shared.examples_header")
        if options_key:
             HelpPrinter._print_section(options_key, "commands.shared.options_header")
        if details_key:
            HelpPrinter._print_section(details_key, "commands.shared.details_header")
        if tips_key:
            HelpPrinter._print_section(tips_key, "commands.shared.tips_header")
        if footer_key:
            print("")
            print(colorize(t(footer_key), '96'))
        print("")
        sys.exit(0)
    @staticmethod
    def _print_section(data_key, header_single, header_plural=None):
        items = t(data_key)
        if not items:
            return
        if not isinstance(items, list):
            items = [items]
        header = header_plural if (header_plural and len(items) > 1) else header_single
        print("")
        print(colorize(t(header), '93'))
        for item in items:
            print(f"  {item}")
def print_minimal_help():
    cyan = '96' if COLOR_ENABLED else None
    yellow = '93' if COLOR_ENABLED else None
    bold = '1' if COLOR_ENABLED else None
    def c(text, code):
        return colorize(text, code) if code else text
    print(c(r"""
      Y88b   d88P 
       Y88b d88P  
        Y88o88P   
         Y888P         EXC – GitHub Analysis & Security Tool
         d888b                github.com/exc-analyzer
        d88888b   
       d88P Y88b  
      d88P   Y88b 
""", bold))
    cmd_login    = "exc login"
    cmd_analysis = f"exc analysis   {t('cli.min_help.args_repo')}"
    cmd_user     = f"exc user-a     {t('cli.min_help.args_user')}"
    max_len = max(len(cmd_login), len(cmd_analysis), len(cmd_user))
    pad = max_len + 2
    def print_item(cmd, desc):
        prefix = c("[+]", '92')
        print(f"  {prefix} {c(cmd.ljust(pad), cyan)}{c(desc, yellow)}")
    print_item(cmd_login, t("cli.min_help.login_desc"))
    print_item(cmd_analysis, t("cli.min_help.analysis_desc"))
    print_item(cmd_user, t("cli.min_help.user_desc"))
    print("")
    print(c(t("cli.min_help.help_hint"), yellow))
    print(c(t("cli.min_help.detail_hint"), yellow))
    print("")
    sys.exit(0)
def print_full_help():
    cyan = '96' if COLOR_ENABLED else None
    yellow = '93' if COLOR_ENABLED else None
    def c(text, code):
        return colorize(text, code) if code else text
    print("")
    header = f"{c('[+]', '92')} {c(t('cli.full_help.title'), '1')}" 
    print(header)
    print("")
    print(t("cli.full_help.common_header"))
    def arg(k): return t(f"cli.args.{k}")
    common_cmds = [
        (t("cli.full_help.login_logout_usage"), "", "commands.login.desc_combined"),
        ("exc analysis", arg("owner_repo"), "commands.analysis.desc_short"),
        ("exc user-a", arg("username"), "commands.user_a.desc_short"),
        ("exc scan-secrets", arg("owner_repo"), "commands.scan_secrets.desc_short"),
        ("exc file-history", f"{arg('owner_repo')} {arg('file')}", "commands.file_history.desc_short"),
    ]
    sec_cmds = [
        ("exc user-anomaly", arg("username"), "commands.user_anomaly.desc_short"),
        ("exc dork-scan", arg("dork_query"), "commands.dork_scan.desc_short"),
        ("exc advanced-secrets", arg("owner_repo"), "commands.advanced_secrets.desc_short"),
        ("exc security-score", arg("owner_repo"), "commands.security_score.desc_short"),
        ("exc commit-anomaly", arg("owner_repo"), "commands.commit_anomaly.desc_short"),
        ("exc content-audit", arg("owner_repo"), "commands.content_audit.desc_short"),
        ("exc actions-audit", arg("owner_repo"), "commands.actions_audit.desc_short"),
    ]
    gen_opts = [
        ("--version", "(-v)", "cli.general_options.version"),
        ("--verbose", "(-V)", "cli.general_options.verbose"),
        ("--lang", "(-l/-L)", "cli.general_options.lang"),
        ("--show-rate-limit", "(-r)", "cli.general_options.rate_limit"),
    ]
    all_cmds_list = common_cmds + sec_cmds
    max_cmd_len = 0
    for cmd, _, _ in all_cmds_list:
        if len(cmd) > max_cmd_len:
            max_cmd_len = len(cmd)
    cmd_pad = max_cmd_len + 1
    def prepare_cmd_lines(group):
        lines = []
        for cmd, args, desc_key in group:
            prefix = cmd.ljust(cmd_pad)
            if args:
                full_usage = f"{prefix} {args}"
            else:
                full_usage = cmd 
            lines.append((full_usage, desc_key))
        return lines
    common_lines = prepare_cmd_lines(common_cmds)
    sec_lines = prepare_cmd_lines(sec_cmds)
    max_len_cmds = 0
    for usage, _ in common_lines + sec_lines:
        if len(usage) > max_len_cmds:
            max_len_cmds = len(usage)
    desc_pad_cmds = max_len_cmds + 4
    max_long = 0
    for long_f, _, _ in gen_opts:
        if len(long_f) > max_long:
            max_long = len(long_f)
    long_pad = max_long + 4  
    max_short = 0
    for _, short_f, _ in gen_opts:
        if len(short_f) > max_short:
            max_short = len(short_f)
    short_pad = max_short + 4 
    def p_lines(lines, pad, color_code):
        for usage, key in lines:
            left = f"  {usage}".ljust(pad)
            desc = t(key)
            print(c(left, cyan) + c(desc, color_code))
    p_lines(common_lines, desc_pad_cmds, yellow)
    print("")
    print(t("cli.full_help.security_header"))
    p_lines(sec_lines, desc_pad_cmds, yellow)
    print("")
    print(t("cli.full_help.general_options_header"))
    for long_f, short_f, key in gen_opts:
        long_part = f"  {long_f}".ljust(long_pad + 2) 
        short_part = f"{short_f}".ljust(short_pad)
        left = f"{long_part}{short_part}"
        desc = f"# {t(key)}"
        print(c(left, cyan) + c(desc, yellow))
    print("")
    print("")
    print(t("cli.full_help.info_hint"))
    print("")
    notify_new_version()
    print("")
    sys.exit(0)
def _extract_cli_language(argv):
    lang = None
    for idx, arg in enumerate(argv):
        if arg in ("--lang", "-L", "-l"):
            if idx + 1 < len(argv):
                potential_lang = argv[idx + 1]
                if arg == "-l" and potential_lang.isdigit():
                    continue
                lang = potential_lang
            break
        if arg.startswith("--lang="):
            lang = arg.split("=", 1)[1]
            break
    return lang
def configure_language():
    """Resolve the active language from CLI flag, env vars, or saved settings."""
    cli_lang = _extract_cli_language(sys.argv)
    env_lang = os.environ.get("EXC_LANG") or os.environ.get("LANG")
    saved_lang = get_language_preference()
    if cli_lang:
        if set_language(cli_lang):
            active = get_active_language()
            set_language_preference(active)
            return active
        Print.warn(t("cli.language_not_available", lang=cli_lang, fallback=DEFAULT_LANGUAGE))
        set_language(DEFAULT_LANGUAGE)
        return DEFAULT_LANGUAGE
    if env_lang and set_language(env_lang):
        return get_active_language()
    if saved_lang:
        if set_language(saved_lang):
            return get_active_language()
    set_language(DEFAULT_LANGUAGE)
    return DEFAULT_LANGUAGE
def main_cli():
    configure_language()
    notify_new_version()
    if "--version" in sys.argv or "-v" in sys.argv:
        notify_new_version()
        print("")
        local_version = get_version_from_pyproject() or t("cli.version_missing")
        print(f"EXC Analyzer v{local_version}")
        print("")
        sys.exit(0)
        print("")
        sys.exit(0) 
    if len(sys.argv) == 1 or (len(sys.argv) > 1 and sys.argv[1] == "exc"):
        print_minimal_help() 
        sys.exit(0)
    if sys.argv[1] in ("-h", "--help", "help"):
        print_full_help()  
        sys.exit(0)
    if "--verbose" in sys.argv or "-V" in sys.argv:
        set_verbose(True)
        Print.warn(t("cli.verbose_enabled"))
        sys.argv = [a for a in sys.argv if a not in ["--verbose", "-V"]]
    parser = SilentArgumentParser(
        prog="exc",
        usage="",
        description="",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    parser.add_argument(
        "-L", "-l",
        "--lang",
        metavar=t("cli.lang_option_metavar"),
        help=t("cli.general_options.lang")
    )
    subparsers = parser.add_subparsers(dest="command")
    login_parser = subparsers.add_parser(
        "login",
        description="Authenticate via GitHub Device Flow.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    login_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def login_help(args):
        print("")
        print(colorize(t("commands.login.usage"), '96'))
        print("")
        desc = t("commands.login.description")
        url = "https://github.com/login/device"
        desc = desc.replace(url, colorize(url, '1;94;4'))
        parts = desc.split('\n', 1)
        if len(parts) > 0:
            parts[0] = colorize(parts[0], '1;97')
            desc = '\n'.join(parts)
        print(desc)
        sys.exit(0)
    login_parser.set_defaults(func=cmd_login, help_func=login_help)
    logout_parser = subparsers.add_parser(
        "logout",
        description="Log out and remove API key.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    logout_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def logout_help(args):
        print("")
        print(colorize(t("commands.logout.usage"), '96'))
        print("")
        desc = t("commands.logout.description")
        cmd_str = '"exc login"'
        desc = desc.replace(cmd_str, colorize(cmd_str, '93'))
        print(desc)
        sys.exit(0)
    logout_parser.set_defaults(func=cmd_logout, help_func=logout_help)
    analysis_parser = subparsers.add_parser(
        "analysis",
        description="Repository analysis: code, security, dependencies, stats.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    analysis_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    analysis_parser.add_argument("-o", "--output", nargs='?', const='', help=t("commands.shared.help_output"))
    analysis_parser.add_argument("-r", "--show-rate-limit", action="store_true", help=argparse.SUPPRESS)
    analysis_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def analysis_help(args):
        HelpPrinter.print_help(
            "commands.analysis.usage",
            "commands.analysis.description",
            examples_key="commands.analysis.examples",
            options_key="commands.analysis.options"
        )
    analysis_parser.set_defaults(func=cmd_analysis, help_func=analysis_help)
    user_parser = subparsers.add_parser(
        "user-a",
        description="Analyze a GitHub user's profile and repositories.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    user_parser.add_argument("username", nargs="?", help=argparse.SUPPRESS)
    user_parser.add_argument("-o", "--output", nargs='?', const='', help=t("commands.shared.help_output"))
    user_parser.add_argument("-r", "--show-rate-limit", action="store_true", help=argparse.SUPPRESS)
    user_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def user_help(args):
        HelpPrinter.print_help(
            "commands.user_a.usage",
            "commands.user_a.description",
            examples_key="commands.user_a.examples",
            details_key="commands.user_a.details",
            tips_key="commands.user_a.tip" 
        )
    user_parser.set_defaults(func=cmd_user_a, help_func=user_help)
    scan_parser = subparsers.add_parser(
        "scan-secrets",
        description="Scan recent commits for leaked secrets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    scan_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    scan_parser.add_argument("-l", "--limit", type=int, default=10, help=t("commands.shared.help_limit", default=10))
    scan_parser.add_argument("-o", "--output", nargs='?', const='', help=t("commands.shared.help_output"))
    scan_parser.add_argument("-r", "--show-rate-limit", action="store_true", help=argparse.SUPPRESS)
    scan_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def scan_help(args):
        HelpPrinter.print_help(
            "commands.scan_secrets.usage",
            "commands.scan_secrets.description",
            examples_key="commands.scan_secrets.examples",
            options_key="commands.scan_secrets.options"
        )
    scan_parser.set_defaults(func=cmd_scan_secrets, help_func=scan_help)
    file_parser = subparsers.add_parser(
        "file-history",
        description="Show the change history of a file in a repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    file_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    file_parser.add_argument("filepath", nargs="?", help=argparse.SUPPRESS)
    file_parser.add_argument("-l", "--limit", type=int, default=5, help=t("commands.shared.help_limit", default=5))
    file_parser.add_argument("-o", "--output", nargs='?', const='', help=t("commands.shared.help_output"))
    file_parser.add_argument("-r", "--show-rate-limit", action="store_true", help=argparse.SUPPRESS)
    file_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def file_help(args):
        HelpPrinter.print_help(
            "commands.file_history.usage",
            "commands.file_history.description",
            examples_key="commands.file_history.examples",
            options_key="commands.file_history.options"
        )
    file_parser.set_defaults(func=cmd_file_history, help_func=file_help)
    dork_parser = subparsers.add_parser(
        "dork-scan",
        description="Scan GitHub for sensitive keywords or patterns (dorking).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    dork_parser.add_argument("query", nargs="*", help=argparse.SUPPRESS)
    dork_parser.add_argument("-n", "--num", type=int, default=10, help=t("commands.shared.help_num"))
    dork_parser.add_argument("-p", "--preset", help=t("commands.dork_scan.help_preset")) 
    dork_parser.add_argument("--verify", action="store_true", help=t("commands.dork_scan.help_verify"))
    dork_parser.add_argument("--list-presets", action="store_true", help=t("commands.dork_scan.help_list_presets"))
    dork_parser.add_argument("--export", metavar="FILE", help=t("commands.dork_scan.help_export"))
    dork_parser.add_argument("-o", "--output", nargs='?', const='', help=t("commands.shared.help_output"))
    dork_parser.add_argument("-r", "--show-rate-limit", action="store_true", help=argparse.SUPPRESS)
    dork_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def dork_help(args):
        HelpPrinter.print_help(
            "commands.dork_scan.usage",
            "commands.dork_scan.description",
            examples_key="commands.dork_scan.examples",
            options_key="commands.dork_scan.options",
            details_key="commands.dork_scan.details",
            tips_key="commands.dork_scan.tips",
            footer_key="commands.dork_scan.footer"
        )
    dork_parser.set_defaults(func=cmd_dork_scan, help_func=dork_help)
    advsec_parser = subparsers.add_parser(
        "advanced-secrets",
        description="Scan repo for a wide range of secret patterns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    advsec_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    advsec_parser.add_argument("-l", "--limit", type=int, default=20, help=t("commands.shared.help_limit", default=20))
    advsec_parser.add_argument("-o", "--output", nargs='?', const='', help=t("commands.shared.help_output"))
    advsec_parser.add_argument("-r", "--show-rate-limit", action="store_true", help=argparse.SUPPRESS)
    advsec_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def advsec_help(args):
        HelpPrinter.print_help(
            "commands.advanced_secrets.usage",
            "commands.advanced_secrets.description",
            examples_key="commands.advanced_secrets.examples",
            options_key="commands.advanced_secrets.options"
        )
    advsec_parser.set_defaults(func=cmd_advanced_secrets, help_func=advsec_help)
    secscore_parser = subparsers.add_parser(
        "security-score",
        description="Calculate a security score for the repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    secscore_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    secscore_parser.add_argument("-o", "--output", nargs='?', const='', help=t("commands.shared.help_output"))
    secscore_parser.add_argument("-r", "--show-rate-limit", action="store_true", help=argparse.SUPPRESS)
    secscore_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def secscore_help(args):
        HelpPrinter.print_help(
            "commands.security_score.usage",
            "commands.security_score.description",
            examples_key="commands.security_score.examples"
        )
    secscore_parser.set_defaults(func=cmd_security_score, help_func=secscore_help)
    commanom_parser = subparsers.add_parser(
        "commit-anomaly",
        description="Analyze commit/PR activity for anomalies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    commanom_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    commanom_parser.add_argument("-o", "--output", nargs='?', const='', help=t("commands.shared.help_output"))
    commanom_parser.add_argument("-r", "--show-rate-limit", action="store_true", help=argparse.SUPPRESS)
    commanom_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def commanom_help(args):
        HelpPrinter.print_help(
            "commands.commit_anomaly.usage",
            "commands.commit_anomaly.description",
            examples_key="commands.commit_anomaly.examples"
        )
    commanom_parser.set_defaults(func=cmd_commit_anomaly, help_func=commanom_help)
    useranom_parser = subparsers.add_parser(
        "user-anomaly",
        description="Detect unusual activity in a user's GitHub activity.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    useranom_parser.add_argument("username", nargs="?", help=argparse.SUPPRESS)
    useranom_parser.add_argument("-o", "--output", nargs='?', const='', help=t("commands.shared.help_output"))
    useranom_parser.add_argument("-r", "--show-rate-limit", action="store_true", help=argparse.SUPPRESS)
    useranom_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def useranom_help(args):
        HelpPrinter.print_help(
            "commands.user_anomaly.usage",
            "commands.user_anomaly.description",
            examples_key="commands.user_anomaly.examples"
        )
    useranom_parser.set_defaults(func=cmd_user_anomaly, help_func=useranom_help)
    content_parser = subparsers.add_parser(
        "content-audit",
        description="Audit repo for license, security.md, docs, etc.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    content_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    content_parser.add_argument("-o", "--output", nargs='?', const='', help=t("commands.shared.help_output"))
    content_parser.add_argument("-r", "--show-rate-limit", action="store_true", help=argparse.SUPPRESS)
    content_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def content_help(args):
        HelpPrinter.print_help(
            "commands.content_audit.usage",
            "commands.content_audit.description",
            examples_key="commands.content_audit.examples"
        )
    content_parser.set_defaults(func=cmd_content_audit, help_func=content_help)
    actions_parser = subparsers.add_parser(
        "actions-audit",
        description="Audit GitHub Actions/CI workflows for security.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    actions_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    actions_parser.add_argument("-o", "--output", nargs='?', const='', help=t("commands.shared.help_output"))
    actions_parser.add_argument("-r", "--show-rate-limit", action="store_true", help=argparse.SUPPRESS)
    actions_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def actions_help(args):
        HelpPrinter.print_help(
            "commands.actions_audit.usage",
            "commands.actions_audit.description",
            examples_key="commands.actions_audit.examples"
        )
    actions_parser.set_defaults(func=cmd_actions_audit, help_func=actions_help)
    parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    if len(sys.argv) > 1:
        sys.argv[1] = sys.argv[1].lower()
    args, unknown = parser.parse_known_args()
    if unknown:
        print("")
        Print.error(t("cli.unknown_args", args=' '.join(unknown)))
        print("")
        sys.exit(1)
    if hasattr(args, 'help') and args.help:
        if hasattr(args, 'help_func'):
            args.help_func(args)
        else:
            print_full_help()
    if args.command == "dork-scan" and not args.query and not getattr(args, 'preset', None) and not getattr(args, 'list_presets', False):
        print_error(t("commands.dork_scan.missing_query"))
        sys.exit(1)
    if hasattr(args, 'func'):
        try:
            output_file = getattr(args, 'output', None)
            if output_file is not None:
                if not output_file or output_file == '':
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    cmd = getattr(args, 'command', 'output')
                    filename_parts = [cmd]
                    if hasattr(args, 'repo') and args.repo:
                        repo_name = args.repo.replace('/', '_')
                        filename_parts.append(repo_name)
                    elif hasattr(args, 'username') and args.username:
                        filename_parts.append(args.username)
                    elif hasattr(args, 'query') and args.query:
                        if isinstance(args.query, list):
                            query_str = '_'.join(args.query)[:20]
                        else:
                            query_str = str(args.query)[:20]
                        query_safe = query_str.replace(' ', '_').replace('/', '_')
                        filename_parts.append(query_safe)
                    filename_parts.append(timestamp)
                    output_file = f"{'_'.join(filename_parts)}.txt"
                from exc_analyzer.print_utils import set_output_file
                set_output_file(output_file)
            args.func(args)
            if output_file:
                close_output_file()
        except KeyboardInterrupt:
            print("")
            from exc_analyzer.print_utils import print_cancelled
            print_cancelled(t("commands.shared.scan_cancelled"))
            try:
                close_output_file()
            except Exception:
                pass
            sys.exit(130)  
        except Exception as e:
            try:
                from exc_analyzer.errors import ExcAnalyzerError
                if isinstance(e, ExcAnalyzerError):
                    error_msg = str(e)
                else:
                    error_msg = t("commands.shared.error_occurred", error=str(e))
                print_error(error_msg)
            except Exception as ex:
                try:
                    from exc_analyzer.print_utils import print_critical_error
                    print_critical_error(str(e))
                except:
                    print(f"FATAL ERROR: {e}")
            try:
                close_output_file()
            except Exception:
                pass
            from exc_analyzer.logging_utils import log
            log(f"Command error: {e}")
            sys.exit(1)
    else:
        print_full_help()
