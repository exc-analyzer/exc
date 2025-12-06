import sys
import os
import argparse
from datetime import datetime
from exc_analyzer.constants import CONFIG_DIR, LOG_FILE
from exc_analyzer.print_utils import Print, COLOR_ENABLED, colorize, set_verbose, VERBOSE
from exc_analyzer.config import delete_key
from exc_analyzer.api import notify_new_version, get_version_from_pyproject
from exc_analyzer.api import mask_sensitive
from exc_analyzer.commands.key import cmd_key
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
from exc_analyzer.i18n import t, set_language, get_active_language, DEFAULT_LANGUAGE
from exc_analyzer.preferences import get_language_preference, set_language_preference


# ---------------------
# Logging function
# ---------------------

def log(msg):
    try:
        masked = mask_sensitive(str(msg))
    except Exception:
        masked = str(msg)

    if VERBOSE:
        Print.info(masked)
    try:
        log_dir = os.path.dirname(LOG_FILE)
        if not os.path.isdir(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            try:
                os.chmod(log_dir, 0o700)
            except Exception:
                pass
        if os.path.isfile(LOG_FILE) and os.path.getsize(LOG_FILE) > 1024*1024:
            os.remove(LOG_FILE)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat()}] {masked}\n")
        try:
            os.chmod(LOG_FILE, 0o600)
        except Exception:
            pass
    except Exception as e:
        if VERBOSE:
            Print.warn(f"Log file error: {e}")

# ---------------------
# Helper Functions
# ---------------------

def _extract_cli_language(argv):
    lang = None
    for idx, arg in enumerate(argv):
        if arg in ("--lang", "-L"):
            if idx + 1 < len(argv):
                lang = argv[idx + 1]
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

    if saved_lang and set_language(saved_lang):
        return get_active_language()

    set_language(DEFAULT_LANGUAGE)
    return DEFAULT_LANGUAGE

def main():
    from exc_analyzer.main import print_minimal_help, print_full_help, SilentArgumentParser
    global VERBOSE
    configure_language()
    notify_new_version()
   
    if "--version" in sys.argv or "-v" in sys.argv:
        notify_new_version()
        print("")
        local_version = get_version_from_pyproject() or t("cli.version_missing")
        print(f"EXC Analyzer v{local_version}")
        print("")
        sys.exit(0)
        
    if "--reset" in sys.argv or "-r" in sys.argv:
        delete_key()
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
        "-L",
        "--lang",
        metavar=t("cli.lang_option_metavar"),
        help=t("cli.general_options.lang")
    )
    subparsers = parser.add_subparsers(dest="command")

    def _ensure_list(value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _print_block(header_key, items):
        lines = _ensure_list(items)
        if not lines:
            return
        print("")
        print(colorize(t(header_key), '93'))
        for line in lines:
            print(f"  {line}")

    def _print_examples(items):
        lines = _ensure_list(items)
        if not lines:
            return
        header_key = "commands.shared.examples_header" if len(lines) > 1 else "commands.shared.example_header"
        _print_block(header_key, lines)

    def _print_options(items):
        _print_block("commands.shared.options_header", items)

    def _print_details(items):
        _print_block("commands.shared.details_header", items)

    def _print_tips(items):
        _print_block("commands.shared.tips_header", items)

    def _print_description_block(items):
        _print_block("commands.shared.description_header", items)

# ---------------------
# Key Management Command
# ---------------------

    key_parser = subparsers.add_parser(
        "key",
        description="Manage GitHub API keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    key_parser.add_argument("key", nargs="?", help=argparse.SUPPRESS)
    key_parser.add_argument("-r", "--reset", action="store_true", help=argparse.SUPPRESS)
    key_parser.add_argument("-m", "--migrate", action="store_true", help=argparse.SUPPRESS)
    key_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def key_help(args):
        print("")
        print(colorize(t("commands.key.usage"), '96'))
        print("")
        print(t("commands.key.description"))
        _print_examples(t("commands.key.examples"))
        print("")
        print(t("commands.key.prompt_hint"))
        sys.exit(0)
    key_parser.set_defaults(func=cmd_key, help_func=key_help)

# ---------------------
# Repository Analysis Command
# ---------------------

    analysis_parser = subparsers.add_parser(
        "analysis",
        description="Repository analysis: code, security, dependencies, stats.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    analysis_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    analysis_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def analysis_help(args):
        print("")
        print(colorize(t("commands.analysis.usage"), '96'))
        print("")
        print(t("commands.analysis.description"))
        _print_examples(t("commands.analysis.examples"))
        sys.exit(0)
    analysis_parser.set_defaults(func=cmd_analysis, help_func=analysis_help)

# ---------------------
#  User Analysis Command
# ---------------------

    user_parser = subparsers.add_parser(
        "user-a",
        description="Analyze a GitHub user's profile and repositories.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    user_parser.add_argument("username", nargs="?", help=argparse.SUPPRESS)
    user_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def user_help(args):
        print("")
        print(colorize(t("commands.user_a.usage"), '96'))
        print("")
        print(t("commands.user_a.description"))
        _print_examples(t("commands.user_a.examples"))
        _print_details(t("commands.user_a.details"))
        print("")
        print(t("commands.user_a.tip"))
        sys.exit(0)
    user_parser.set_defaults(func=cmd_user_a, help_func=user_help)

# ---------------------
#  Scan Secrets Command
# ---------------------

    scan_parser = subparsers.add_parser(
        "scan-secrets",
        description="Scan recent commits for leaked secrets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    scan_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    scan_parser.add_argument("-l", "--limit", type=int, default=10, help="Number of recent commits to scan (default: 10)")
    scan_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def scan_help(args):
        print("")
        print(colorize(t("commands.scan_secrets.usage"), '96'))
        print("")
        print(t("commands.scan_secrets.description"))
        _print_examples(t("commands.scan_secrets.examples"))
        _print_options(t("commands.scan_secrets.options"))
        sys.exit(0)
    scan_parser.set_defaults(func=cmd_scan_secrets, help_func=scan_help)

# ---------------------
#  File History Command
# ---------------------

    file_parser = subparsers.add_parser(
        "file-history",
        description="Show the change history of a file in a repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    file_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    file_parser.add_argument("filepath", nargs="?", help=argparse.SUPPRESS)
    file_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def file_help(args):
        print("")
        print(colorize(t("commands.file_history.usage"), '96'))
        print("")
        print(t("commands.file_history.description"))
        _print_examples(t("commands.file_history.examples"))
        sys.exit(0)
    file_parser.set_defaults(func=cmd_file_history, help_func=file_help)

# ---------------------
#  Dork Scan Command
# ---------------------

    dork_parser = subparsers.add_parser(
        "dork-scan",
        description="Scan GitHub for sensitive keywords or patterns (dorking).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    dork_parser.add_argument("query", nargs="*", help=argparse.SUPPRESS)
    dork_parser.add_argument("--ext", help="Filter by file extension (e.g. py, json)")
    dork_parser.add_argument("--filename", help="Filter by specific filename")
    dork_parser.add_argument("-n", "--num", type=int, default=10, help="Number of results to show (max 100)")
    dork_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def dork_help(args):
        print("")
        print(colorize(t("commands.dork_scan.usage"), '96'))
        print("")
        print(t("commands.dork_scan.description"))
        _print_examples(t("commands.dork_scan.examples"))
        _print_options(t("commands.dork_scan.options"))
        _print_description_block(t("commands.dork_scan.details"))
        _print_tips(t("commands.dork_scan.tips"))
        print("")
        print(colorize(t("commands.dork_scan.footer"), '96'))
        sys.exit(0)
    dork_parser.set_defaults(func=cmd_dork_scan, help_func=dork_help)

# ---------------------
#  Advanced Secrets Command
# ---------------------

    advsec_parser = subparsers.add_parser(
        "advanced-secrets",
        description="Scan repo for a wide range of secret patterns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    advsec_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    advsec_parser.add_argument("-l", "--limit", type=int, default=20, help="Number of recent commits to scan (default: 20)")
    advsec_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def advsec_help(args):
        print("")
        print(colorize(t("commands.advanced_secrets.usage"), '96'))
        print("")
        print(t("commands.advanced_secrets.description"))
        _print_options(t("commands.advanced_secrets.options"))
        _print_examples(t("commands.advanced_secrets.examples"))
        sys.exit(0)
    advsec_parser.set_defaults(func=cmd_advanced_secrets, help_func=advsec_help)

# ---------------------
#  Security Score Command
# ---------------------

    secscore_parser = subparsers.add_parser(
        "security-score",
        description="Calculate a security score for the repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    secscore_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    secscore_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def secscore_help(args):
        print("")
        print(colorize(t("commands.security_score.usage"), '96'))
        print("")
        print(t("commands.security_score.description"))
        _print_examples(t("commands.security_score.examples"))
        sys.exit(0)
    secscore_parser.set_defaults(func=cmd_security_score, help_func=secscore_help)

# ---------------------
#  Commit Anomaly Command
# ---------------------

    commanom_parser = subparsers.add_parser(
        "commit-anomaly",
        description="Analyze commit/PR activity for anomalies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    commanom_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    commanom_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def commanom_help(args):
        print("")
        print(colorize(t("commands.commit_anomaly.usage"), '96'))
        print("")
        print(t("commands.commit_anomaly.description"))
        _print_examples(t("commands.commit_anomaly.examples"))
        sys.exit(0)
    commanom_parser.set_defaults(func=cmd_commit_anomaly, help_func=commanom_help)

# ---------------------
#  User Anomaly Command
# ---------------------

    useranom_parser = subparsers.add_parser(
        "user-anomaly",
        description="Detect unusual activity in a user's GitHub activity.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    useranom_parser.add_argument("username", nargs="?", help=argparse.SUPPRESS)
    useranom_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def useranom_help(args):
        print("")
        print(colorize(t("commands.user_anomaly.usage"), '96'))
        print("")
        print(t("commands.user_anomaly.description"))
        _print_examples(t("commands.user_anomaly.examples"))
        sys.exit(0)
    useranom_parser.set_defaults(func=cmd_user_anomaly, help_func=useranom_help)

# ---------------------
#  Content Audit Command
# ---------------------

    content_parser = subparsers.add_parser(
        "content-audit",
        description="Audit repo for license, security.md, docs, etc.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    content_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    content_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def content_help(args):
        print("")
        print(colorize(t("commands.content_audit.usage"), '96'))
        print("")
        print(t("commands.content_audit.description"))
        _print_examples(t("commands.content_audit.examples"))
        sys.exit(0)
    content_parser.set_defaults(func=cmd_content_audit, help_func=content_help)

# ---------------------
#  Actions Audit Command
# ---------------------

    actions_parser = subparsers.add_parser(
        "actions-audit",
        description="Audit GitHub Actions/CI workflows for security.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    actions_parser.add_argument("repo", nargs="?", help=argparse.SUPPRESS)
    actions_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def actions_help(args):
        print("")
        print(colorize(t("commands.actions_audit.usage"), '96'))
        print("")
        print(t("commands.actions_audit.description"))
        _print_examples(t("commands.actions_audit.examples"))
        sys.exit(0)
    actions_parser.set_defaults(func=cmd_actions_audit, help_func=actions_help)

# ---------------------
#  -h --help Command
# ---------------------

    parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)

    try:
        if len(sys.argv) > 1:
            sys.argv[1] = sys.argv[1].lower()
        args, unknown = parser.parse_known_args()
        if unknown:
            Print.warn(t("cli.unknown_args", args=' '.join(unknown)))
    except SystemExit:
        return

    if hasattr(args, 'help') and args.help:
        if hasattr(args, 'help_func'):
            args.help_func(args)
        else:
            print_full_help()
    if args.command == "dork-scan" and not args.query:
        print_full_help()
    if hasattr(args, 'func'):
        try:
            args.func(args)
        except Exception as e:
            try:
                from exc_analyzer.errors import ExcAnalyzerError
                if isinstance(e, ExcAnalyzerError):
                    Print.error(str(e))
                else:
                    Print.error(f"Error executing command: {e}")
            except Exception:
                Print.error(f"Error executing command: {e}")
            log(f"Command error: {e}")
            sys.exit(1)
    else:
        print_full_help()

if __name__ == "__main__":
    main()
