import sys
import os
import argparse
from datetime import datetime
from exc_analyzer.config import CONFIG_DIR
from exc_analyzer.print_utils import VERBOSE, LOG_FILE
from exc_analyzer.print_utils import Print, COLOR_ENABLED, colorize
from exc_analyzer.config import delete_key
from exc_analyzer.api import notify_new_version, get_version_from_pyproject
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


# ---------------------
# Logging function
# ---------------------

def log(msg):
    if VERBOSE:
        Print.info(msg)
    try:
        if os.path.isfile(LOG_FILE) and os.path.getsize(LOG_FILE) > 1024*1024: # Log file rotation (max 1MB)
            os.remove(LOG_FILE)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    except Exception as e:
        if VERBOSE:
            Print.warn(f"Log file error: {e}")

# ---------------------
# Helper Functions
# ---------------------

def main():
    from exc_analyzer.main import print_minimal_help, print_full_help, SilentArgumentParser
    global VERBOSE
   
    if "--version" in sys.argv or "-v" in sys.argv:
        notify_new_version()
        print("")
        local_version = get_version_from_pyproject() or "ersion information missing."
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
        VERBOSE = True
        Print.warn("Verbose mode enabled.")
        sys.argv = [a for a in sys.argv if a not in ["--verbose", "-V"]]

    parser = SilentArgumentParser(
        prog="exc",
        usage="",
        description="",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    subparsers = parser.add_subparsers(dest="command")

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
    key_parser.add_argument("-h", "--help", action="store_true", help=argparse.SUPPRESS)
    def key_help(args):
        print("""
\033[96mUsage: exc key [API_KEY] [-r|--reset]\033[0m

Manage your GitHub API key securely.

\033[93mExamples:\033[0m
  exc key                # Securely input and save your API key
  exc key --reset        # Delete the stored API key

If you run 'exc key' without an argument, you will be prompted to enter your key securely (input is hidden).
""")
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
        print("""
\033[96mUsage: exc analysis <owner/repo>\033[0m

Performs a detailed analysis of a GitHub repository: code quality, security, dependencies, and statistics.

\033[93mExample:\033[0m
  exc analysis torvalds/linux
""")
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
        print("""
\033[96mUsage: exc user-a <github_username>\033[0m

Analyzes a user's contribution profile: commit patterns, code ownership, and top repositories.

\033[93mExample:\033[0m
  exc user-a octocat
""")
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
        print("""
\033[96mUsage: exc scan-secrets <owner/repo> [-l N]\033[0m

Scans the last N commits (default 10) for secrets like API keys, AWS credentials, SSH keys, and tokens.

\033[93mExample:\033[0m
  exc scan-secrets torvalds/linux -l 50

\033[93mOptions:\033[0m
  -l, --limit   Number of recent commits to scan (default: 10)
""")
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
        print("""
\033[96mUsage: exc file-history <owner/repo> <path_to_file>\033[0m

Displays the full change history of a specific file (commit, author, date, message).

\033[93mExample:\033[0m
  exc file-history torvalds/linux kernel/sched/core.c
""")
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
        print("""
\033[96mUsage: exc dork-scan <dork_query> [options]\033[0m

Scan public GitHub code for sensitive keywords, secrets, or configuration files using advanced dorking techniques.

\033[93mExamples:\033[0m
  exc dork-scan brgkdm

\033[93mOptions:\033[0m
  <dork_query>         The search query (can be multiple words, quoted if needed)
  -n, --num N          Number of results to show (default: 10, max: 100)
  -h, --help           Show this help message and exit

\033[93mDescription:\033[0m
  This command allows you to search public GitHub repositories for exposed secrets, API keys, tokens, or sensitive files
  using custom search queries (dorks). You can combine keywords, file extensions, and filename filters for more precise results.

\033[93mTips:\033[0m
  - Use quotes for multi-word queries (e.g. "sensitive key")
  - Results include repository, file path, and direct link to the file on GitHub

\033[96mFor more info: https://github.com/exc-analyzer/exc\033[0m
""")
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
        print("""
\033[96mUsage: exc advanced-secrets <owner/repo> [-l N]\033[0m

Scans repository files and the last N commits for a wide range of secret patterns (API keys, tokens, config files, etc.).

\033[93mOptions:\033[0m
  -l, --limit   Number of recent commits to scan (default: 20)

\033[93mExample:\033[0m
  exc advanced-secrets torvalds/linux -l 30
""")
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
        print("""
\033[96mUsage: exc security-score <owner/repo>\033[0m

Calculates a security score for the repository based on open issues, branch protection, security.md, license, dependabot, code scanning, and more.

\033[93mExample:\033[0m
  exc security-score torvalds/linux
""")
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
        print("""
\033[96mUsage: exc commit-anomaly <owner/repo>\033[0m

Analyzes commit messages and PRs for suspicious or risky activity.

\033[93mExample:\033[0m
  exc commit-anomaly torvalds/linux
""")
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
        print("""
\033[96mUsage: exc user-anomaly <github_username>\033[0m

Detects unusual activity or anomalies in a user's GitHub activity.

\033[93mExample:\033[0m
  exc user-anomaly octocat
""")
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
        print("""
\033[96mUsage: exc content-audit <owner/repo>\033[0m

Audits the repository for license, security.md, code of conduct, contributing.md, and documentation quality.

\033[93mExample:\033[0m
  exc content-audit torvalds/linux
""")
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
        print("""
\033[96mUsage: exc actions-audit <owner/repo>\033[0m

Analyzes GitHub Actions/CI workflow files for security risks and best practices.

\033[93mExample:\033[0m
  exc actions-audit torvalds/linux
""")
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
           Print.warn(f"Unrecognized arguments: {' '.join(unknown)}")
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
            Print.error(f"Error executing command: {e}")
            log(f"Command error: {e}")
            sys.exit(1)
    else:
        print_full_help()

if __name__ == "__main__":
    main()
