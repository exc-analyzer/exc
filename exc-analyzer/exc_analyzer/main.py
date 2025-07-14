import argparse
import sys
import difflib
from exc_analyzer.logging_utils import main as logging_main
from exc_analyzer.print_utils import Print, COLOR_ENABLED, colorize
from exc_analyzer.logging_utils import log
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
# argparse Argument Parser
# ---------------------

class SilentArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        words = message.split()
        attempted = None
        if 'invalid choice:' in message:
            try:
                attempted = message.split('invalid choice:')[1].split('(')[0].strip().strip("'")
            except Exception:
                attempted = None
        # List of valid commands and their aliases
        commands = {
            'key': ['k', 'kei', 'kee', 'ky', 'kk', 'keey', 'keyy', 'ket', 'keu', 'keg', 'ker'],
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
        print(f"\033[91m[!] Invalid command.\033[0m")
        if suggestion:
            print("")
            print(f"\033[93m[?] Did you mean: exc {suggestion}\033[0m")
            print("")
        sys.exit(2)


# ---------------------
# Minimal and Full Help
# ---------------------

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
         Y888P         EXC ANALYZER – GitHub Security Tool
         d888b                github.com/exc-analyzer
        d88888b   
       d88P Y88b  
      d88P   Y88b 

""", bold))
    Print.success(c("  exc key      <your_api_key> ", cyan) + c("# Manage GitHub API key", yellow))
    Print.success(c("  exc analysis <owner/repo> ", cyan) + c("  # Analyze a repository", yellow))
    Print.success(c("  exc user-a   <username> ", cyan) + c("    # Analyze a GitHub user", yellow))
    print("")
    Print.info(c("  For all commands : exc --help or -h", yellow))
    Print.info(c("  For detailed help: exc <command> --help", yellow))
    print("")
    sys.exit(0)


def print_full_help():
    cyan = '96' if COLOR_ENABLED else None
    yellow = '93' if COLOR_ENABLED else None

    def c(text, code):
        return colorize(text, code) if code else text

    print("")
    Print.success("EXC Help")
    print("")
    print("Common Usage:")
    print(c("  exc key {your_api_key}                ", cyan) + c("# Manage GitHub API key", yellow))
    print(c("  exc analysis <owner/repo>             ", cyan) + c("# Analyze a repository", yellow))
    print(c("  exc scan-secrets <owner/repo>         ", cyan) + c("# Scan for leaked secrets", yellow))
    print(c("  exc file-history <owner/repo> <file>  ", cyan) + c("# Show file change history", yellow))
    print(c("  exc user-a <username>                 ", cyan) + c("# Analyze a GitHub user", yellow))
    print("")
    print("Security & Intelligence:")
    print(c("  exc dork-scan <dork_query>            ", cyan) + c("# GitHub dorking for secrets/configs", yellow))
    print(c("  exc advanced-secrets <owner/repo>     ", cyan) + c("# Advanced secret/config scan", yellow))
    print(c("  exc security-score <owner/repo>       ", cyan) + c("# Repo security scoring", yellow))
    print(c("  exc commit-anomaly <owner/repo>       ", cyan) + c("# Commit/PR anomaly detection", yellow))
    print(c("  exc user-anomaly <username>           ", cyan) + c("# User activity anomaly detection", yellow))
    print(c("  exc content-audit <owner/repo>        ", cyan) + c("# Audit repo content/docs", yellow))
    print(c("  exc actions-audit <owner/repo>        ", cyan) + c("# Audit GitHub Actions/CI security", yellow))
    print("")
    print("General Options:")
    print(c("  --version  (-v)    Show version & update info", cyan))
    print(c("  --verbose  (-V)    Verbose/debug output", cyan))
    print(c("  --reset    (-r)    API Key Reset", cyan))
    print("")
    Print.info(c("For detailed help: exc <command> --help", yellow))
    print("")
    notify_new_version()
    print("")
    sys.exit(0)
    
def main():
    notify_new_version()
    logging_main()

if __name__ == "__main__":
    main()
