import argparse
import sys
import difflib
from exc_analyzer.logging_utils import main as logging_main
from exc_analyzer.print_utils import Print, COLOR_ENABLED, colorize
from exc_analyzer.logging_utils import log
from exc_analyzer.config import delete_key
from exc_analyzer.api import notify_new_version
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
from exc_analyzer.i18n import t



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
        error_text = t("cli.invalid_command")
        print(colorize(error_text, '91') if COLOR_ENABLED else error_text)
        if suggestion:
            print("")
            suggestion_text = t("cli.invalid_command_suggestion", command=suggestion)
            print(colorize(suggestion_text, '93') if COLOR_ENABLED else suggestion_text)
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
    Print.success(c("  exc key      <your_api_key> ", cyan) + c(t("cli.min_help.key_desc"), yellow))
    Print.success(c("  exc key --migrate (-m)    ", cyan) + c(t("cli.min_help.migrate_desc"), yellow))
    Print.success(c("  exc analysis <owner/repo> ", cyan) + c(t("cli.min_help.analysis_desc"), yellow))
    Print.success(c("  exc user-a   <username> ", cyan) + c(t("cli.min_help.user_desc"), yellow))
    print("")
    Print.info(c(t("cli.min_help.help_hint"), yellow))
    Print.info(c(t("cli.min_help.detail_hint"), yellow))
    print("")
    sys.exit(0)


def print_full_help():
    cyan = '96' if COLOR_ENABLED else None
    yellow = '93' if COLOR_ENABLED else None

    def c(text, code):
        return colorize(text, code) if code else text

    print("")
    Print.success(t("cli.full_help.title"))
    print("")
    print(t("cli.full_help.common_header"))
    print(c("  exc key {your_api_key}                ", cyan) + c(t("commands.key.desc_short"), yellow))
    print(c("  exc analysis <owner/repo>             ", cyan) + c(t("commands.analysis.desc_short"), yellow))
    print(c("  exc scan-secrets <owner/repo>         ", cyan) + c(t("commands.scan_secrets.desc_short"), yellow))
    print(c("  exc file-history <owner/repo> <file>  ", cyan) + c(t("commands.file_history.desc_short"), yellow))
    print(c("  exc user-a <username>                 ", cyan) + c(t("commands.user_a.desc_short"), yellow))
    print("")
    print(t("cli.full_help.security_header"))
    print(c("  exc dork-scan <dork_query>            ", cyan) + c(t("commands.dork_scan.desc_short"), yellow))
    print(c("  exc advanced-secrets <owner/repo>     ", cyan) + c(t("commands.advanced_secrets.desc_short"), yellow))
    print(c("  exc security-score <owner/repo>       ", cyan) + c(t("commands.security_score.desc_short"), yellow))
    print(c("  exc commit-anomaly <owner/repo>       ", cyan) + c(t("commands.commit_anomaly.desc_short"), yellow))
    print(c("  exc user-anomaly <username>           ", cyan) + c(t("commands.user_anomaly.desc_short"), yellow))
    print(c("  exc content-audit <owner/repo>        ", cyan) + c(t("commands.content_audit.desc_short"), yellow))
    print(c("  exc actions-audit <owner/repo>        ", cyan) + c(t("commands.actions_audit.desc_short"), yellow))
    print("")
    print(t("cli.full_help.general_options_header"))
    print(c("  --version  (-v)    ", cyan) + c(t("cli.general_options.version"), yellow))
    print(c("  --verbose  (-V)    ", cyan) + c(t("cli.general_options.verbose"), yellow))
    print(c("  --reset    (-r)    ", cyan) + c(t("cli.general_options.reset"), yellow))
    print(c("  --migrate  (-m)    ", cyan) + c(t("cli.general_options.migrate"), yellow))
    print(c("  --lang     (-L)    ", cyan) + c(t("cli.general_options.lang"), yellow))
    print("")
    Print.info(c(t("cli.full_help.info_hint"), yellow))
    print("")
    notify_new_version()
    print("")
    sys.exit(0)
    
def main():
    try:
        logging_main()
    except Exception as e:
        try:
            from exc_analyzer.errors import ExcAnalyzerError
            from exc_analyzer.print_utils import Print
            if isinstance(e, ExcAnalyzerError):
                Print.error(str(e))
            else:
                Print.error(f"Fatal error: {e}")
        except Exception:
            print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
