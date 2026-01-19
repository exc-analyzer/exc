from exc_analyzer.config import delete_key
from exc_analyzer.i18n import t
from exc_analyzer.print_utils import Print, colorize
def cmd_logout(args):
    """
    Handle the logout process (delete stored API key).
    """
    from exc_analyzer.config import load_key
    if not load_key():
        from exc_analyzer.print_utils import print_warning, safe_print, _write_output
        safe_print("")
        _write_output("")
        print_warning(t("commands.logout.not_logged_in"))
        safe_print("")
        _write_output("")
        return
    from exc_analyzer.print_utils import print_info, print_success, safe_print, _write_output
    safe_print("")
    _write_output("")
    delete_key()
    print_success(t("commands.logout.success"))
    print_info(t("commands.logout.hint"))
    safe_print("")
    _write_output("")
