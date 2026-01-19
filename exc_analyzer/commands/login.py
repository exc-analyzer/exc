import sys
import webbrowser
import time
from exc_analyzer.print_utils import print_info, print_success, print_warning, print_error, print_action, print_cancelled, safe_print, colorize, clear_screen, _write_output
from exc_analyzer.i18n import t, get_active_language
from exc_analyzer.api import exchange_device_code, poll_for_token, fetch_github_user
from exc_analyzer.config import save_key
from exc_analyzer.spinner import Spinner
def cmd_login(args):
    """
    Handle the GitHub Device Flow login.
    """
    from exc_analyzer.config import load_key
    existing_key = load_key()
    if existing_key:
        user = fetch_github_user(existing_key)
        if user:
            safe_print("")
            _write_output("")
            print_success(t("commands.login.already_logged_in", user=colorize(user, '1')))
            safe_print("")
            _write_output("")
            safe_print(t("commands.login.already_login_hint"))
            _write_output(t("commands.login.already_login_hint"))
            safe_print("")
            _write_output("")
            sys.exit(0)
    safe_print("")
    _write_output("")
    disclaimer = t("commands.login.security_disclaimer")
    safe_print(colorize(disclaimer, '90'))
    _write_output(disclaimer)
    safe_print("")
    _write_output("")
    agree_text = colorize(t("commands.login.agree_prompt"), '97')
    try:
        if sys.version_info.major < 3:
            response = raw_input(agree_text)
        else:
            response = input(agree_text)
    except KeyboardInterrupt:
        clear_screen()
        print_cancelled(t("commands.login.cancelled"))
        safe_print("")
        sys.exit(0)
    lang = get_active_language()
    valid_responses = ['y', 'yes']
    if lang == 'tr':
        valid_responses = ['e', 'evet']
    if response.lower() not in valid_responses:
        clear_screen()
        print_cancelled(t("commands.login.cancelled"))
        safe_print("")
        sys.exit(0)
    device_data = exchange_device_code()
    if not device_data:
        sys.exit(1)
    user_code = device_data['user_code']
    verification_uri = device_data['verification_uri']
    interval = device_data['interval']
    device_code = device_data['device_code']
    safe_print("\n" + "="*40)
    _write_output("\n" + "="*40)
    print_action(t("commands.login.otp_code", code=colorize(user_code, '93')))
    safe_print("="*40 + "\n")
    _write_output("="*40 + "\n")
    try:
        import pyperclip
        pyperclip.copy(user_code)
        print_success(t("commands.login.clipboard_copy"))
    except ImportError:
        pass
    except Exception:
        pass
    safe_print(f"URL: {colorize(verification_uri, '96')}\n")
    _write_output(f"URL: {verification_uri}\n")
    try:
        sys.stdout.flush()
        input(t("commands.login.open_browser"))
    except KeyboardInterrupt:
        clear_screen()
        print_cancelled(t("commands.login.cancelled"))
        safe_print("")
        sys.exit(0)
    webbrowser.open(verification_uri)
    token = None
    try:
        with Spinner(t("commands.login.waiting")):
            token = poll_for_token(device_code, interval)
    except KeyboardInterrupt:
        clear_screen()
        print_cancelled(t("commands.login.cancelled"))
        safe_print("")
        sys.exit(0)
    sys.stdout.flush()
    if token:
        clear_screen()
        save_key(token, silent=True)
        user = fetch_github_user(token) or "Unknown"
        print_success(t("commands.login.success", user=colorize(user, '1')))
        hint = t("commands.login.suggestion")
        safe_print(colorize(hint, '93'))
        _write_output(hint)
        safe_print("")
        _write_output("")
    else:
        clear_screen()
        print_cancelled(t("commands.login.cancelled"))
        safe_print("")
        sys.exit(1)
