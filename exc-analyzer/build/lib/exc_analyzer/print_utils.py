import sys
import os
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".exc_analyzer")
VERBOSE = False
LOG_FILE = os.path.join(CONFIG_DIR, "exc.log")
# ---------------------
# CliOutput and Color Support
# ---------------------

def supports_color():
    plat = sys.platform
    supported_platform = plat != 'Pocket PC' and (plat != 'win32' or 'ANSICON' in os.environ or 'WT_SESSION' in os.environ or 'TERM' in os.environ)
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    return supported_platform and is_a_tty

COLOR_ENABLED = supports_color()

def colorize(text, color_code):
    if COLOR_ENABLED:
        return f"\033[{color_code}m{text}\033[0m"
    return text

class Print:
    @staticmethod
    def success(msg):
        print(colorize(f"[+] {msg}", '92'))

    @staticmethod
    def error(msg):
        print(colorize(f"[ERROR] {msg}", '91'))

    @staticmethod
    def warn(msg):
        print(colorize(f"[WARN] {msg}", '93'))

    @staticmethod
    def info(msg):
        print(colorize(f"[*] {msg}", '96'))

    @staticmethod
    def action(msg):
        print(colorize(f"[>] {msg}", '90')) 

    @staticmethod
    def link(url):
        print(colorize(url, '94'))
    @staticmethod
    def colorize(text, color_code):
        return f"\033[{color_code}m{text}\033[0m"


