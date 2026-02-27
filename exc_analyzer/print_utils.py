import sys
import os
import ctypes
import subprocess
VERBOSE = False
_OUTPUT_FILE = None
_OUTPUT_STATS = {'lines': 0, 'bytes': 0}
_WRITE_ERROR_SHOWN = False
def _enable_windows_vt_mode():
    """Enable Virtual Terminal Processing on Windows for ANSI/\r support."""
    if os.name != 'nt':
        return
    try:
        kernel32 = ctypes.windll.kernel32
        hStdOut = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(hStdOut, ctypes.byref(mode)):
            return
        if not (mode.value & 0x0004):
            kernel32.SetConsoleMode(hStdOut, mode.value | 0x0004)
    except Exception as e:
        try:
            from exc_analyzer.logging_utils import log
            log(f"Windows VT mode enable failed: {e}")
        except Exception:
            if VERBOSE:
                sys.stderr.write(f"[WARN] Windows VT mode enable failed: {e}\n")
_enable_windows_vt_mode()
def supports_color():
    plat = sys.platform
    if plat == 'win32':
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    supported_platform = plat != 'Pocket PC' and (plat != 'win32' or 'ANSICON' in os.environ or 'WT_SESSION' in os.environ or 'TERM' in os.environ)
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    return supported_platform and is_a_tty
COLOR_ENABLED = supports_color()
def colorize(text, color_code):
    if COLOR_ENABLED:
        return f"\033[{color_code}m{text}\033[0m"
    return text
def _strip_ansi(text):
    """Remove ANSI color codes from text."""
    import re
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    osc_escape = re.compile(r'\x1B\].*?(?:\x07|\x1B\\)')
    text = ansi_escape.sub('', text)
    return osc_escape.sub('', text)
def clear_screen():
    """Clear the terminal screen."""
    if os.name == 'nt':
        subprocess.run(['cmd', '/c', 'cls'], capture_output=True, check=False)
    else:
        subprocess.run(['clear'], capture_output=True, check=False)
def set_output_file(filepath):
    """Set output file for saving CLI output."""
    global _OUTPUT_FILE, _OUTPUT_STATS, _WRITE_ERROR_SHOWN
    from exc_analyzer.i18n import t
    if filepath:
        try:
            _OUTPUT_FILE = open(filepath, 'w', encoding='utf-8')
            _OUTPUT_STATS = {'lines': 0, 'bytes': 0}
            _WRITE_ERROR_SHOWN = False
        except PermissionError:
            from exc_analyzer.logging_utils import log
            Print.warn(t("commands.shared.permission_denied"))
            log(f"Output file permission error: {filepath}")
            _OUTPUT_FILE = None
        except Exception as e:
            from exc_analyzer.logging_utils import log
            error_msg = t("commands.shared.output_file_error", filepath=filepath, error=str(e))
            Print.warn(error_msg)
            log(f"Output file error: {filepath}: {e}")
            _OUTPUT_FILE = None
    else:
        _OUTPUT_FILE = None
def close_output_file():
    """Close output file if it's open."""
    global _OUTPUT_FILE, _OUTPUT_STATS
    from exc_analyzer.i18n import t
    from exc_analyzer.helpers import format_size
    if _OUTPUT_FILE:
        try:
            filepath = _OUTPUT_FILE.name
            lines_count = _OUTPUT_STATS['lines']
            bytes_count = _OUTPUT_STATS['bytes']
            _OUTPUT_FILE.close()
            _OUTPUT_FILE = None  
            size_str = format_size(bytes_count)
            Print.success(t("output.file_closed_stats", 
                          filepath=filepath, 
                          lines=lines_count, 
                          size=size_str))
        except Exception as e:
            from exc_analyzer.logging_utils import log
            log(f"Output file close stats failed: {e}")
        _OUTPUT_FILE = None
def _write_output(text):
    """Write to output file without colors."""
    global _OUTPUT_FILE, _OUTPUT_STATS, _WRITE_ERROR_SHOWN
    if _OUTPUT_FILE:
        try:
            clean_text = _strip_ansi(str(text))
            _OUTPUT_FILE.write(clean_text + '\n')
            _OUTPUT_FILE.flush()
            _OUTPUT_STATS['lines'] += 1
            _OUTPUT_STATS['bytes'] += len(clean_text) + 1  
        except Exception as e:
            if not _WRITE_ERROR_SHOWN:
                from exc_analyzer.i18n import t
                Print.warn(t("commands.shared.output_write_error", error=str(e)))
                _WRITE_ERROR_SHOWN = True
            from exc_analyzer.logging_utils import log
            log(f"Output write error: {e}")
def safe_print(text='', **kwargs):
    """Print text with Unicode encoding error handling."""
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        try:
            encoded = text.encode('utf-8', errors='replace').decode('utf-8')
            print(encoded, **kwargs)
        except Exception:
            encoded_ascii = str(text).encode('ascii', errors='replace').decode('ascii')
            print(encoded_ascii, **kwargs)
    _write_output(text)
class Print:
    @staticmethod
    def success(msg, **kwargs):
        from exc_analyzer.i18n import t
        prefix = t("log_levels.success")
        colored_msg = colorize(f"[{prefix}] {msg}", '92')
        try:
            print(colored_msg, **kwargs)
        except UnicodeEncodeError:
            print(colored_msg.encode('utf-8', errors='replace').decode('utf-8'), **kwargs)
        _write_output(f"[{prefix}] {msg}")
    @staticmethod
    def error(msg, **kwargs):
        from exc_analyzer.i18n import t
        prefix = t("log_levels.error")
        colored_msg = colorize(f"[{prefix}] {msg}", '91')
        try:
            print(colored_msg, **kwargs)
        except UnicodeEncodeError:
            print(colored_msg.encode('utf-8', errors='replace').decode('utf-8'), **kwargs)
        _write_output(f"[{prefix}] {msg}")
    @staticmethod
    def warn(msg, **kwargs):
        from exc_analyzer.i18n import t
        prefix = t("log_levels.warn")
        colored_msg = colorize(f"[{prefix}] {msg}", '93')
        try:
            print(colored_msg, **kwargs)
        except UnicodeEncodeError:
            print(colored_msg.encode('utf-8', errors='replace').decode('utf-8'), **kwargs)
        _write_output(f"[{prefix}] {msg}")
    @staticmethod
    def info(msg, **kwargs):
        from exc_analyzer.i18n import t
        prefix = t("log_levels.info")
        colored_msg = colorize(f"[{prefix}] {msg}", '96')
        try:
            print(colored_msg, **kwargs)
        except UnicodeEncodeError:
            print(colored_msg.encode('utf-8', errors='replace').decode('utf-8'), **kwargs)
        _write_output(f"[{prefix}] {msg}")
    @staticmethod
    def action(msg, **kwargs):
        from exc_analyzer.i18n import t
        prefix = t("log_levels.action")
        colored_msg = colorize(f"[{prefix}] {msg}", '90')
        try:
            print(colored_msg, **kwargs)
        except UnicodeEncodeError:
            print(colored_msg.encode('utf-8', errors='replace').decode('utf-8'), **kwargs)
        _write_output(f"[{prefix}] {msg}")
    @staticmethod
    def critical_error(msg, **kwargs):
        from exc_analyzer.i18n import t
        prefix = t("log_levels.critical_error")
        colored_msg = colorize(f"[{prefix}] {msg}", '1;91')
        try:
            print(colored_msg, **kwargs)
        except UnicodeEncodeError:
            print(colored_msg.encode('utf-8', errors='replace').decode('utf-8'), **kwargs)
        _write_output(f"[{prefix}] {msg}")
    @staticmethod
    def cancelled(msg, **kwargs):
        from exc_analyzer.i18n import t
        prefix = t("log_levels.cancelled")
        colored_msg = colorize(f"[{prefix}] {msg}", '90')
        try:
            print(colored_msg, **kwargs)
        except UnicodeEncodeError:
            print(colored_msg.encode('utf-8', errors='replace').decode('utf-8'), **kwargs)
        _write_output(f"[{prefix}] {msg}")
    @staticmethod
    def link(url, **kwargs):
        colored_msg = colorize(url, '94')
        try:
            print(colored_msg, **kwargs)
        except UnicodeEncodeError:
            print(colored_msg.encode('utf-8', errors='replace').decode('utf-8'), **kwargs)
        _write_output(url)
    @staticmethod
    def hyperlink(text, url, **kwargs):
        """Print clickable hyperlink (OSC 8) with shortened text."""
        colored_text = colorize(text, '33')
        if COLOR_ENABLED:
            link_seq = f"\033]8;;{url}\033\\{colored_text}\033]8;;\033\\"
        else:
            link_seq = f"{text} ({url})"
        try:
            print(link_seq, **kwargs)
        except UnicodeEncodeError:
            print(link_seq.encode('utf-8', errors='replace').decode('utf-8'), **kwargs)
        _write_output(f"{text} ({url})")
    @staticmethod
    def colorize(text, color_code):
        return f"\033[{color_code}m{text}\033[0m"
def print_success(msg): Print.success(msg)
def print_error(msg): Print.error(msg)
def print_warning(msg): Print.warn(msg)
def print_info(msg): Print.info(msg)
def print_action(msg): Print.action(msg)
def print_cancelled(msg): Print.cancelled(msg)
def print_critical_error(msg): Print.critical_error(msg)
def set_verbose(v: bool):
    """Set verbose flag for printing/logging."""
    global VERBOSE
    VERBOSE = bool(v)
_original_print = print
def _print_wrapper(*args, **kwargs):
    """Wrapper for print() that also writes to output file."""
    _original_print(*args, **kwargs)
    if _OUTPUT_FILE:
        try:
            text = ' '.join(str(arg) for arg in args)
            clean_text = _strip_ansi(text)
            _OUTPUT_FILE.write(clean_text + '\n')
            _OUTPUT_FILE.flush()
        except Exception as e:
            if VERBOSE:
                _original_print(f"[WARN] Output mirror failed: {e}")
