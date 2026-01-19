import os
from datetime import datetime
from exc_analyzer.constants import LOG_FILE
from exc_analyzer.print_utils import Print, VERBOSE
from exc_analyzer.utils import mask_sensitive
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
