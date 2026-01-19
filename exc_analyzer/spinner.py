"""Loading spinner for CLI operations."""
import sys
import threading
import time
from .print_utils import COLOR_ENABLED
class Spinner:
    """Thread-based loading spinner for CLI."""
    FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    @staticmethod
    def _is_powershell():
        """Check if running in PowerShell."""
        import os
        return os.environ.get('PSModulePath') is not None or \
               'powershell' in os.environ.get('PROMPT', '').lower() or \
               'pwsh' in os.environ.get('PROMPT', '').lower()
    def __init__(self, message="Loading", color='96'):
        """
        Initialize spinner.
        Args:
            message: Text to display alongside spinner
            color: ANSI color code (default: cyan 96)
        """
        self.message = message
        self.color = color
        self._stop_event = threading.Event()
        self._thread = None
        self._frame_index = 0
        self._is_powershell = self._is_powershell()
    def _spin(self):
        """Internal spinner loop (runs in thread)."""
        import shutil
        last_len = 0
        try:
            while not self._stop_event.is_set():
                frame = self.FRAMES[self._frame_index % len(self.FRAMES)]
                cols = shutil.get_terminal_size((80, 20)).columns
                max_msg_len = max(5, cols - 5) 
                msg = self.message
                current_len = len(f"{frame} {msg}")
                if current_len > max_msg_len:
                    available = max_msg_len - len(f"{frame} ...")
                    if available > 0:
                        msg = msg[:available] + "..."
                    else:
                        msg = "..."
                if COLOR_ENABLED:
                    output = f"\r\033[K\033[{self.color}m{frame}\033[0m {msg}"
                else:
                    output = f"\r{frame} {msg}"
                    prev_len = last_len
                    curr_len = len(output)
                    if curr_len < prev_len:
                         output += " " * (prev_len - curr_len)
                sys.stdout.write(output)
                sys.stdout.flush()
                if COLOR_ENABLED:
                    last_len = len(f"{frame} {msg}") + 5 
                else:
                    last_len = len(output)
                self._frame_index += 1
                time.sleep(0.1)
        except Exception:
            pass
        finally:
            try:
                if COLOR_ENABLED:
                    sys.stdout.write('\r\033[K')
                else:
                    sys.stdout.write('\r' + ' ' * max(last_len, 40) + '\r')
                sys.stdout.flush()
            except Exception:
                pass
    def start(self):
        """Start the spinner animation."""
        if self._thread is not None:
            return  
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
    def stop(self, final_message=None):
        """
        Stop the spinner animation.
        Args:
            final_message: Optional message to display after stopping
        """
        if self._thread is None:
            return  
        self._stop_event.set()
        self._thread.join(timeout=0.5)
        self._thread = None
        sys.stdout.write('\r')
        if COLOR_ENABLED:
             sys.stdout.write('\033[K')
        sys.stdout.flush()
        if final_message:
            print(final_message)
    def update_message(self, new_message):
        """Update spinner message while running."""
        self.message = new_message
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
        return False
def spinner(message="Loading", color='96'):
    """
    Create a spinner context manager.
    Usage:
        with spinner("Fetching data"):
            # Long running operation
            time.sleep(5)
    Args:
        message: Text to display
        color: ANSI color code
    Returns:
        Spinner instance
    """
    return Spinner(message, color)
