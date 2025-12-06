import os

# Home and config paths shared across the package
HOME_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME_DIR, ".exc")
LOG_FILE = os.path.join(CONFIG_DIR, "exc.log")
