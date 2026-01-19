import os
HOME_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME_DIR, ".exc")
LOG_FILE = os.path.join(CONFIG_DIR, "exc.log")
CLIENT_ID = "Ov23li5ckngNd4fu4gO1"
DEVICE_CODE_URL = "https://github.com/login/device/code"
ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
AUTH_SCOPES = "repo read:org read:user user:email workflow"
