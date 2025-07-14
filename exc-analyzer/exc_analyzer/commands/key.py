# key.py
import sys
import getpass
from ..print_utils import Print
from ..config import save_key, load_key, delete_key, validate_key


def show_instructions():
    print("")
    print("To authenticate with GitHub, you need a personal access token.")
    print("")
    Print.info("You can generate one at the following address: ")
    Print.link("https://github.com/settings/personal-access-tokens")
    print("")


def prompt_for_key() -> str:
    Print.info("You can paste your key by right-clicking or pressing Ctrl+V.")
    Print.success("Enter your GitHub API key (input hidden): ")
    key = getpass.getpass("").strip()
    return key




def validate_and_save_key(key: str):
    if not key:
        Print.warn("API key cannot be empty.")
        return

    Print.action("Validating API key...")
    if validate_key(key):
        save_key(key)
    else:
        Print.error("Invalid API key. The key was not saved.")


def reset_key():
    delete_key()
    Print.success("API key has been reset.")


def cmd_key(args):
    if args.reset:
        reset_key()
        return

    key = args.key
    if not key:
        show_instructions()
        key = prompt_for_key()

    validate_and_save_key(key)
