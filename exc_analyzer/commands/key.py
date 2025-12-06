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


def migrate_key():
    # Try to migrate existing stored key into keyring (if available)
    import os
    import shutil
    from datetime import datetime

    try:
        from ..config import load_key, KEYRING_AVAILABLE, KEY_FILE
    except Exception:
        Print.error("Migration not available: config import failed.")
        return

    Print.info("Starting key migration...")

    # Check if any key stored at all (file or keyring)
    file_exists = os.path.isfile(KEY_FILE)
    file_key = None
    if file_exists:
        try:
            with open(KEY_FILE, 'r', encoding='utf-8') as f:
                encoded = f.read()
            import base64
            file_key = base64.b64decode(encoded).decode('utf-8')
        except Exception:
            Print.warn("Could not read existing key file. Migration aborted.")
            return

    # If keyring not available, advise user
    if not KEYRING_AVAILABLE:
        Print.warn("OS credential store (keyring) not available on this system.")
        Print.info("To enable migration, install the 'keyring' package: e.g. pip install keyring")
        if file_exists:
            Print.info("Your key remains stored in the local fallback file. Consider installing keyring and re-running this command to migrate.")
        else:
            Print.info("No stored key found to migrate.")
        return

    # KEYRING_AVAILABLE == True
    try:
        import keyring
    except Exception:
        Print.warn("Keyring import failed despite availability flag. Migration cannot continue.")
        return

    # Check if key already in keyring
    try:
        existing_keyring = keyring.get_password("exc-analyzer", "github_token")
    except Exception:
        existing_keyring = None

    if existing_keyring:
        Print.info("A key already exists in the OS credential store.")
        # If file exists and matches, we can remove file safely after backup
        if file_exists and file_key and file_key == existing_keyring:
            Print.action("Existing file key matches OS credential store. Removing file fallback after backup...")
            try:
                ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
                backup_path = f"{KEY_FILE}.bak.{ts}"
                shutil.copy2(KEY_FILE, backup_path)
                os.remove(KEY_FILE)
                Print.success(f"Backup created: {backup_path} and fallback file removed.")
            except Exception as e:
                Print.warn(f"Could not remove file fallback: {e}")
        else:
            Print.info("No action taken. If you want to overwrite the OS credential entry, delete it first and re-run migration.")
        return

    # No key in keyring; migrate from file if present
    if not file_exists:
        Print.info("No stored key found to migrate.")
        return

    if not file_key:
        Print.warn("Stored key could not be read. Migration aborted.")
        return

    Print.action("Migrating key from local fallback file to OS credential store...")
    try:
        # store into keyring
        keyring.set_password("exc-analyzer", "github_token", file_key)
    except Exception as e:
        Print.error(f"Failed to save key to OS credential store: {e}")
        return

    # backup and remove file fallback
    try:
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        backup_path = f"{KEY_FILE}.bak.{ts}"
        shutil.copy2(KEY_FILE, backup_path)
        os.remove(KEY_FILE)
        Print.success(f"Key migrated successfully. Backup of previous file created at: {backup_path}")
        Print.info("Your API key is now stored in the OS credential store.")
    except Exception as e:
        Print.warn(f"Key saved to OS credential store, but failed to remove local fallback: {e}")
        Print.info("You may remove the local key file manually to complete migration.")


def cmd_key(args):
    if getattr(args, 'migrate', False):
        migrate_key()
        return

    if args.reset:
        reset_key()
        return

    key = args.key
    if not key:
        show_instructions()
        key = prompt_for_key()

    validate_and_save_key(key)
