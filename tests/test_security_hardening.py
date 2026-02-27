import subprocess
import base64

import pytest

from exc_analyzer import config
from exc_analyzer import print_utils
from exc_analyzer.errors import ExcAnalyzerError


def test_ensure_config_dir_windows_grants_current_user(monkeypatch, tmp_path):
    cfg_dir = tmp_path / "cfg"
    monkeypatch.setattr(config, "CONFIG_DIR", str(cfg_dir))
    monkeypatch.setattr(config.os, "name", "nt", raising=False)
    monkeypatch.setenv("USERNAME", "ci_user")

    called = {}

    def fake_run(args, capture_output, check):
        called["args"] = args

    monkeypatch.setattr(subprocess, "run", fake_run)

    config.ensure_config_dir()

    assert called["args"][0] == "icacls"
    assert "ci_user:(OI)(CI)F" in called["args"]
    assert "%username%:(OI)(CI)F" not in called["args"]


def test_clear_screen_uses_subprocess_on_windows(monkeypatch):
    monkeypatch.setattr(print_utils.os, "name", "nt", raising=False)
    called = {}

    def fake_run(args, capture_output, check):
        called["args"] = args

    monkeypatch.setattr(print_utils.subprocess, "run", fake_run)

    print_utils.clear_screen()

    assert called["args"] == ["cmd", "/c", "cls"]


@pytest.mark.parametrize("os_name", ["nt", "posix"])
def test_save_key_requires_os_keyring(monkeypatch, os_name):
    monkeypatch.setattr(config.os, "name", os_name, raising=False)
    monkeypatch.setattr(config, "KEYRING_AVAILABLE", False)

    with pytest.raises(ExcAnalyzerError):
        config.save_key("ghp_xxx", silent=True)


def test_load_key_migrates_legacy_file_to_keyring(monkeypatch, tmp_path):
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    legacy_file = cfg_dir / "build.sec"
    legacy_file.write_text(base64.b64encode("legacy_token".encode("utf-8")).decode("utf-8"), encoding="utf-8")

    monkeypatch.setattr(config, "CONFIG_DIR", str(cfg_dir))
    monkeypatch.setattr(config, "KEY_FILE", str(legacy_file))
    monkeypatch.setattr(config, "KEYRING_AVAILABLE", True)

    stored = {}

    class DummyKeyring:
        @staticmethod
        def set_password(service, user, value):
            stored[(service, user)] = value

        @staticmethod
        def get_password(service, user):
            return stored.get((service, user))

    monkeypatch.setattr(config, "keyring", DummyKeyring)

    token = config.load_key()

    assert token == "legacy_token"
    assert stored[(config.KEYRING_SERVICE, config.KEYRING_USER)] == "legacy_token"
    assert not legacy_file.exists()


def test_load_key_returns_none_when_keyring_backend_broken(monkeypatch, tmp_path):
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "CONFIG_DIR", str(cfg_dir))
    monkeypatch.setattr(config, "KEY_FILE", str(cfg_dir / "build.sec"))
    monkeypatch.setattr(config, "KEYRING_AVAILABLE", True)

    class BrokenKeyring:
        @staticmethod
        def get_password(service, user):
            raise RuntimeError("backend unavailable")

        @staticmethod
        def set_password(service, user, value):
            raise RuntimeError("backend unavailable")

    monkeypatch.setattr(config, "keyring", BrokenKeyring)

    assert config.load_key() is None


def test_delete_key_legacy_cleanup_when_backend_broken(monkeypatch, tmp_path):
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    legacy_file = cfg_dir / "build.sec"
    legacy_file.write_text("legacy", encoding="utf-8")

    monkeypatch.setattr(config, "KEY_FILE", str(legacy_file))
    monkeypatch.setattr(config, "KEYRING_AVAILABLE", True)

    class BrokenKeyring:
        @staticmethod
        def get_password(service, user):
            raise RuntimeError("backend unavailable")

        @staticmethod
        def delete_password(service, user):
            raise RuntimeError("backend unavailable")

    monkeypatch.setattr(config, "keyring", BrokenKeyring)

    removed = config.delete_key()

    assert removed is True
    assert not legacy_file.exists()
