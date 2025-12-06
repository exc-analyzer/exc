from types import SimpleNamespace

from exc_analyzer.commands import key as key_cmd


def test_cmd_key_saves_valid_token(monkeypatch, capsys):
    saved = {}
    monkeypatch.setattr(key_cmd, "validate_key", lambda token: True)
    monkeypatch.setattr(key_cmd, "save_key", lambda token: saved.setdefault("value", token))

    args = SimpleNamespace(key="ghp_valid_token", reset=False, migrate=False)
    key_cmd.cmd_key(args)

    out = capsys.readouterr().out
    assert saved["value"] == "ghp_valid_token"
    assert "Validating API key" in out


def test_cmd_key_rejects_invalid_token(monkeypatch, capsys):
    monkeypatch.setattr(key_cmd, "validate_key", lambda token: False)

    called = {}

    def fake_save(token):
        called["value"] = token

    monkeypatch.setattr(key_cmd, "save_key", fake_save)

    args = SimpleNamespace(key="ghp_invalid", reset=False, migrate=False)
    key_cmd.cmd_key(args)

    out = capsys.readouterr().out
    assert "Invalid API key" in out
    assert "value" not in called
