from types import SimpleNamespace

from exc_analyzer.commands import user_a


def test_user_a_requires_username(capsys):
    args = SimpleNamespace(username=None)
    user_a.cmd_user_a(args)
    out = capsys.readouterr().out
    assert "Username missing" in out
    assert "Usage: exc user-a" in out