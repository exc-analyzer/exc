import pytest
import sys
from unittest.mock import patch
from exc_analyzer.cli import main_cli, _extract_cli_language
def test_extract_cli_language():
    assert _extract_cli_language(["ex.py", "--lang", "tr"]) == "tr"
    assert _extract_cli_language(["ex.py", "-L", "en"]) == "en"
    assert _extract_cli_language(["ex.py", "--lang=fr"]) == "fr"
    assert _extract_cli_language(["ex.py", "analysis"]) is None
def test_cli_help(capsys):
    with patch.object(sys, 'argv', ["exc", "--help"]):
        with pytest.raises(SystemExit) as e:
            main_cli()
        assert e.value.code == 0
        out, err = capsys.readouterr()
        # Baslik ceviriliyor, komut adlari cevrilmiyor.
        #
        # Bu satir once "EXC ANALYZER" / "Common Usage" ariyordu ve testi
        # gelistiricinin dil tercihine bagimli kiliyordu: `exc --lang tr`
        # calistirmis biri "[+] EXC Komut Yardimi" gorur ve test kirilir.
        # CI'da varsayilan Ingilizce oldugu icin orada gecip yerelde
        # kaliyordu. Ayni dosyadaki test_cli_no_args zaten dogru deseni
        # kullaniyor: cevrilmeyen komut adlarina bakiyor.
        assert "exc login" in out
        assert "exc analysis" in out
def test_cli_version(capsys):
    with patch.object(sys, 'argv', ["exc", "--version"]):
        with pytest.raises(SystemExit) as e:
            main_cli()
        assert e.value.code == 0
        out, err = capsys.readouterr()
        assert "EXC Analyzer v" in out
def test_cli_no_args(capsys):
    with patch.object(sys, 'argv', ["exc"]):
        with pytest.raises(SystemExit) as e:
            main_cli()
        assert e.value.code == 0
        out, err = capsys.readouterr()
        assert "exc login" in out
        assert "exc analysis" in out
def test_cli_invalid_command(capsys):
    with patch.object(sys, 'argv', ["exc", "invalid-cmd"]):
        with pytest.raises(SystemExit) as e:
            main_cli()
        assert e.value.code == 2
        out, _ = capsys.readouterr()
        assert "Invalid command" in out or "Geçersiz komut" in out 
