from exc_analyzer.commands import file_history


def test_format_commit_date_valid_iso():
    commit_data = {"author": {"date": "2024-03-10T14:22:31Z"}}

    result = file_history._format_commit_date(commit_data)

    assert result == "2024-03-10"


def test_format_commit_date_invalid_falls_back_prefix():
    commit_data = {"author": {"date": "2024/03/10 14:22:31"}}

    result = file_history._format_commit_date(commit_data)

    assert result == "2024/03/10"


def test_format_commit_date_missing_returns_dash():
    result = file_history._format_commit_date({})

    assert result == "-"
