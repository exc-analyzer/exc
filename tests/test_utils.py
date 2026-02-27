from exc_analyzer.utils import mask_sensitive
def test_mask_sensitive_no_sensitive_data():
    text = "This is a safe string."
    assert mask_sensitive(text) == text
def test_mask_sensitive_github_token():
    token = "ghp_1234567890abcdef1234567890abcdef1234" 
    text = f"My token is {token}"
    masked = mask_sensitive(text)
    assert "ghp_********************" in masked
    assert token not in masked
def test_mask_sensitive_aws_key():
    key = "AWS_SECRET_ACCESS_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    text = f"Config: {key}"
    masked = mask_sensitive(text)
    assert "AWS_SECRET_ACCESS_KEY=***" in masked
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in masked
def test_mask_sensitive_multiple_occurrences():
    token1 = "ghp_111111111111111111111111111111111111"
    token2 = "ghp_222222222222222222222222222222222222"
    text = f"Keys: {token1} and {token2}"
    masked = mask_sensitive(text)
    assert masked.count("ghp_********************") == 2
    assert token1 not in masked
    assert token2 not in masked
def test_mask_sensitive_non_string_input():
    assert mask_sensitive(None) is None
    assert mask_sensitive(123) == 123
