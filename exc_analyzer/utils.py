def mask_sensitive(text: str) -> str:
    """Mask known sensitive patterns before logging/displaying."""
    try:
        import re
        text = re.sub(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}", r"\1_********************", text)
        text = re.sub(r"github_pat_[A-Za-z0-9_]{50,}", "github_pat_********************", text)
        text = re.sub(r"(?i)(aws_secret_access_key\s*[:=]\s*)([A-Za-z0-9/+=]{16,})", r"\1***", text)
        return text
    except Exception:
        return text
