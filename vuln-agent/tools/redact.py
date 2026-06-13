import hashlib

SECRET_MASK_KEEP = 4


def redact_secret(secret: str) -> str:
    """保留前後4字元，中間以*遮蔽；用於 gitleaks 找到的密鑰原文，
    避免完整明文進入 LLM prompt 或寫入資料庫/顯示於儀表板"""
    if not secret:
        return ""
    if len(secret) <= SECRET_MASK_KEEP * 2:
        return "*" * len(secret)
    return secret[:SECRET_MASK_KEEP] + "*" * (len(secret) - SECRET_MASK_KEEP * 2) + secret[-SECRET_MASK_KEEP:]


def secret_hash(secret: str) -> str:
    """密鑰的短 hash，供重複偵測比對而不需保留明文"""
    return hashlib.sha256(secret.encode()).hexdigest()[:12] if secret else ""
