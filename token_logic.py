"""
token_logic.py — Pure decision functions for OpenClaw OAuth management.
No I/O, no side effects. Easy to test and reason about.
"""


def token_health(expires_ms: int, now_ms: int) -> str:
    """Classify token health based on expiry timestamp.
    Returns: 'OK', 'LOW', 'CRITICAL', 'EXPIRED', or 'NO_TOKEN'.
    """
    if expires_ms <= 0:
        return "NO_TOKEN"
    if expires_ms <= now_ms:
        return "EXPIRED"
    remaining_hours = (expires_ms - now_ms) / 3600000
    if remaining_hours < 1.0:
        return "CRITICAL"
    if remaining_hours < 3.0:
        return "LOW"
    return "OK"


def should_self_refresh(local_expires, s3_expires, last_attempt, now, cooldown_ms):
    """Whether to attempt API self-refresh. Rate-limited by cooldown_ms.
    Returns True only when both local AND S3 tokens are expired AND no recent attempt within cooldown.
    """
    if local_expires is not None and local_expires > now:
        return False
    if s3_expires is not None and s3_expires > now:
        return False
    attempt_ts = last_attempt or 0
    if attempt_ts > 0 and (now - attempt_ts) <= cooldown_ms:
        return False
    return True


def should_update_from_s3(s3_expires, local_expires, now):
    """Whether local token should be replaced with S3 token."""
    if s3_expires <= now:
        return False
    if s3_expires <= local_expires:
        return False
    return True


def needs_profile_cleanup(profile: dict, provider_profile: str) -> bool:
    """Whether auth-profiles.json needs stale entries removed."""
    profiles = profile.get("profiles", {})
    provider_name = provider_profile.split(":")[0]
    api_key_name = f"{provider_name}:api_key"
    if api_key_name in profiles:
        return True
    last_good = profile.get("lastGood", {})
    if last_good.get(provider_name) != provider_profile:
        return True
    return False


def should_headless_recover(last_attempt_ms: int, now_ms: int, cooldown_ms: int) -> bool:
    """Whether headless recovery is allowed (outside cooldown window)."""
    if last_attempt_ms <= 0:
        return True
    return (now_ms - last_attempt_ms) > cooldown_ms
