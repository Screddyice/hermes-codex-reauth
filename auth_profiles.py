"""Read/write openai-codex tokens into openclaw's auth-profiles.json files
and into Codex CLI 0.128.0+'s native `~/.codex/auth.json` store.

Scope: only the `openai-codex:codex-cli` slot in openclaw, and only the
`tokens` block (plus `last_refresh`) in the Codex CLI native file. Other
providers and other fields are left alone.
"""
from __future__ import annotations

import glob
import json
import os
import time

from codex_oauth import (
    CodexTokens,
    expires_ms_from_jwt,
    id_token_expires_ms_from_jwt,
)

PROFILE_KEY = "openai-codex:codex-cli"
PROVIDER_NAME = "openai-codex"
DEFAULT_GLOBS = [
    "~/.openclaw/auth-profiles.json",
    "~/.openclaw/agents/*/agent/auth-profiles.json",
]
CODEX_CLI_AUTH_PATH = "~/.codex/auth.json"


def discover_paths(globs: list[str] | None = None) -> list[str]:
    out: list[str] = []
    for g in globs or DEFAULT_GLOBS:
        out.extend(glob.glob(os.path.expanduser(g)))
    return out


def read_current(paths: list[str]) -> dict | None:
    """Return the freshest (longest-expiring) existing codex profile, or None."""
    best: dict | None = None
    best_expires = 0
    for p in paths:
        try:
            with open(p) as f:
                d = json.load(f)
        except Exception:
            continue
        prof = d.get("profiles", {}).get(PROFILE_KEY)
        if not prof:
            continue
        exp = int(prof.get("expires", 0))
        if exp > best_expires:
            best_expires = exp
            best = prof
    return best


def write_tokens(paths: list[str], tokens: CodexTokens) -> int:
    """Overwrite the codex profile slot in all given auth-profiles.json files.

    Returns the number of files successfully updated.
    """
    new_profile = tokens.to_openclaw_profile()
    updated = 0
    for p in paths:
        try:
            with open(p) as f:
                d = json.load(f)
        except Exception:
            continue
        d.setdefault("profiles", {})[PROFILE_KEY] = new_profile
        d.get("profiles", {}).pop(f"{PROVIDER_NAME}:api_key", None)
        # `lastGood` is canonically a dict keyed by provider, but older hand-seeded
        # files sometimes set it to a bare PROFILE_KEY string. Normalize defensively
        # so we don't crash with TypeError on the first headless reauth.
        if not isinstance(d.get("lastGood"), dict):
            d["lastGood"] = {}
        d["lastGood"][PROVIDER_NAME] = PROFILE_KEY
        try:
            with open(p, "w") as f:
                json.dump(d, f)
            updated += 1
        except Exception:
            pass
    return updated


def write_token_cache(cache_path: str, tokens: CodexTokens) -> None:
    """Update ~/.openclaw/oauth-token-cache.json (used by legacy refresh cron)."""
    cache_path = os.path.expanduser(cache_path)
    try:
        with open(cache_path) as f:
            c = json.load(f)
    except Exception:
        c = {}
    c["access"] = tokens.access
    c["refresh"] = tokens.refresh
    c["expires"] = tokens.expires_ms
    with open(cache_path, "w") as f:
        json.dump(c, f)


# ----------------------------- Codex CLI native (~/.codex/auth.json) ---------
def read_codex_cli_native(path: str = CODEX_CLI_AUTH_PATH) -> dict | None:
    """Read tokens from Codex CLI's native auth.json, return an openclaw-shaped
    profile dict (so callers can treat it identically to read_current's output).

    Returns None if the file is missing, malformed, or has no tokens.
    """
    p = os.path.expanduser(path)
    try:
        with open(p) as f:
            d = json.load(f)
    except Exception:
        return None
    tokens = d.get("tokens") or {}
    access = tokens.get("access_token")
    refresh = tokens.get("refresh_token")
    if not access or not refresh:
        return None
    expires_ms = expires_ms_from_jwt(access)
    # Surface the id_token's TTL alongside the access token's so the watchdog can
    # gate health on the SOONER of the two. 0 means "no id_token present" — the
    # health gate treats that as nothing-to-enforce, not as expired.
    id_expires_ms = id_token_expires_ms_from_jwt(tokens.get("id_token") or "")
    profile: dict = {
        "type": "oauth",
        "provider": PROVIDER_NAME,
        "mode": "oauth",
        "access": access,
        "refresh": refresh,
        "expires": expires_ms,
        "id_token_expires": id_expires_ms,
        "scopes": ["openid", "profile", "email", "offline_access"],
    }
    if tokens.get("account_id"):
        profile["accountId"] = tokens["account_id"]
    return profile


def write_codex_cli_native(
    tokens: CodexTokens,
    path: str = CODEX_CLI_AUTH_PATH,
    *,
    create_if_missing: bool = False,
) -> bool:
    """Merge fresh tokens into Codex CLI's native auth.json.

    Preserves any non-token fields already in the file (`auth_mode`,
    `OPENAI_API_KEY`, etc.).

    id_token merge policy (the rot-prevention rule):
      - If the fresh `tokens.id_token` is present, write it (it is current).
      - Else, inspect the pre-existing id_token:
          * still valid (exp > now) → keep it untouched.
          * EXPIRED → drop it entirely (`pop`) so a dead id_token can never be
            re-persisted, and stamp `needs_reauth = True` on the store so the
            watchdog can detect that refresh-alone could not heal it and must
            escalate to a full interactive login.
      - If a fresh id_token IS present, clear any stale `needs_reauth` flag.

    By default this is a no-op when the file is missing — the watchdog should
    not invent a Codex CLI install where one doesn't exist. Pass
    create_if_missing=True from the fresh-login flows (codex_reauth_server,
    codex_reauth_mac) to seed the file on first auth.

    Returns True if the file was written, False otherwise.
    """
    p = os.path.expanduser(path)
    if not os.path.exists(p) and not create_if_missing:
        return False
    try:
        with open(p) as f:
            d = json.load(f)
    except Exception:
        d = {}
    if create_if_missing and not d:
        # Seed minimal scaffolding — mirrors the shape Codex CLI 0.128.0 writes
        # after `codex login` with a ChatGPT account.
        d = {"OPENAI_API_KEY": None, "auth_mode": "chatgpt", "tokens": {}}
    existing = d.get("tokens") or {}
    existing["access_token"] = tokens.access
    existing["refresh_token"] = tokens.refresh
    if tokens.id_token:
        # Fresh id_token — write it and clear any prior needs-reauth signal.
        existing["id_token"] = tokens.id_token
        d.pop("needs_reauth", None)
    else:
        # Refresh response omitted id_token. Decide on the EXISTING one rather
        # than blindly preserving it (the old bug that let id_tokens rot).
        stale = existing.get("id_token")
        if stale:
            id_exp_ms = id_token_expires_ms_from_jwt(stale)
            now_ms = int(time.time() * 1000)
            if id_exp_ms and id_exp_ms <= now_ms:
                # Dead id_token: never re-persist it, and signal needs-reauth so
                # the watchdog escalates to a full login that mints a fresh one.
                existing.pop("id_token", None)
                d["needs_reauth"] = True
            # else: still-valid id_token → leave it in place untouched.
    if tokens.account_id:
        existing["account_id"] = tokens.account_id
    d["tokens"] = existing
    d["last_refresh"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            json.dump(d, f)
        os.chmod(p, 0o600)
        return True
    except Exception:
        return False
