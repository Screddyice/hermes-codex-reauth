"""
token_refresh.py — API-based token refresh and auth-profile I/O.
"""
from __future__ import annotations

import glob
import json
import os
import time
import urllib.parse
import urllib.request
import urllib.error


# ── Provider Registry ──────────────────────────────────────────────────

PROVIDERS = {
    "claude": {
        "profile_key": "openai-codex:codex-cli",
        "provider_name": "openai-codex",
        "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
        "token_url": "https://platform.claude.com/v1/oauth/token",
        "api_refresh": True,
    },
    "chatgpt": {
        "profile_key": "openai:oauth",
        "provider_name": "openai",
        "client_id": None,
        "token_url": None,
        "api_refresh": False,
    },
    "gemini": {
        "profile_key": "google-gemini:oauth",
        "provider_name": "google-gemini",
        "client_id": None,
        "client_secret": None,
        "token_url": "https://oauth2.googleapis.com/token",
        "api_refresh": True,
    },
    "perplexity": {
        "profile_key": "perplexity:api_key",
        "provider_name": "perplexity",
        "client_id": None,
        "token_url": None,
        "api_refresh": False,
    },
}


# ── Exceptions ─────────────────────────────────────────────────────────

class TokenRefreshError(Exception):
    """Base class for token refresh failures."""

class InvalidGrantError(TokenRefreshError):
    """Refresh token was revoked or already consumed."""

class ProviderUnavailableError(TokenRefreshError):
    """Provider returned 5xx or timed out."""

class UnsupportedProviderError(TokenRefreshError):
    """Provider does not support API refresh."""


# ── Public API ─────────────────────────────────────────────────────────

def get_profile_key(provider: str) -> str:
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}")
    return PROVIDERS[provider]["profile_key"]


def supports_api_refresh(provider: str) -> bool:
    return PROVIDERS.get(provider, {}).get("api_refresh", False)


def get_provider_name(provider: str) -> str:
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}")
    return PROVIDERS[provider]["provider_name"]


def get_auth_profile_paths() -> list:
    """Glob for all auth-profiles.json files in standard OpenClaw locations."""
    return (
        glob.glob(os.path.expanduser("~/.openclaw/auth-profiles.json"))
        + glob.glob(os.path.expanduser("~/.openclaw/agents/*/agent/auth-profiles.json"))
    )


def find_best_token(paths: list, provider_profile: str) -> dict | None:
    """Scan auth-profiles.json files, return token with longest remaining life."""
    best = None
    best_expires = 0
    for p in paths:
        try:
            with open(p) as f:
                d = json.load(f)
            oauth = d.get("profiles", {}).get(provider_profile, {})
            exp = oauth.get("expires", 0)
            if exp > best_expires:
                best_expires = exp
                best = oauth
        except Exception:
            pass
    return best


def write_tokens(paths: list, provider_profile: str, oauth: dict) -> int:
    """Write new token to all local auth-profiles.json files.
    Cleans up stale api_key entries and sets lastGood. Returns count updated."""
    provider_name = provider_profile.split(":")[0]
    api_key_name = f"{provider_name}:api_key"
    updated = 0
    for p in paths:
        try:
            with open(p) as f:
                d = json.load(f)
            d.setdefault("profiles", {})[provider_profile] = oauth
            d.get("profiles", {}).pop(api_key_name, None)
            d.setdefault("lastGood", {})[provider_name] = provider_profile
            with open(p, "w") as f:
                json.dump(d, f)
            updated += 1
        except Exception:
            pass
    return updated


def refresh_token(provider: str, refresh_tok: str) -> dict:
    """Call provider's OAuth endpoint. Returns {access, refresh, expires, ...}.

    Raises:
      UnsupportedProviderError — provider has no API refresh
      InvalidGrantError — refresh token revoked/consumed
      ProviderUnavailableError — 5xx or timeout
    """
    if not supports_api_refresh(provider):
        raise UnsupportedProviderError(f"{provider} does not support API refresh")

    prov = PROVIDERS[provider]

    if provider == "claude":
        return _refresh_claude(prov, refresh_tok)
    elif provider == "gemini":
        return _refresh_gemini(prov, refresh_tok)
    else:
        raise UnsupportedProviderError(f"No refresh implementation for {provider}")


# ── Private refresh implementations ───────────────────────────────────

def _refresh_claude(prov: dict, refresh_tok: str) -> dict:
    payload = json.dumps({
        "grant_type": "refresh_token",
        "client_id": prov["client_id"],
        "refresh_token": refresh_tok,
    }).encode()
    req = urllib.request.Request(
        prov["token_url"],
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "OpenClawOAuth/1.0"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()
        except Exception:
            pass
        if e.code == 400 or "invalid_grant" in body:
            raise InvalidGrantError(f"HTTP {e.code}: {body[:200]}")
        if e.code >= 500:
            raise ProviderUnavailableError(f"HTTP {e.code}: {body[:200]}")
        raise TokenRefreshError(f"HTTP {e.code}: {body[:200]}")
    except Exception as e:
        raise ProviderUnavailableError(str(e))

    if "access_token" not in result:
        raise TokenRefreshError(f"No access_token in response: {json.dumps(result)[:200]}")

    return {
        "type": "oauth",
        "provider": prov["provider_name"],
        "access": result["access_token"],
        "refresh": result["refresh_token"],
        "expires": int(time.time() * 1000) + result["expires_in"] * 1000 - 5 * 60 * 1000,
        "scopes": ["user:inference", "user:profile"],
    }


def _refresh_gemini(prov: dict, refresh_tok: str) -> dict:
    client_id, client_secret = _get_gemini_credentials(prov)
    payload = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_tok,
    }).encode()
    req = urllib.request.Request(
        prov["token_url"],
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()
        except Exception:
            pass
        if e.code == 400 or "invalid_grant" in body:
            raise InvalidGrantError(f"HTTP {e.code}: {body[:200]}")
        if e.code >= 500:
            raise ProviderUnavailableError(f"HTTP {e.code}: {body[:200]}")
        raise TokenRefreshError(f"HTTP {e.code}: {body[:200]}")
    except Exception as e:
        raise ProviderUnavailableError(str(e))

    if "access_token" not in result:
        raise TokenRefreshError(f"No access_token: {json.dumps(result)[:200]}")

    return {
        "type": "oauth",
        "provider": prov["provider_name"],
        "access": result["access_token"],
        "refresh": result.get("refresh_token", refresh_tok),
        "expires": int(time.time() * 1000) + result.get("expires_in", 3600) * 1000 - 60 * 1000,
        "scopes": ["cloud-platform", "userinfo.email"],
    }


def _get_gemini_credentials(prov: dict) -> tuple:
    """Extract Gemini client ID and secret from installed npm package or fallback."""
    try:
        import subprocess
        result = subprocess.run(
            ["node", "-e",
             "const p=require.resolve('@google/gemini-cli/package.json');"
             "const fs=require('fs');"
             "const d=fs.readFileSync(p.replace('package.json','dist/oauth2.js'),'utf8');"
             "const id=d.match(/client_id['\"]?\\s*[:=]\\s*['\"]([^'\"]+)/);"
             "const sec=d.match(/client_secret['\"]?\\s*[:=]\\s*['\"]([^'\"]+)/);"
             "console.log(JSON.stringify({id:id?.[1],sec:sec?.[1]}))"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout.strip())
            if data.get("id") and data.get("sec"):
                return data["id"], data["sec"]
    except Exception:
        pass
    return (
        prov.get("client_id") or "NOT_CONFIGURED",
        prov.get("client_secret") or "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",
    )
