"""OpenAI Codex OAuth primitives.

Everything in this module is pure HTTP + crypto — no browser, no Gmail, no
file I/O. It mirrors the flow from the bundled openclaw pi-ai library at
  node_modules/@mariozechner/pi-ai/dist/utils/oauth/openai-codex.js

The three operations used by the re-auth scripts:

  build_authorize_url()     — returns (url, verifier, state) for PKCE flow
  exchange_code(...)        — authorization_code -> access + refresh tokens
  refresh_access_token(...) — refresh_token -> new access + refresh tokens
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
REDIRECT_URI = "http://localhost:1455/auth/callback"
SCOPE = "openid profile email offline_access"
JWT_CLAIM_PATH = "https://api.openai.com/auth"


@dataclass
class CodexTokens:
    access: str
    refresh: str
    expires_ms: int  # epoch ms
    account_id: str | None
    id_token: str | None = None

    def to_hermes_profile(self) -> dict:
        """Serialize into the shape openclaw expects at profile slot
        `openai-codex:codex-cli` inside auth-profiles.json."""
        return {
            "type": "oauth",
            "provider": "openai-codex",
            "mode": "oauth",
            "access": self.access,
            "refresh": self.refresh,
            "expires": self.expires_ms,
            "scopes": SCOPE.split(),
            **({"accountId": self.account_id} if self.account_id else {}),
        }

    def to_codex_cli_tokens(self) -> dict:
        """Token block compatible with the `tokens` field of ~/.codex/auth.json
        (Codex CLI 0.128.0+'s native ChatGPT-OAuth store)."""
        block: dict = {
            "access_token": self.access,
            "refresh_token": self.refresh,
        }
        if self.id_token:
            block["id_token"] = self.id_token
        if self.account_id:
            block["account_id"] = self.account_id
        return block


# ------------------------------------------------------------------ PKCE
def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_pkce() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


# --------------------------------------------------------- authorize URL
def build_authorize_url(originator: str = "pi") -> tuple[str, str, str]:
    verifier, challenge = generate_pkce()
    state = secrets.token_hex(16)
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "originator": originator,
    }
    return f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}", verifier, state


# ----------------------------------------------------------- token calls
def _post_token(body: dict) -> dict:
    data = urllib.parse.urlencode(body).encode()
    req = urllib.request.Request(
        TOKEN_URL,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "openclaw-codex-reauth/1.0",
        },
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=20)
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode()
        except Exception:
            pass
        raise RuntimeError(f"OpenAI token endpoint {e.code}: {err_body[:300]}")
    return json.loads(resp.read())


def exchange_code(code: str, verifier: str) -> CodexTokens:
    result = _post_token({
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": REDIRECT_URI,
    })
    return _parse_tokens(result)


def refresh_access_token(refresh_token: str) -> CodexTokens:
    # CRITICAL: send `scope` (openid ...) and `id_token_add_organizations` on the
    # refresh grant, exactly as build_authorize_url does. Without the openid
    # scope OpenAI's refresh_token grant returns NO id_token, so a long-lived
    # access token rolls forward while the id_token silently rots. Mirroring the
    # authorize params here makes every successful refresh mint a fresh id_token.
    result = _post_token({
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token,
        "scope": SCOPE,
        "id_token_add_organizations": "true",
    })
    # OpenAI may omit refresh_token on refresh if unchanged; keep caller's
    # refresh in that case so we don't lose rotation chain.
    if "refresh_token" not in result:
        result["refresh_token"] = refresh_token
    return _parse_tokens(result)


def _parse_tokens(result: dict) -> CodexTokens:
    if not result.get("access_token") or not result.get("refresh_token"):
        raise RuntimeError(f"Incomplete token response: {json.dumps(result)[:300]}")
    expires_in = int(result.get("expires_in", 3600))
    access = result["access_token"]
    return CodexTokens(
        access=access,
        refresh=result["refresh_token"],
        expires_ms=int(time.time() * 1000) + expires_in * 1000 - 60_000,
        account_id=_account_id_from_jwt(access),
        id_token=result.get("id_token"),
    )


def _exp_ms_from_jwt(token: str) -> int:
    """Decode any JWT's `exp` claim (seconds) and return it as epoch ms.

    Returns 0 on any failure: empty/None token, malformed JWT, or missing/
    non-numeric exp. Shared by the access-token and id-token readers.
    """
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            return int(exp * 1000)
    except Exception:
        pass
    return 0


def expires_ms_from_jwt(access_token: str) -> int:
    """Read the `exp` claim (seconds) from a JWT access_token, return epoch ms.

    Used when reading tokens from `~/.codex/auth.json`, which has no explicit
    `expires` field but does carry a JWT we can decode locally.
    """
    return _exp_ms_from_jwt(access_token)


def id_token_expires_ms_from_jwt(id_token: str) -> int:
    """Read the `exp` claim (seconds) from a JWT id_token, return epoch ms.

    Lets the watchdog/health gate and the merge layer detect a rotting id_token
    (the access token can stay healthy while the id_token expires). Returns 0
    when the id_token is missing or undecodable, which callers treat as
    "no id_token TTL to enforce".
    """
    return _exp_ms_from_jwt(id_token)


def _account_id_from_jwt(access_token: str) -> str | None:
    try:
        payload_b64 = access_token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        auth = payload.get(JWT_CLAIM_PATH) or {}
        acct = auth.get("chatgpt_account_id")
        return acct if isinstance(acct, str) and acct else None
    except Exception:
        return None
