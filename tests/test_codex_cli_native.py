"""Verify read/write contract for Codex CLI 0.128.0+'s native ~/.codex/auth.json.

Locks in:
  - read returns openclaw-shaped profile when the file is valid
  - read returns None when missing or malformed
  - write merges into existing file preserving non-token fields
  - write no-ops on missing file unless create_if_missing=True
  - a still-valid id_token is preserved across refresh-style writes that omit it
  - an EXPIRED id_token is dropped (never re-persisted) and needs_reauth is set
  - read surfaces id_token_expires alongside the access expiry
"""
from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _jwt(exp_seconds: int) -> str:
    """Build a fake JWT with given exp claim. Header/signature are placeholders."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": exp_seconds, "https://api.openai.com/auth": {"chatgpt_account_id": "acct_xyz"}}).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def test_read_returns_none_when_missing(tmp_path):
    from auth_profiles import read_codex_cli_native
    assert read_codex_cli_native(str(tmp_path / "nope.json")) is None


def test_read_returns_profile_shape_when_valid(tmp_path):
    from auth_profiles import read_codex_cli_native
    f = tmp_path / "auth.json"
    exp_s = int(time.time()) + 3600
    f.write_text(json.dumps({
        "OPENAI_API_KEY": None,
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": _jwt(exp_s),
            "refresh_token": "rt_abc",
            "id_token": "idt_abc",
            "account_id": "acct_xyz",
        },
        "last_refresh": "2026-05-04T00:00:00Z",
    }))
    p = read_codex_cli_native(str(f))
    assert p is not None
    assert p["provider"] == "openai-codex"
    assert p["mode"] == "oauth"
    assert p["access"].startswith("ey")
    assert p["refresh"] == "rt_abc"
    assert p["accountId"] == "acct_xyz"
    assert p["expires"] == exp_s * 1000


def test_write_no_op_when_missing(tmp_path):
    from auth_profiles import write_codex_cli_native
    from codex_oauth import CodexTokens
    target = tmp_path / "auth.json"
    tokens = CodexTokens(access="a", refresh="r", expires_ms=1, account_id=None)
    assert write_codex_cli_native(tokens, str(target)) is False
    assert not target.exists()


def test_write_merges_preserving_non_token_fields(tmp_path):
    """A refresh that omits id_token must preserve a STILL-VALID existing one,
    while updating the access/refresh/account fields and last_refresh."""
    from auth_profiles import write_codex_cli_native
    from codex_oauth import CodexTokens
    target = tmp_path / "auth.json"
    valid_idt = _jwt(int(time.time()) + 3600)  # id_token good for another hour
    target.write_text(json.dumps({
        "OPENAI_API_KEY": None,
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": "old_at",
            "refresh_token": "old_rt",
            "id_token": valid_idt,
            "account_id": "acct_old",
        },
        "last_refresh": "old",
    }))
    tokens = CodexTokens(
        access="new_at", refresh="new_rt",
        expires_ms=int(time.time() * 1000) + 3600_000,
        account_id="acct_new",
        id_token=None,  # simulate refresh response that omitted id_token
    )
    assert write_codex_cli_native(tokens, str(target)) is True
    d = json.loads(target.read_text())
    assert d["OPENAI_API_KEY"] is None
    assert d["auth_mode"] == "chatgpt"
    assert d["tokens"]["access_token"] == "new_at"
    assert d["tokens"]["refresh_token"] == "new_rt"
    assert d["tokens"]["id_token"] == valid_idt, "a still-valid id_token must be preserved when refresh omits it"
    assert d["tokens"]["account_id"] == "acct_new"
    assert d["last_refresh"] != "old"
    assert "needs_reauth" not in d, "a valid id_token must not trigger needs_reauth"


def test_write_drops_expired_id_token_and_flags_reauth(tmp_path):
    """REGRESSION GUARD for the id_token-rot bug: a refresh that omits id_token
    must NOT re-persist an EXPIRED id_token. The dead token is dropped and the
    store is stamped needs_reauth so the watchdog escalates to a full login.

    Before the fix, write_codex_cli_native preserved the stale id_token
    unconditionally (`if tokens.id_token: ...` with no else), so an expired
    id_token rolled forward forever while the access token stayed fresh.
    """
    from auth_profiles import write_codex_cli_native
    from codex_oauth import CodexTokens
    target = tmp_path / "auth.json"
    expired_idt = _jwt(int(time.time()) - 3600)  # id_token expired an hour ago
    target.write_text(json.dumps({
        "OPENAI_API_KEY": None,
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": "old_at",
            "refresh_token": "old_rt",
            "id_token": expired_idt,
            "account_id": "acct_old",
        },
        "last_refresh": "old",
    }))
    tokens = CodexTokens(
        access="new_at", refresh="new_rt",
        expires_ms=int(time.time() * 1000) + 3600_000,
        account_id="acct_new",
        id_token=None,  # refresh response omitted id_token (the rot scenario)
    )
    assert write_codex_cli_native(tokens, str(target)) is True
    d = json.loads(target.read_text())
    assert "id_token" not in d["tokens"], "an EXPIRED id_token must be dropped, never re-persisted"
    assert d.get("needs_reauth") is True, "dropping a dead id_token must signal needs_reauth"
    # access/refresh still rolled forward as usual.
    assert d["tokens"]["access_token"] == "new_at"
    assert d["tokens"]["refresh_token"] == "new_rt"


def test_write_fresh_id_token_clears_needs_reauth(tmp_path):
    """When a fresh id_token IS supplied, it is written and any prior
    needs_reauth flag is cleared."""
    from auth_profiles import write_codex_cli_native
    from codex_oauth import CodexTokens
    target = tmp_path / "auth.json"
    target.write_text(json.dumps({
        "OPENAI_API_KEY": None,
        "auth_mode": "chatgpt",
        "needs_reauth": True,  # left over from a prior rotted-out refresh
        "tokens": {"access_token": "old_at", "refresh_token": "old_rt"},
        "last_refresh": "old",
    }))
    fresh_idt = _jwt(int(time.time()) + 7200)
    tokens = CodexTokens(
        access="new_at", refresh="new_rt",
        expires_ms=int(time.time() * 1000) + 3600_000,
        account_id="acct", id_token=fresh_idt,
    )
    assert write_codex_cli_native(tokens, str(target)) is True
    d = json.loads(target.read_text())
    assert d["tokens"]["id_token"] == fresh_idt
    assert "needs_reauth" not in d, "a fresh id_token must clear the needs_reauth signal"


def test_read_surfaces_id_token_expiry(tmp_path):
    """read_codex_cli_native must expose id_token_expires so the watchdog can
    gate health on the sooner of access/id_token TTL."""
    from auth_profiles import read_codex_cli_native
    f = tmp_path / "auth.json"
    access_exp = int(time.time()) + 3600
    id_exp = int(time.time()) - 100  # id_token already expired
    f.write_text(json.dumps({
        "OPENAI_API_KEY": None,
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": _jwt(access_exp),
            "refresh_token": "rt_abc",
            "id_token": _jwt(id_exp),
            "account_id": "acct_xyz",
        },
    }))
    p = read_codex_cli_native(str(f))
    assert p is not None
    assert p["expires"] == access_exp * 1000
    assert p["id_token_expires"] == id_exp * 1000
    # Sanity: id_token TTL is earlier than access TTL -> watchdog will refresh.
    assert p["id_token_expires"] < p["expires"]


def test_read_id_token_expires_zero_when_absent(tmp_path):
    """No id_token present -> id_token_expires is 0 (watchdog treats as
    nothing-to-enforce, not as expired)."""
    from auth_profiles import read_codex_cli_native
    f = tmp_path / "auth.json"
    f.write_text(json.dumps({
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": _jwt(int(time.time()) + 3600),
            "refresh_token": "rt_abc",
        },
    }))
    p = read_codex_cli_native(str(f))
    assert p is not None
    assert p["id_token_expires"] == 0


def test_write_creates_when_missing_and_flag_set(tmp_path):
    from auth_profiles import write_codex_cli_native
    from codex_oauth import CodexTokens
    target = tmp_path / "subdir" / "auth.json"
    tokens = CodexTokens(
        access="at", refresh="rt",
        expires_ms=int(time.time() * 1000) + 3600_000,
        account_id="acct", id_token="idt",
    )
    assert write_codex_cli_native(tokens, str(target), create_if_missing=True) is True
    assert target.exists()
    d = json.loads(target.read_text())
    assert d["auth_mode"] == "chatgpt"
    assert d["tokens"]["access_token"] == "at"
    assert d["tokens"]["id_token"] == "idt"
    # Permissions should be 0600 since this file holds secrets
    import stat
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


def test_to_codex_cli_tokens_shape():
    from codex_oauth import CodexTokens
    tokens = CodexTokens(
        access="at", refresh="rt", expires_ms=0,
        account_id="acct", id_token="idt",
    )
    block = tokens.to_codex_cli_tokens()
    assert block == {
        "access_token": "at",
        "refresh_token": "rt",
        "id_token": "idt",
        "account_id": "acct",
    }


def test_to_codex_cli_tokens_omits_optional_fields():
    from codex_oauth import CodexTokens
    tokens = CodexTokens(access="at", refresh="rt", expires_ms=0, account_id=None)
    block = tokens.to_codex_cli_tokens()
    assert block == {"access_token": "at", "refresh_token": "rt"}
