"""Regression tests for the id_token-rot defect.

The bug: the access_token rolled forward on every refresh while the id_token
silently expired, because

  1. refresh_access_token() omitted the openid scope, so OpenAI never returned a
     fresh id_token on the refresh grant;
  2. the watchdog health gate read ONLY the access-token TTL, so an
     access-fresh / id_token-expired pair was declared "healthy — no action"
     forever, and the rot could never self-heal.

These tests fail against the old code and pass with the fix.
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
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {"exp": exp_seconds, "https://api.openai.com/auth": {"chatgpt_account_id": "acct_xyz"}}
        ).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


# --------------------------------------------------------------- refresh params
def test_refresh_requests_openid_scope_for_id_token(monkeypatch):
    """refresh_access_token must send scope + id_token_add_organizations so the
    refresh grant returns a fresh id_token. Without these the rot is inevitable."""
    import codex_oauth as oauth

    captured = {}

    def fake_post(body):
        captured.update(body)
        # Echo a fresh id_token back only because the request asked for openid.
        return {
            "access_token": _jwt(int(time.time()) + 3600),
            "refresh_token": "rt_new",
            "id_token": _jwt(int(time.time()) + 3600),
            "expires_in": 3600,
        }

    monkeypatch.setattr(oauth, "_post_token", fake_post)
    tokens = oauth.refresh_access_token("rt_old")

    assert captured["grant_type"] == "refresh_token"
    assert captured.get("scope") == oauth.SCOPE, "refresh must request the openid scope"
    assert "openid" in captured.get("scope", ""), "scope must include openid to mint an id_token"
    assert captured.get("id_token_add_organizations") == "true"
    assert tokens.id_token, "a scoped refresh should yield an id_token"


# ---------------------------------------------------------------- health gate
@pytest.fixture
def watchdog(tmp_path, monkeypatch):
    import codex_watchdog as mod
    # Isolate side-effect files so tests don't touch the real home dir.
    monkeypatch.setattr(mod, "REAUTH_FLAG_FILE", str(tmp_path / "reauth.flag"))
    monkeypatch.setattr(mod, "OAUTH_CACHE", str(tmp_path / "cache.json"))
    return mod


def test_access_fresh_idtoken_expired_is_latent_no_action(watchdog, monkeypatch):
    """Reactive-only (Hermes-safe): access token healthy (+200h) but id_token
    expired.

    The watchdog must do NOTHING — it must NOT rotate the shared OpenAI refresh
    token just to freshen a latent id_token, because that rotation would
    invalidate Hermes' pooled copy of the same account (refresh_token_reused).
    The latent id_token heals for free on the next genuine (access-expiry)
    refresh, which now carries the openid scope.
    """
    mod = watchdog
    now_ms = int(time.time() * 1000)

    # No openclaw profile; force the codex-cli native read path.
    monkeypatch.setattr(mod, "discover_paths", lambda globs: [])
    monkeypatch.setattr(mod, "read_current", lambda paths: None)
    monkeypatch.setattr(
        mod, "read_codex_cli_native",
        lambda *a, **k: {
            "provider": "openai-codex",
            "access": _jwt(int(time.time()) + 200 * 3600),  # healthy
            "refresh": "rt_old",
            "expires": now_ms + 200 * 3_600_000,            # access fine
            "id_token_expires": now_ms - 29 * 3_600_000,    # id_token EXPIRED -29h
        },
    )
    # No Hermes store on this host.
    monkeypatch.setattr(mod, "read_hermes_pool", lambda *a, **k: None)

    refresh_called = {"n": 0}
    monkeypatch.setattr(mod, "refresh_access_token", lambda rt: refresh_called.__setitem__("n", refresh_called["n"] + 1))
    notified = {"n": 0}
    monkeypatch.setattr(mod, "_notify_refresh", lambda *a, **k: notified.__setitem__("n", notified["n"] + 1))
    escalated = {"n": 0}
    monkeypatch.setattr(mod, "_escalate", lambda: escalated.__setitem__("n", escalated["n"] + 1) or 0)

    rc = mod.main()
    assert rc == 0
    assert refresh_called["n"] == 0, "a latent expired id_token must NOT trigger a token rotation (Hermes-safe)"
    assert notified["n"] == 0, "no refresh happened -> no notification"
    assert escalated["n"] == 0


def test_access_expired_refreshes_and_notifies(watchdog, monkeypatch):
    """When the ACCESS token has actually expired, the watchdog refreshes, the
    scoped refresh mints a fresh id_token, and exactly one notification fires
    (a real refresh is the only routine event worth a ping)."""
    mod = watchdog
    now_ms = int(time.time() * 1000)
    monkeypatch.setattr(mod, "discover_paths", lambda globs: [])
    monkeypatch.setattr(mod, "read_current", lambda paths: None)
    monkeypatch.setattr(
        mod, "read_codex_cli_native",
        lambda *a, **k: {
            "provider": "openai-codex",
            "access": _jwt(int(time.time()) - 3600),     # access EXPIRED
            "refresh": "rt_old",
            "expires": now_ms - 3_600_000,
            "id_token_expires": now_ms - 5 * 3_600_000,
        },
    )
    monkeypatch.setattr(mod, "read_hermes_pool", lambda *a, **k: None)

    def fake_refresh(rt):
        from codex_oauth import CodexTokens
        return CodexTokens(
            access=_jwt(int(time.time()) + 3600), refresh="rt_new",
            expires_ms=now_ms + 3_600_000, account_id="acct",
            id_token=_jwt(int(time.time()) + 3600),  # fresh id_token from scoped refresh
        )

    monkeypatch.setattr(mod, "refresh_access_token", fake_refresh)
    monkeypatch.setattr(mod, "write_tokens", lambda paths, t: 0)
    monkeypatch.setattr(mod, "write_token_cache", lambda c, t: None)
    monkeypatch.setattr(mod, "write_codex_cli_native", lambda t: True)
    notified = {"n": 0}
    monkeypatch.setattr(mod, "_notify_refresh", lambda *a, **k: notified.__setitem__("n", notified["n"] + 1))
    rc = mod.main()
    assert rc == 0
    assert notified["n"] == 1, "an actual refresh must notify exactly once"


def test_healthy_tick_is_silent(watchdog, monkeypatch):
    """A fully-healthy tick must not notify (no constant pings)."""
    mod = watchdog
    now_ms = int(time.time() * 1000)
    monkeypatch.setattr(mod, "discover_paths", lambda globs: [])
    monkeypatch.setattr(mod, "read_current", lambda paths: None)
    monkeypatch.setattr(
        mod, "read_codex_cli_native",
        lambda *a, **k: {
            "provider": "openai-codex",
            "access": _jwt(int(time.time()) + 200 * 3600),
            "refresh": "rt_old",
            "expires": now_ms + 200 * 3_600_000,
            "id_token_expires": now_ms + 50 * 3_600_000,
        },
    )
    monkeypatch.setattr(mod, "read_hermes_pool", lambda *a, **k: None)
    notified = {"n": 0}
    monkeypatch.setattr(mod, "_notify_refresh", lambda *a, **k: notified.__setitem__("n", notified["n"] + 1))
    alerted = {"n": 0}
    monkeypatch.setattr(mod, "_alert_slack", lambda *a, **k: alerted.__setitem__("n", alerted["n"] + 1))
    rc = mod.main()
    assert rc == 0
    assert notified["n"] == 0 and alerted["n"] == 0, "healthy tick must be silent"


def test_both_healthy_no_action(watchdog, monkeypatch):
    """Sanity: when both access and id_token are healthy, no refresh happens."""
    mod = watchdog
    now_ms = int(time.time() * 1000)
    monkeypatch.setattr(mod, "discover_paths", lambda globs: [])
    monkeypatch.setattr(mod, "read_current", lambda paths: None)
    monkeypatch.setattr(
        mod, "read_codex_cli_native",
        lambda *a, **k: {
            "provider": "openai-codex",
            "access": _jwt(int(time.time()) + 200 * 3600),
            "refresh": "rt_old",
            "expires": now_ms + 200 * 3_600_000,
            "id_token_expires": now_ms + 50 * 3_600_000,  # id_token healthy too
        },
    )
    refresh_called = {"n": 0}
    monkeypatch.setattr(mod, "refresh_access_token", lambda rt: refresh_called.__setitem__("n", 1))
    rc = mod.main()
    assert rc == 0
    assert refresh_called["n"] == 0, "both tokens healthy -> no refresh"


def test_refresh_without_fresh_id_token_escalates(watchdog, monkeypatch):
    """If access is expired and the refresh STILL fails to return an id_token
    (server-side scope refusal), the watchdog must escalate to full reauth
    rather than returning 0 with a half-fresh store."""
    mod = watchdog
    now_ms = int(time.time() * 1000)
    monkeypatch.setattr(mod, "discover_paths", lambda globs: [])
    monkeypatch.setattr(mod, "read_current", lambda paths: None)
    monkeypatch.setattr(
        mod, "read_codex_cli_native",
        lambda *a, **k: {
            "provider": "openai-codex",
            "access": _jwt(int(time.time()) - 3600),  # access expired
            "refresh": "rt_old",
            "expires": now_ms - 3_600_000,
            "id_token_expires": now_ms - 5 * 3_600_000,
        },
    )

    def fake_refresh(rt):
        from codex_oauth import CodexTokens
        # Refresh succeeds for access but returns NO id_token (the bad server case).
        return CodexTokens(
            access=_jwt(int(time.time()) + 3600), refresh="rt_new",
            expires_ms=now_ms + 3_600_000, account_id="acct", id_token=None,
        )

    monkeypatch.setattr(mod, "refresh_access_token", fake_refresh)
    monkeypatch.setattr(mod, "write_tokens", lambda paths, t: 0)
    monkeypatch.setattr(mod, "write_token_cache", lambda c, t: None)
    monkeypatch.setattr(mod, "write_codex_cli_native", lambda t: True)
    escalated = {"n": 0}
    monkeypatch.setattr(mod, "_escalate", lambda: escalated.__setitem__("n", escalated["n"] + 1) or 7)

    rc = mod.main()
    assert escalated["n"] == 1, "a refresh that yields no id_token must escalate to full reauth"
    assert rc == 7, "watchdog returns the escalation's exit code"
