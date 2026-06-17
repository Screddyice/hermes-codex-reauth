"""Hermes-adaptation tests for the watchdog.

The watchdog must treat Hermes' own credential store (~/.hermes/auth.json on
neb-brain-hostinger) as READ-ONLY: it monitors Hermes health and alerts only
when Hermes is actually down (access expired + relogin_required). It must NEVER
write Hermes' store — Hermes is the sole writer, and force-writing rotates the
shared OpenAI refresh token (the refresh_token_reused collision).
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
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp_seconds}).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def _write_hermes(path: Path, *, access_exp_seconds: int, relogin_required: bool) -> None:
    """Write a realistic ~/.hermes/auth.json mirroring the live Hostinger shape."""
    doc = {
        "version": 1,
        "providers": {
            "openai-codex": {
                "tokens": {
                    "id_token": _jwt(access_exp_seconds),
                    "access_token": _jwt(access_exp_seconds),
                    "refresh_token": _jwt(int(time.time()) + 10 * 86400),
                    "account_id": "706d0823-e3fe-47a7-9f34-3ac9a24ab4fe",
                },
                "last_refresh": "2026-06-16T14:17:25.584536Z",
                "auth_mode": "chatgpt",
            }
        },
        "active_provider": "openai-codex",
        "credential_pool": {
            "openai-codex": [
                {"id": "54aaf4", "auth_type": "oauth", "access_token": _jwt(access_exp_seconds),
                 "refresh_token": _jwt(int(time.time()) + 10 * 86400)}
            ]
        },
    }
    if relogin_required:
        doc["providers"]["openai-codex"]["last_auth_error"] = {
            "code": "refresh_token_reused",
            "relogin_required": True,
            "at": "2026-06-14T13:00:32.191442+00:00",
        }
    path.write_text(json.dumps(doc))


# ------------------------------------------------------------- read_hermes_pool
def test_read_hermes_pool_parses_live_shape(tmp_path):
    import auth_profiles as ap
    p = tmp_path / "auth.json"
    _write_hermes(p, access_exp_seconds=int(time.time()) + 3600, relogin_required=True)
    prof = ap.read_hermes_pool(str(p))
    assert prof is not None
    assert prof["provider"] == "openai-codex"
    assert prof["accountId"] == "706d0823-e3fe-47a7-9f34-3ac9a24ab4fe"
    assert prof["relogin_required"] is True
    assert prof["expires"] > 0


def test_read_hermes_pool_missing_file_returns_none(tmp_path):
    import auth_profiles as ap
    assert ap.read_hermes_pool(str(tmp_path / "nope.json")) is None


# --------------------------------------------------------------- _monitor_hermes
@pytest.fixture
def wd(tmp_path, monkeypatch):
    import codex_watchdog as mod
    monkeypatch.setattr(mod, "REAUTH_FLAG_FILE", str(tmp_path / "reauth.flag"))
    return mod


def test_monitor_alerts_when_hermes_down(wd, tmp_path, monkeypatch):
    mod = wd
    p = tmp_path / "auth.json"
    _write_hermes(p, access_exp_seconds=int(time.time()) - 3600, relogin_required=True)  # expired + relogin
    monkeypatch.setattr("auth_profiles.HERMES_AUTH_PATH", str(p))
    monkeypatch.setattr(mod, "read_hermes_pool", lambda *a, **k: __import__("auth_profiles").read_hermes_pool(str(p)))
    alerted = {"n": 0}
    monkeypatch.setattr(mod, "_alert_slack", lambda *a, **k: alerted.__setitem__("n", alerted["n"] + 1))
    mod._monitor_hermes(int(time.time() * 1000))
    assert alerted["n"] == 1, "Hermes down (access expired + relogin_required) must alert"


def test_monitor_silent_when_hermes_access_healthy(wd, tmp_path, monkeypatch):
    mod = wd
    p = tmp_path / "auth.json"
    # Access still valid -> Hermes is up even if relogin_required flag lingers.
    _write_hermes(p, access_exp_seconds=int(time.time()) + 5 * 3600, relogin_required=True)
    monkeypatch.setattr(mod, "read_hermes_pool", lambda *a, **k: __import__("auth_profiles").read_hermes_pool(str(p)))
    alerted = {"n": 0}
    monkeypatch.setattr(mod, "_alert_slack", lambda *a, **k: alerted.__setitem__("n", alerted["n"] + 1))
    mod._monitor_hermes(int(time.time() * 1000))
    assert alerted["n"] == 0, "healthy Hermes access must stay silent"


def test_hermes_only_box_monitors_never_refreshes(wd, tmp_path, monkeypatch):
    """On a Hermes-only host (no openclaw/codex store), main() monitors Hermes
    and must NOT refresh or escalate on its behalf."""
    mod = wd
    p = tmp_path / "auth.json"
    _write_hermes(p, access_exp_seconds=int(time.time()) + 5 * 3600, relogin_required=False)
    monkeypatch.setattr(mod, "discover_paths", lambda globs: [])
    monkeypatch.setattr(mod, "read_current", lambda paths: None)
    monkeypatch.setattr(mod, "read_codex_cli_native", lambda *a, **k: None)
    monkeypatch.setattr(mod, "read_hermes_pool", lambda *a, **k: __import__("auth_profiles").read_hermes_pool(str(p)))
    refreshed = {"n": 0}
    escalated = {"n": 0}
    monkeypatch.setattr(mod, "refresh_access_token", lambda rt: refreshed.__setitem__("n", refreshed["n"] + 1))
    monkeypatch.setattr(mod, "_escalate", lambda: escalated.__setitem__("n", escalated["n"] + 1) or 9)
    rc = mod.main()
    assert rc == 0
    assert refreshed["n"] == 0 and escalated["n"] == 0, "Hermes box must be monitored, never refreshed/escalated by us"
