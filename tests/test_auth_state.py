from __future__ import annotations

import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
WATCHDOG = HERE.parent / "watchdog"


def load_auth_state():
    sys.path.insert(0, str(WATCHDOG))
    spec = importlib.util.spec_from_file_location("auth_state", WATCHDOG / "auth_state.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_selected_credential_skips_dead_and_quota_blocked_entries():
    auth_state = load_auth_state()
    auth = {
        "credential_pool": {
            "openai-codex": [
                {"id": "dead", "label": "dead", "auth_type": "oauth",
                 "access_token": "dead-at", "refresh_token": "dead-rt",
                 "last_status": "dead", "priority": 0},
                {"id": "quota", "label": "quota", "auth_type": "oauth",
                 "access_token": "quota-at", "refresh_token": "quota-rt",
                 "last_status": "exhausted", "last_error_code": 429,
                 "last_error_reset_at": 2000, "priority": 1},
                {"id": "backup", "label": "backup", "auth_type": "oauth",
                 "access_token": "backup-at", "refresh_token": "backup-rt",
                 "last_status": "ok", "priority": 2},
            ]
        }
    }
    selected = auth_state.selected_codex_credential(auth, now=1000)
    assert selected["label"] == "backup"
    assert selected["access_token"] == "backup-at"


def test_selected_credential_uses_singleton_without_a_pool():
    auth_state = load_auth_state()
    auth = {"providers": {"openai-codex": {"tokens": {
        "access_token": "singleton-at", "refresh_token": "singleton-rt"
    }}}}
    selected = auth_state.selected_codex_credential(auth, now=1000)
    assert selected["label"] == "singleton"
    assert selected["access_token"] == "singleton-at"


def test_full_pool_reset_uses_latest_reset_when_every_entry_is_blocked():
    auth_state = load_auth_state()
    auth = {"credential_pool": {"openai-codex": [
        {"id": "a", "auth_type": "oauth", "refresh_token": "ra",
         "last_status": "exhausted", "last_error_code": 429,
         "last_error_reset_at": 1800},
        {"id": "b", "auth_type": "oauth", "refresh_token": "rb",
         "last_status": "exhausted", "last_error_code": 429,
         "last_error_reset_at": 2200},
    ]}}
    assert auth_state.full_pool_reset_at(auth, now=1000) == 2200
