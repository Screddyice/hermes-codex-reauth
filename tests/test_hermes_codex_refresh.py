from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys


HERE = pathlib.Path(__file__).resolve().parent
WATCHDOG = HERE.parent / "watchdog"
HELPER = WATCHDOG / "hermes_codex_refresh.py"


def load_helper():
    spec = importlib.util.spec_from_file_location("hermes_codex_refresh", HELPER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


helper = load_helper()


AUTH_SOURCE = '''
AUTH_STORE_VERSION = 1
AUTH_LOCK_TIMEOUT_SECONDS = 15.0
CODEX_OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
CODEX_RATE_LIMITED_CODE = "codex_rate_limited"

def _auth_lock_path():
    return _auth_file_path().with_suffix(".lock")

def _auth_store_lock(timeout_seconds=AUTH_LOCK_TIMEOUT_SECONDS, *, target_path=None):
    return None

def _load_auth_store(auth_file=None):
    return {}

def _save_auth_store(auth_store, target_path=None):
    return None

def refresh_codex_oauth_pure(access_token, refresh_token, *, timeout_seconds=20.0):
    raise RuntimeError("contract source must never be imported")
'''


POOL_SOURCE = '''
class CredentialPool:
    def _sync_device_code_entry_to_auth_store(self, entry):
        if entry.source not in {"device_code", "loopback_pkce"}:
            return
        if self.provider == "openai-codex":
            tokens["access_token"] = entry.access_token
            tokens["refresh_token"] = entry.refresh_token

    def _refresh_entry(self, entry, *, force):
        refreshed = auth_mod.refresh_codex_oauth_pure(
            entry.access_token, entry.refresh_token
        )
        self._persist()
        self._sync_device_code_entry_to_auth_store(entry)
        return refreshed
'''


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_contract(tmp_path: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    auth_module = tmp_path / "hermes_cli" / "auth.py"
    pool_module = tmp_path / "agent" / "credential_pool.py"
    auth_module.parent.mkdir()
    pool_module.parent.mkdir()
    auth_module.write_text(AUTH_SOURCE)
    pool_module.write_text(POOL_SOURCE)
    dist_info = tmp_path / "hermes_agent-0.16.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: hermes-agent\nVersion: 0.16.0\n"
    )
    return auth_module, pool_module


def test_auth_contract_rejects_unreviewed_signature_expansion():
    source = AUTH_SOURCE.replace(
        "def _save_auth_store(auth_store, target_path=None):",
        "def _save_auth_store(auth_store, target_path=None, unsafe=False):",
    )

    try:
        helper._validate_auth_ast(source)
    except helper.RefreshError as exc:
        assert str(exc) == "Hermes auth signature mismatch for _save_auth_store"
    else:
        raise AssertionError("unreviewed signature expansion was accepted")


def helper_argv(
    auth_module: pathlib.Path,
    pool_module: pathlib.Path,
) -> list[str]:
    return [
        sys.executable,
        str(HELPER),
        "--expected-python",
        sys.executable,
        "--expected-version",
        "0.16.0",
        "--auth-module",
        str(auth_module),
        "--auth-sha256",
        sha256(auth_module),
        "--pool-module",
        str(pool_module),
        "--pool-sha256",
        sha256(pool_module),
    ]


def helper_env(tmp_path: pathlib.Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp_path)
    return env


def test_readiness_validates_pinned_contract_without_importing_hermes_modules(tmp_path):
    auth_module, pool_module = write_contract(tmp_path)
    import_marker = tmp_path / "forbidden-import"
    for package in ("agent", "plugins"):
        package_dir = tmp_path / package
        package_dir.mkdir(exist_ok=True)
        (package_dir / "__init__.py").write_text(
            f"from pathlib import Path\nPath({str(import_marker)!r}).write_text({package!r})\n"
        )
    completed = subprocess.run(
        helper_argv(auth_module, pool_module) + [
            "--check-readiness",
        ],
        text=True,
        capture_output=True,
        env=helper_env(tmp_path),
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"status": "ready"}
    assert not import_marker.exists()


def test_plan_selects_one_eligible_manual_pool_lineage(tmp_path):
    auth_module, pool_module = write_contract(tmp_path)
    auth_path = tmp_path / "auth.json"
    auth_path.write_text(json.dumps({
        "providers": {
            "openai-codex": {
                "tokens": {"access_token": "stale", "refresh_token": "stale-refresh"},
                "last_auth_error": {"code": "refresh_token_reused"},
            }
        },
        "credential_pool": {"openai-codex": [
            {
                "id": "terminal",
                "source": "manual",
                "auth_type": "oauth",
                "priority": 0,
                "access_token": "terminal-access",
                "refresh_token": "terminal-refresh",
                "last_status": "dead",
            },
            {
                "id": "manual-live",
                "source": "manual:oauth",
                "auth_type": "oauth",
                "priority": 1,
                "access_token": "expired-access",
                "refresh_token": "manual-refresh",
                "last_status": "ok",
            },
        ]},
    }))

    completed = subprocess.run(
        helper_argv(auth_module, pool_module) + [
            "--plan",
            "--auth-json",
            str(auth_path),
        ],
        text=True,
        capture_output=True,
        env=helper_env(tmp_path),
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["status"] == "planned"
    assert payload["lineage"] == "pool:manual-live"
    assert payload["refresh_fingerprint"] == hashlib.sha256(
        b"manual-refresh"
    ).hexdigest()
    assert "manual-refresh" not in completed.stdout


def test_plan_rejects_ambiguous_pool_priority_before_request(tmp_path):
    auth_module, pool_module = write_contract(tmp_path)
    auth_path = tmp_path / "auth.json"
    entries = [
        {
            "id": entry_id,
            "source": "manual",
            "auth_type": "oauth",
            "priority": 0,
            "access_token": f"access-{entry_id}",
            "refresh_token": f"refresh-{entry_id}",
        }
        for entry_id in ("first", "second")
    ]
    auth_path.write_text(json.dumps({
        "providers": {},
        "credential_pool": {"openai-codex": entries},
    }))

    completed = subprocess.run(
        helper_argv(auth_module, pool_module) + [
            "--plan",
            "--auth-json",
            str(auth_path),
        ],
        text=True,
        capture_output=True,
        env=helper_env(tmp_path),
        check=False,
    )

    assert completed.returncode == 1
    assert json.loads(completed.stderr)["status"] == "disarmed"
    assert "ambiguous" in completed.stderr.lower()


def test_manual_pool_refresh_is_one_request_and_preserves_unrelated_state(tmp_path):
    assert hasattr(helper, "refresh_auth_store")
    terminal = {
        "id": "terminal",
        "source": "manual",
        "auth_type": "oauth",
        "priority": 0,
        "access_token": "terminal-access",
        "refresh_token": "terminal-refresh",
        "last_status": "dead",
        "last_error_code": "invalid_grant",
    }
    singleton = {
        "tokens": {"access_token": "stale", "refresh_token": "stale-refresh"},
        "last_auth_error": {"code": "refresh_token_reused"},
    }
    auth_path = tmp_path / "auth.json"
    auth_path.write_text(json.dumps({
        "providers": {"openai-codex": singleton},
        "credential_pool": {"openai-codex": [
            terminal,
            {
                "id": "manual-live",
                "source": "manual:oauth",
                "auth_type": "oauth",
                "priority": 1,
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "last_status": "exhausted",
                "last_status_at": 1,
                "last_error_code": 429,
                "last_error_reason": "usage_limit_reached",
                "last_error_message": "old quota",
                "last_error_reset_at": 2,
            },
        ]},
        "unrelated": {"keep": True},
    }))
    auth_path.chmod(0o644)
    calls = []

    def transport(endpoint, fields, timeout):
        calls.append((endpoint, dict(fields), timeout))
        return helper.HttpResult(
            200,
            json.dumps({
                "access_token": "new-access",
                "refresh_token": "new-refresh",
            }).encode(),
            {},
        )

    outcome = helper.refresh_auth_store(
        auth_path,
        expected_lineage="pool:manual-live",
        expected_fingerprint=hashlib.sha256(b"old-refresh").hexdigest(),
        transport=transport,
        now=1000,
    )

    assert outcome.status == "persisted"
    assert calls == [(
        "https://auth.openai.com/oauth/token",
        {
            "grant_type": "refresh_token",
            "refresh_token": "old-refresh",
            "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
        },
        20.0,
    )]
    saved = json.loads(auth_path.read_text())
    refreshed = saved["credential_pool"]["openai-codex"][1]
    assert refreshed["access_token"] == "new-access"
    assert refreshed["refresh_token"] == "new-refresh"
    assert refreshed["last_status"] == "ok"
    assert refreshed["last_error_code"] is None
    assert saved["credential_pool"]["openai-codex"][0] == terminal
    assert saved["providers"]["openai-codex"] == singleton
    assert saved["unrelated"] == {"keep": True}
    assert auth_path.stat().st_mode & 0o777 == 0o600


def test_device_code_refresh_updates_the_linked_singleton_and_pool(tmp_path):
    assert hasattr(helper, "refresh_auth_store")
    auth_path = tmp_path / "auth.json"
    auth_path.write_text(json.dumps({
        "providers": {"openai-codex": {
            "tokens": {"access_token": "old-access", "refresh_token": "old-refresh"},
            "label": "primary",
        }},
        "credential_pool": {"openai-codex": [{
            "id": "device",
            "source": "device_code",
            "auth_type": "oauth",
            "priority": 0,
            "access_token": "old-access",
            "refresh_token": "old-refresh",
        }]},
    }))

    outcome = helper.refresh_auth_store(
        auth_path,
        expected_lineage="pool:device",
        expected_fingerprint=hashlib.sha256(b"old-refresh").hexdigest(),
        transport=lambda *_args: helper.HttpResult(
            200,
            b'{"access_token":"new-access","refresh_token":"new-refresh"}',
            {},
        ),
        now=1000,
    )

    assert outcome.status == "persisted"
    saved = json.loads(auth_path.read_text())
    singleton_tokens = saved["providers"]["openai-codex"]["tokens"]
    pool_entry = saved["credential_pool"]["openai-codex"][0]
    assert singleton_tokens == {
        "access_token": "new-access",
        "refresh_token": "new-refresh",
    }
    assert pool_entry["access_token"] == "new-access"
    assert pool_entry["refresh_token"] == "new-refresh"
    assert saved["providers"]["openai-codex"]["label"] == "primary"


def test_429_records_reset_without_persisting_or_retrying(tmp_path):
    assert hasattr(helper, "refresh_auth_store")
    auth_path = tmp_path / "auth.json"
    original = {
        "providers": {"openai-codex": {"tokens": {
            "access_token": "old-access",
            "refresh_token": "old-refresh",
        }}},
    }
    auth_path.write_text(json.dumps(original))
    calls = []

    def transport(*args):
        calls.append(args)
        return helper.HttpResult(
            429,
            b'{"error":{"code":"usage_limit_reached","resets_at":2500}}',
            {},
        )

    outcome = helper.refresh_auth_store(
        auth_path,
        expected_lineage="singleton",
        expected_fingerprint=hashlib.sha256(b"old-refresh").hexdigest(),
        transport=transport,
        now=1000,
    )

    assert outcome == helper.RefreshOutcome("quota", 2500.0)
    assert len(calls) == 1
    assert json.loads(auth_path.read_text()) == original


def test_uncertain_response_never_retries_or_persists(tmp_path):
    assert hasattr(helper, "refresh_auth_store")
    auth_path = tmp_path / "auth.json"
    original = {
        "providers": {"openai-codex": {"tokens": {
            "access_token": "old-access",
            "refresh_token": "old-refresh",
        }}},
    }
    auth_path.write_text(json.dumps(original))
    calls = []

    def transport(*args):
        calls.append(args)
        raise TimeoutError("response lost after request")

    try:
        helper.refresh_auth_store(
            auth_path,
            expected_lineage="singleton",
            expected_fingerprint=hashlib.sha256(b"old-refresh").hexdigest(),
            transport=transport,
            now=1000,
        )
    except helper.UncertainRefresh:
        pass
    else:
        raise AssertionError("uncertain refresh was reported as safe")

    assert len(calls) == 1
    assert json.loads(auth_path.read_text()) == original


def test_readiness_rejects_hash_and_ast_drift(tmp_path):
    auth_module, pool_module = write_contract(tmp_path)
    auth_module.write_text(AUTH_SOURCE.replace(
        "def refresh_codex_oauth_pure", "def changed_refresh_contract"
    ))

    completed = subprocess.run(
        helper_argv(auth_module, pool_module) + ["--check-readiness"],
        text=True,
        capture_output=True,
        env=helper_env(tmp_path),
        check=False,
    )

    assert completed.returncode == 1
    assert "missing refresh_codex_oauth_pure" in completed.stderr


def test_plan_fails_closed_while_hermes_auth_lock_is_held(tmp_path):
    auth_module, pool_module = write_contract(tmp_path)
    auth_path = tmp_path / "auth.json"
    auth_path.write_text(json.dumps({
        "providers": {"openai-codex": {"tokens": {
            "access_token": "access",
            "refresh_token": "refresh",
        }}},
    }))

    with helper.auth_lock(auth_path, 1.0):
        completed = subprocess.run(
            helper_argv(auth_module, pool_module) + [
                "--plan",
                "--auth-json",
                str(auth_path),
                "--lock-timeout",
                "0",
            ],
            text=True,
            capture_output=True,
            env=helper_env(tmp_path),
            check=False,
        )

    assert completed.returncode == 1
    assert "timed out waiting for Hermes auth lock" in completed.stderr


def test_post_write_verification_failure_is_uncertain(tmp_path, monkeypatch):
    auth_path = tmp_path / "auth.json"
    auth_path.write_text(json.dumps({
        "providers": {"openai-codex": {"tokens": {
            "access_token": "old-access",
            "refresh_token": "old-refresh",
        }}},
    }))
    monkeypatch.setattr(
        helper,
        "_verify_persisted",
        lambda *_args: (_ for _ in ()).throw(
            helper.UncertainRefresh("post-write verification failed")
        ),
    )

    try:
        helper.refresh_auth_store(
            auth_path,
            expected_lineage="singleton",
            expected_fingerprint=hashlib.sha256(b"old-refresh").hexdigest(),
            transport=lambda *_args: helper.HttpResult(
                200,
                b'{"access_token":"new-access","refresh_token":"new-refresh"}',
                {},
            ),
            now=1000,
        )
    except helper.UncertainRefresh as exc:
        assert "post-write verification" in str(exc)
    else:
        raise AssertionError("partial persistence was reported as verified")
