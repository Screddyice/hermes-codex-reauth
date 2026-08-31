from __future__ import annotations

import base64
import dataclasses
import http.server
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import threading
import time
import traceback
import urllib.request

import pytest

HERE = pathlib.Path(__file__).resolve().parent
WATCHDOG = HERE.parent / "watchdog"
sys.path.insert(0, str(WATCHDOG))


def load_healer():
    spec = importlib.util.spec_from_file_location("self_heal", WATCHDOG / "self_heal.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


healer = load_healer()


def result(returncode: int, stdout: str = "", stderr: str = ""):
    return healer.CommandResult(returncode, stdout, stderr)


class ScriptedRunner:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []
        self.timeouts = []

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        self.timeouts.append(timeout)
        if not self.results:
            raise AssertionError(f"unexpected command: {argv}")
        scripted = self.results.pop(0)
        return scripted(argv, timeout) if callable(scripted) else scripted


def local_cfg():
    return {
        "gateway_unit": "hermes-gateway.service",
        "self_heal": {
            "health_timer": "hermes-codex-health.timer",
            "check_service": "hermes-codex-health.service",
            "gateway_restart": True,
            "codex_model": "openai-codex/gpt-5.5",
            "retry_s": 21600,
            "peers": [],
        },
    }


class CliArgs:
    def __init__(self, config, state_file, dry_run=False):
        self.config = str(config) if config is not None else None
        self.state_file = str(state_file) if state_file is not None else None
        self.dry_run = dry_run


def write_cli_config(tmp_path, *, peers=None, observer=False):
    if observer:
        cfg = {
            "host_label": "observer",
            "mode": "observer",
            "self_heal": {
                "health_timer": "codex-observer.timer",
                "check_service": "codex-observer.service",
                "gateway_restart": False,
                "maintenance_lock": str(tmp_path / "SELF_HEAL_PAUSED"),
                "retry_s": 21600,
                "peers": peers or [],
            },
        }
    else:
        hermes_home = tmp_path / "hermes"
        hermes_home.mkdir(exist_ok=True)
        (hermes_home / "auth.json").write_text(json.dumps(healthy_singleton()))
        cfg = {
            "host_label": "test-host",
            "hermes_home": str(hermes_home),
            "gateway_unit": "hermes-gateway.service",
            "self_heal": {
                "health_timer": "hermes-codex-health.timer",
                "check_service": "hermes-codex-health.service",
                "gateway_restart": True,
                "codex_model": "openai-codex/gpt-5.5",
                "maintenance_lock": str(tmp_path / "SELF_HEAL_PAUSED"),
                "retry_s": 21600,
                "peers": peers or [],
            },
        }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg))
    return path


def token_with_exp(exp: int) -> str:
    claims = {
        "https://api.openai.com/auth": {"chatgpt_account_id": "acct"},
        "exp": exp,
    }
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"h.{payload}.s"


def healthy_singleton():
    return {"providers": {"openai-codex": {"tokens": {
        "access_token": token_with_exp(2000), "refresh_token": "refresh"
    }}}}


def expired_refreshable_singleton():
    return {"providers": {"openai-codex": {"tokens": {
        "access_token": token_with_exp(900), "refresh_token": "refresh"
    }}}}


def dead_singleton():
    return {"providers": {"openai-codex": {
        "tokens": {"access_token": token_with_exp(900), "refresh_token": ""},
        "last_auth_error": {"code": "refresh_token_reused", "relogin_required": True,
                            "at": "2026-08-31T00:00:00Z"},
        "last_refresh": "2026-08-30T00:00:00Z",
    }}}


def fully_blocked_pool(reset_at: int):
    return {"credential_pool": {"openai-codex": [{
        "id": "quota", "label": "quota", "auth_type": "oauth",
        "access_token": token_with_exp(3000), "refresh_token": "refresh",
        "last_status": "exhausted", "last_error_code": 429,
        "last_error_reset_at": reset_at,
    }]}}


def stale_singleton_with_healthy_manual_pool():
    auth = dead_singleton()
    auth["credential_pool"] = {"openai-codex": [{
        "id": "manual", "label": "manual", "source": "manual:oauth",
        "auth_type": "oauth", "access_token": token_with_exp(3000),
        "refresh_token": "manual-refresh", "last_status": "ok", "priority": 1,
    }]}
    return auth


@pytest.mark.parametrize(("auth", "now", "expected"), [
    (healthy_singleton(), 1000, "none"),
    (expired_refreshable_singleton(), 1000, "warmup"),
    (dead_singleton(), 1000, "human_2fa"),
    (fully_blocked_pool(reset_at=2000), 1000, "wait_quota"),
    (fully_blocked_pool(reset_at=2000), 2000, "warmup"),
    (stale_singleton_with_healthy_manual_pool(), 1000, "warmup"),
])
def test_credential_action(auth, now, expected):
    assert healer.credential_action(auth, now) == expected


def test_quota_without_a_renewable_credential_requires_human_2fa():
    auth = fully_blocked_pool(reset_at=2000)
    auth["credential_pool"]["openai-codex"][0]["refresh_token"] = ""

    assert healer.credential_action(auth, 1000) == "human_2fa"


@pytest.mark.parametrize("code", [
    "refresh_token_reused",
    "invalid_grant",
    "token_revoked",
    "token_invalidated",
    "invalid_token",
    "dead",
])
def test_terminal_credential_codes_require_human_2fa(code):
    auth = healthy_singleton()
    auth["providers"]["openai-codex"]["last_auth_error"] = {"code": code}

    assert healer.credential_action(auth, 1000) == "human_2fa"


def test_healthy_pool_alternate_replaces_a_terminal_entry():
    auth = {"credential_pool": {"openai-codex": [
        {
            "id": "dead", "last_status": "dead", "last_error_code": "invalid_grant",
            "access_token": token_with_exp(900), "refresh_token": "",
            "priority": 0,
        },
        {
            "id": "manual", "source": "manual:oauth", "last_status": "ok",
            "access_token": token_with_exp(3000), "refresh_token": "manual-refresh",
            "priority": 1,
        },
    ]}}

    assert healer.credential_action(auth, 1000) == "warmup"


def test_backup_is_private_and_retains_five_newest(tmp_path):
    auth = tmp_path / "auth.json"
    auth.write_text('{"providers": {}}')
    backups = tmp_path / "backups"
    for now in range(1000, 1006):
        path = healer.backup_auth(auth, backups, now)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert len(list(backups.glob("*-auth.json"))) == 5


def test_backup_destination_is_private_before_auth_bytes_are_copied(tmp_path, monkeypatch):
    auth = tmp_path / "auth.json"
    auth.write_text('{"refresh_token":"short-test-value"}')
    backups = tmp_path / "backups"
    real_copyfile = healer.shutil.copyfile
    observed = []

    def inspect_destination_before_copy(source, destination):
        destination = pathlib.Path(destination)
        observed.append((stat.S_IMODE(destination.stat().st_mode), destination.stat().st_size))
        return real_copyfile(source, destination)

    monkeypatch.setattr(healer.shutil, "copyfile", inspect_destination_before_copy)

    healer.backup_auth(auth, backups, 1000)

    assert observed == [(0o600, 0)]


def test_warmup_is_pinned_safe_and_bounded():
    runner = ScriptedRunner([result(0, "OK")])
    outcome = healer.run_hermes_warmup(local_cfg(), runner)
    assert outcome.returncode == 0
    assert runner.calls == [[
        "hermes", "--safe-mode", "--provider", "openai-codex",
        "-m", "openai-codex/gpt-5.5", "-z", "Reply with exactly: OK"
    ]]
    assert runner.timeouts == [120]


def test_warmup_runtime_kills_process_group_on_timeout(monkeypatch):
    events = []
    oversized = b"x" * (64 * 1024 + 1024)

    class TimedOutProcess:
        pid = 4321
        returncode = None

        def __init__(self, stdout, stderr):
            self.stdout = stdout
            self.stderr = stderr

        def communicate(self, timeout=None):
            events.append(("communicate", timeout))
            if timeout is not None:
                if hasattr(self.stdout, "write"):
                    self.stdout.write(oversized)
                    self.stderr.write(b"timed out")
                raise subprocess.TimeoutExpired("hermes", timeout)
            self.returncode = -9
            if hasattr(self.stdout, "write"):
                return None, None
            return oversized.decode(), "timed out"

    def fake_popen(argv, **kwargs):
        events.append(("popen", list(argv), kwargs))
        return TimedOutProcess(kwargs["stdout"], kwargs["stderr"])

    monkeypatch.setattr(healer.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(healer.os, "killpg", lambda pid, sig: events.append(("killpg", pid, sig)))

    outcome = healer.run_command(["hermes"], timeout=120)

    assert outcome.returncode != 0
    assert events[0][2]["start_new_session"] is True
    assert [event[0] for event in events] == ["popen", "communicate", "killpg", "communicate"]
    assert len(outcome.stdout.encode()) <= 64 * 1024
    assert outcome.stderr == "timed out"


def test_run_command_capture_is_file_backed_and_memory_bounded(monkeypatch):
    observed = {}
    oversized = b"x" * (64 * 1024 + 1024)

    class NoisyProcess:
        pid = 5432
        returncode = 0

        def communicate(self, timeout=None):
            observed["timeout"] = timeout
            stdout = observed["stdout"]
            stderr = observed["stderr"]
            if hasattr(stdout, "write"):
                stdout.write(oversized)
                stderr.write(oversized)
                return None, None
            return oversized.decode(), oversized.decode()

    def fake_popen(_argv, **kwargs):
        observed.update(kwargs)
        return NoisyProcess()

    monkeypatch.setattr(healer.subprocess, "Popen", fake_popen)

    outcome = healer.run_command(["noisy"], timeout=20)

    assert observed["stdout"] is not subprocess.PIPE
    assert observed["stderr"] is not subprocess.PIPE
    assert observed["timeout"] == 20
    assert len(outcome.stdout.encode()) <= 64 * 1024
    assert len(outcome.stderr.encode()) <= 64 * 1024


def test_run_command_preserves_small_stdout_and_stderr():
    outcome = healer.run_command([
        sys.executable,
        "-c",
        "import sys; print('small stdout'); print('small stderr', file=sys.stderr)",
    ], timeout=20)

    assert outcome == result(0, "small stdout\n", "small stderr\n")


def write_auth(tmp_path, auth):
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(auth))
    return path


def write_cfg(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(local_cfg()))
    return path


def test_expired_credential_is_backed_up_warmed_restarted_and_probed_once(tmp_path):
    auth_path = write_auth(tmp_path, expired_refreshable_singleton())
    cfg_path = write_cfg(tmp_path)

    def warmup_after_backup(_argv, _timeout):
        snapshots = list((tmp_path / "backups").glob("*-auth.json"))
        assert len(snapshots) == 1
        assert stat.S_IMODE(snapshots[0].stat().st_mode) == 0o600
        return result(0, "OK")

    runner = ScriptedRunner([
        warmup_after_backup,
        result(0),
        result(0, "active"),
        result(0, "OK"),
    ])

    ok, detail = healer.repair_credential(
        local_cfg(), cfg_path, auth_path, {"faults": {}}, runner, 1000, False
    )

    assert ok is True
    assert "verified" in detail
    assert runner.calls == [
        ["hermes", "--safe-mode", "--provider", "openai-codex",
         "-m", "openai-codex/gpt-5.5", "-z", "Reply with exactly: OK"],
        ["systemctl", "--user", "restart", "hermes-gateway.service"],
        ["systemctl", "--user", "is-active", "hermes-gateway.service"],
        [sys.executable, str(WATCHDOG / "codex_auth_probe.py"),
         "--config", str(cfg_path)],
    ]
    assert runner.timeouts == [120, 20, 20, 40]


def test_terminal_credential_requires_human_2fa_without_mutation(tmp_path):
    auth_path = write_auth(tmp_path, dead_singleton())
    state = {"faults": {}}
    runner = ScriptedRunner([])

    ok, detail = healer.repair_credential(
        local_cfg(), write_cfg(tmp_path), auth_path, state, runner, 1000, False
    )

    assert ok is False
    assert "human 2FA" in detail
    assert runner.calls == []
    assert not (tmp_path / "backups").exists()
    assert state == {"faults": {}}


def test_quota_before_reset_makes_no_request_and_leaves_state_unchanged(tmp_path):
    auth_path = write_auth(tmp_path, fully_blocked_pool(reset_at=2000))
    state = {"faults": {}}
    runner = ScriptedRunner([])

    ok, detail = healer.repair_credential(
        local_cfg(), write_cfg(tmp_path), auth_path, state, runner, 1000, False
    )

    assert ok is True
    assert "2000" in detail
    assert runner.calls == []
    assert not (tmp_path / "backups").exists()
    assert state == {"faults": {}}


def test_quota_at_reset_gets_only_one_attempt_for_that_window(tmp_path):
    auth_path = write_auth(tmp_path, fully_blocked_pool(reset_at=2000))
    cfg_path = write_cfg(tmp_path)
    state = {"faults": {}}
    runner = ScriptedRunner([
        result(0, "OK"), result(0), result(0, "active"), result(0, "OK")
    ])

    first_ok, _ = healer.repair_credential(
        local_cfg(), cfg_path, auth_path, state, runner, 2000, False
    )
    second_runner = ScriptedRunner([])
    second_ok, second_detail = healer.repair_credential(
        local_cfg(), cfg_path, auth_path, state, second_runner, 2001, False
    )

    assert first_ok is True
    assert second_ok is True
    assert "already attempted" in second_detail
    assert state["quota_attempt_reset_at"] == 2000
    assert len([call for call in runner.calls if call[0] == "hermes"]) == 1
    assert len([call for call in runner.calls if "codex_auth_probe.py" in call[1]]) == 1
    assert second_runner.calls == []


def test_fresh_probe_quota_records_new_reset_without_second_request(tmp_path):
    auth_path = write_auth(tmp_path, fully_blocked_pool(reset_at=2000))
    cfg_path = write_cfg(tmp_path)
    state = {"faults": {}}

    def warmup_records_next_reset(_argv, _timeout):
        auth_path.write_text(json.dumps(fully_blocked_pool(reset_at=3000)))
        return result(0, "QUOTA")

    runner = ScriptedRunner([
        warmup_records_next_reset,
        result(0),
        result(0, "active"),
        result(3, "QUOTA"),
    ])

    ok, detail = healer.repair_credential(
        local_cfg(), cfg_path, auth_path, state, runner, 2000, False
    )

    assert ok is True
    assert "3000" in detail
    assert state["quota_attempt_reset_at"] == 2000
    assert state["quota_reset_at"] == 3000
    assert len([call for call in runner.calls if call[0] == "hermes"]) == 1
    assert len([call for call in runner.calls if "codex_auth_probe.py" in call[1]]) == 1
    assert len(runner.calls) == 4

    next_runner = ScriptedRunner([
        result(0), result(0), result(0, "active"), result(0)
    ])
    next_ok, _ = healer.repair_credential(
        local_cfg(), cfg_path, auth_path, state, next_runner, 3000, False
    )

    assert next_ok is True
    assert len([call for call in next_runner.calls if call[0] == "hermes"]) == 1
    assert len([call for call in next_runner.calls if "codex_auth_probe.py" in call[1]]) == 1


def test_unknown_probe_marks_verification_failure_and_preserves_backup(tmp_path):
    auth_path = write_auth(tmp_path, expired_refreshable_singleton())
    runner = ScriptedRunner([
        result(0, "OK"), result(0), result(0, "active"), result(2, "UNKNOWN")
    ])

    ok, detail = healer.repair_credential(
        local_cfg(), write_cfg(tmp_path), auth_path, {"faults": {}},
        runner, 1000, False
    )

    assert ok is False
    assert "verification failed" in detail
    assert len(list((tmp_path / "backups").glob("*-auth.json"))) == 1
    assert len([call for call in runner.calls if "codex_auth_probe.py" in call[1]]) == 1


def test_broken_probe_uses_exit_code_even_when_output_says_ok(tmp_path):
    auth_path = write_auth(tmp_path, expired_refreshable_singleton())
    runner = ScriptedRunner([
        result(0), result(0), result(0, "active"), result(1, "OK")
    ])

    ok, detail = healer.repair_credential(
        local_cfg(), write_cfg(tmp_path), auth_path, {"faults": {}},
        runner, 1000, False
    )

    assert ok is False
    assert "human 2FA" in detail


def test_warmup_failure_redacts_and_caps_output_while_preserving_backup(tmp_path):
    auth_path = write_auth(tmp_path, expired_refreshable_singleton())
    token = token_with_exp(9999)
    runner = ScriptedRunner([result(1, f"Bearer {token} " + "x" * 1000)])

    ok, detail = healer.repair_credential(
        local_cfg(), write_cfg(tmp_path), auth_path, {"faults": {}},
        runner, 1000, False
    )

    assert ok is False
    assert token not in detail
    assert len(detail) <= 500
    assert len(list((tmp_path / "backups").glob("*-auth.json"))) == 1
    assert len(runner.calls) == 1


@pytest.mark.parametrize(
    "field", ["access_token", "refresh_token", "id_token", "authorization"]
)
@pytest.mark.parametrize("value", ["short-test-value", "long-" + "x" * 80])
def test_quoted_json_token_fields_are_redacted_in_rendered_detail(tmp_path, field, value):
    outcome = result(1, json.dumps({field: value}, separators=(",", ":")))

    detail = healer._command_failure("command failed", outcome, tmp_path / "backup")

    assert value not in detail
    assert f'"{field}":"[REDACTED]"' in detail


def test_credential_repair_rereads_auth_before_gateway_restart(tmp_path):
    auth_path = write_auth(tmp_path, expired_refreshable_singleton())

    def warmup_leaves_terminal_singleton(_argv, _timeout):
        auth_path.write_text(json.dumps(dead_singleton()))
        return result(0)

    runner = ScriptedRunner([warmup_leaves_terminal_singleton])

    ok, detail = healer.repair_credential(
        local_cfg(), write_cfg(tmp_path), auth_path, {"faults": {}},
        runner, 1000, False
    )

    assert ok is False
    assert "recoverable credential" in detail
    assert len(runner.calls) == 1


def test_credential_dry_run_has_no_commands_backup_or_state_changes(tmp_path):
    auth_path = write_auth(tmp_path, expired_refreshable_singleton())
    state = {"faults": {}}
    runner = ScriptedRunner([])

    ok, detail = healer.repair_credential(
        local_cfg(), write_cfg(tmp_path), auth_path, state, runner, 1000, True
    )

    assert ok is True
    assert detail.startswith("dry-run:")
    assert runner.calls == []
    assert not (tmp_path / "backups").exists()
    assert state == {"faults": {}}


def test_disabled_timer_is_enabled_started_and_verified():
    runner = ScriptedRunner([
        result(1, "disabled"),
        result(0),
        result(0, "enabled"),
        result(0, "active"),
        result(0, "Mon 2026-08-31 18:35:00 +08"),
    ])

    ok, detail = healer.repair_health_timer(local_cfg(), runner, dry_run=False)

    assert ok is True
    assert runner.calls[1] == [
        "systemctl", "--user", "enable", "--now", "hermes-codex-health.timer"
    ]
    assert "scheduled" in detail


@pytest.mark.parametrize("status", ["masked", "masked-runtime"])
def test_masked_timer_is_respected_without_mutation(status):
    runner = ScriptedRunner([result(1, status)])

    ok, detail = healer.repair_health_timer(local_cfg(), runner, dry_run=False)

    assert ok is True
    assert status in detail
    assert len(runner.calls) == 1


def test_enabled_unscheduled_timer_restarts_and_starts_the_check_service_once():
    runner = ScriptedRunner([
        result(0, "enabled"),
        result(0, "active"),
        result(0, ""),
        result(0),
        result(0),
        result(0, "enabled"),
        result(0, "active"),
        result(0, "Mon 2026-08-31 18:35:00 +08"),
    ])

    ok, detail = healer.repair_health_timer(local_cfg(), runner, dry_run=False)

    assert ok is True
    assert "scheduled" in detail
    assert runner.calls == [
        ["systemctl", "--user", "is-enabled", "hermes-codex-health.timer"],
        ["systemctl", "--user", "is-active", "hermes-codex-health.timer"],
        ["systemctl", "--user", "show", "hermes-codex-health.timer",
         "--property=NextElapseUSecRealtime", "--value"],
        ["systemctl", "--user", "restart", "hermes-codex-health.timer"],
        ["systemctl", "--user", "start", "hermes-codex-health.service"],
        ["systemctl", "--user", "is-enabled", "hermes-codex-health.timer"],
        ["systemctl", "--user", "is-active", "hermes-codex-health.timer"],
        ["systemctl", "--user", "show", "hermes-codex-health.timer",
         "--property=NextElapseUSecRealtime", "--value"],
    ]


def test_timer_dry_run_returns_fixed_argv_without_running_commands():
    runner = ScriptedRunner([])

    ok, detail = healer.repair_health_timer(local_cfg(), runner, dry_run=True)

    assert ok is True
    assert detail == (
        "dry-run: systemctl --user enable --now hermes-codex-health.timer"
    )
    assert runner.calls == []


def test_timer_rejects_unsafe_configured_units_before_running_commands():
    runner = ScriptedRunner([])
    cfg = local_cfg()
    cfg["self_heal"]["health_timer"] = "timer;reboot.timer"

    with pytest.raises(healer.Disarmed):
        healer.repair_health_timer(cfg, runner, dry_run=False)

    assert runner.calls == []


def test_inactive_gateway_restarts_when_a_credential_can_recover():
    runner = ScriptedRunner([
        result(3, "inactive"), result(0), result(0, "active")
    ])
    auth = {"providers": {"openai-codex": {"tokens": {
        "access_token": "access", "refresh_token": "refresh"
    }}}}
    original_auth = json.dumps(auth, sort_keys=True)

    ok, detail = healer.repair_gateway(
        local_cfg(), auth, runner, dry_run=False, sleeper=lambda _: None
    )

    assert ok is True
    assert ["systemctl", "--user", "restart", "hermes-gateway.service"] in runner.calls
    assert "active" in detail
    assert json.dumps(auth, sort_keys=True) == original_auth


def test_terminal_credential_blocks_gateway_restart():
    runner = ScriptedRunner([result(3, "inactive")])
    auth = {"credential_pool": {"openai-codex": [{
        "id": "dead", "auth_type": "oauth", "access_token": "",
        "refresh_token": "", "last_status": "dead"
    }]}}

    ok, detail = healer.repair_gateway(
        local_cfg(), auth, runner, dry_run=False, sleeper=lambda _: None
    )

    assert ok is False
    assert "credential" in detail
    assert len(runner.calls) == 1


def test_malformed_credential_pool_blocks_gateway_restart():
    runner = ScriptedRunner([result(3, "inactive")])

    ok, detail = healer.repair_gateway(
        local_cfg(), {"credential_pool": ["invalid"]}, runner,
        dry_run=False, sleeper=lambda _: None
    )

    assert ok is False
    assert "credential" in detail
    assert len(runner.calls) == 1


def test_active_gateway_is_left_unchanged_without_inspecting_credentials():
    runner = ScriptedRunner([result(0, "active")])

    ok, detail = healer.repair_gateway(
        local_cfg(), {"credential_pool": {}}, runner, dry_run=False, sleeper=lambda _: None
    )

    assert ok is True
    assert detail == "gateway is active"
    assert runner.calls == [
        ["systemctl", "--user", "is-active", "hermes-gateway.service"]
    ]


def test_quota_blocked_but_renewable_pool_permits_one_gateway_restart():
    runner = ScriptedRunner([
        result(3, "inactive"), result(0), result(0, "active")
    ])
    auth = {"credential_pool": {"openai-codex": [{
        "id": "quota", "auth_type": "oauth", "refresh_token": "refresh",
        "last_status": "exhausted", "last_error_code": "429",
        "last_error_reset_at": time.time() + 600,
    }]}}

    ok, detail = healer.repair_gateway(
        local_cfg(), auth, runner, dry_run=False, sleeper=lambda _: None
    )

    assert ok is True
    assert "active" in detail
    assert runner.calls[1] == [
        "systemctl", "--user", "restart", "hermes-gateway.service"
    ]


def test_revoked_quota_entry_blocks_gateway_restart():
    runner = ScriptedRunner([result(3, "inactive")])
    auth = {"credential_pool": {"openai-codex": [{
        "id": "revoked", "auth_type": "oauth", "refresh_token": "refresh",
        "last_status": "revoked", "last_error_code": "429",
        "last_error_message": "usage_limit", "last_error_reset_at": time.time() + 600,
    }]}}

    ok, detail = healer.repair_gateway(
        local_cfg(), auth, runner, dry_run=False, sleeper=lambda _: None
    )

    assert ok is False
    assert "credential" in detail
    assert len(runner.calls) == 1


def test_malformed_quota_tokens_block_gateway_restart(monkeypatch):
    runner = ScriptedRunner([result(3, "inactive")])
    auth = {"credential_pool": {"openai-codex": [{
        "id": "quota", "tokens": "bad", "last_status": "exhausted"
    }]}}
    monkeypatch.setattr(healer, "selected_codex_credential", lambda _: None)
    monkeypatch.setattr(healer, "quota_blocked", lambda _: (True, "quota"))

    ok, detail = healer.repair_gateway(
        local_cfg(), auth, runner, dry_run=False, sleeper=lambda _: None
    )

    assert ok is False
    assert "credential" in detail
    assert len(runner.calls) == 1


def test_gateway_polls_at_most_ten_times_after_one_restart():
    sleeps = []
    runner = ScriptedRunner([
        result(3, "inactive"), result(0), *[result(3, "inactive") for _ in range(10)]
    ])
    auth = {"providers": {"openai-codex": {"tokens": {"refresh_token": "refresh"}}}}

    ok, detail = healer.repair_gateway(
        local_cfg(), auth, runner, dry_run=False, sleeper=sleeps.append
    )

    assert ok is False
    assert "did not become active" in detail
    assert len(sleeps) == 9
    assert len(runner.calls) == 12
    assert runner.calls.count([
        "systemctl", "--user", "restart", "hermes-gateway.service"
    ]) == 1


def test_state_is_atomic_private_and_rearms_after_recovery(tmp_path):
    path = tmp_path / "self-heal-state.json"
    state = healer.load_state(path)
    assert healer.fault_transition(state, "local.timer", "failed", 1000) is True
    healer.save_state(path, state)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    state = healer.load_state(path)
    assert healer.fault_transition(state, "local.timer", "failed", 1100) is False
    healer.clear_fault(state, "local.timer")
    assert healer.fault_transition(state, "local.timer", "failed again", 1200) is True


def test_state_save_uses_same_directory_fsync_and_atomic_replace(tmp_path, monkeypatch):
    path = tmp_path / "self-heal-state.json"
    events = []
    real_mkstemp = healer.tempfile.mkstemp
    real_fdopen = healer.os.fdopen
    real_fsync = healer.os.fsync
    real_replace = healer.os.replace

    def spy_mkstemp(*args, **kwargs):
        events.append(("mkstemp", pathlib.Path(kwargs["dir"])))
        return real_mkstemp(*args, **kwargs)

    class TrackingFile:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            self.file.__enter__()
            return self

        def __exit__(self, *args):
            return self.file.__exit__(*args)

        def write(self, value):
            return self.file.write(value)

        def flush(self):
            events.append(("flush",))
            return self.file.flush()

        def fileno(self):
            return self.file.fileno()

    def spy_fdopen(*args, **kwargs):
        return TrackingFile(real_fdopen(*args, **kwargs))

    def spy_fsync(fd):
        events.append(("fsync", fd))
        return real_fsync(fd)

    def spy_replace(source, destination):
        events.append(("replace", pathlib.Path(source), pathlib.Path(destination)))
        return real_replace(source, destination)

    monkeypatch.setattr(healer.tempfile, "mkstemp", spy_mkstemp)
    monkeypatch.setattr(healer.os, "fdopen", spy_fdopen)
    monkeypatch.setattr(healer.os, "fsync", spy_fsync)
    monkeypatch.setattr(healer.os, "replace", spy_replace)

    healer.save_state(path, {"faults": {}})

    assert [event[0] for event in events] == ["mkstemp", "flush", "fsync", "replace"]
    assert events[0][1] == path.parent
    assert events[-1][1].parent == path.parent
    assert events[-1][2] == path


def test_state_rejects_a_dangling_symlink_instead_of_rearming(tmp_path):
    path = tmp_path / "self-heal-state.json"
    path.symlink_to(tmp_path / "missing-state.json")

    with pytest.raises(healer.Disarmed):
        healer.load_state(path)


def test_state_rejects_a_symlink_even_when_its_target_is_valid(tmp_path):
    path = tmp_path / "self-heal-state.json"
    target = tmp_path / "other-state.json"
    target.write_text(json.dumps({"faults": {}}))
    path.symlink_to(target)

    with pytest.raises(healer.Disarmed):
        healer.load_state(path)


def test_state_rejects_malformed_json_instead_of_disarming_repair_silently(tmp_path):
    path = tmp_path / "self-heal-state.json"
    path.write_text("{not json")

    with pytest.raises(healer.Disarmed):
        healer.load_state(path)


def test_state_rejects_a_json_value_that_is_not_an_object(tmp_path):
    path = tmp_path / "self-heal-state.json"
    path.write_text("[]")

    with pytest.raises(healer.Disarmed):
        healer.load_state(path)


def test_state_rejects_a_malformed_faults_record(tmp_path):
    path = tmp_path / "self-heal-state.json"
    path.write_text(json.dumps({"faults": []}))

    with pytest.raises(healer.Disarmed):
        healer.load_state(path)


def test_state_detail_is_bounded_to_prevent_unbounded_state_growth():
    state = {"faults": {}}

    healer.fault_transition(state, "local.timer", "x" * 501, 1000)

    assert state["faults"]["local.timer"]["detail"] == "x" * 500


@pytest.mark.parametrize("bad", ["x;reboot.service", "../x.service", "x.timer.service", ""])
def test_unit_validation_rejects_shell_and_path_tokens(bad):
    with pytest.raises(healer.Disarmed):
        healer.validate_unit(bad, ".service")


@pytest.mark.parametrize("bad", ["bad user", "root;id", "../../root", ""])
def test_peer_validation_rejects_unsafe_ssh_users(tmp_path, bad):
    peer = valid_peer(tmp_path)
    peer["ssh_user"] = bad

    with pytest.raises(healer.Disarmed):
        healer.validate_peer(peer)


@pytest.mark.parametrize("ip", ["100.63.255.255", "100.128.0.0", "192.168.1.8", "not-an-ip"])
def test_peer_validation_rejects_non_tailnet_addresses(tmp_path, ip):
    peer = valid_peer(tmp_path / "known-hosts-case")
    peer["ip"] = ip

    with pytest.raises(healer.Disarmed):
        healer.validate_peer(peer)


@pytest.mark.parametrize(("field", "value"), [
    ("health_timer", "--no-block.timer"),
    ("check_service", "--system.service"),
    ("heartbeat_service", "--wait.service"),
])
def test_peer_validation_rejects_units_that_can_become_systemctl_options(
    tmp_path, field, value
):
    peer = valid_peer(tmp_path)
    peer[field] = value

    with pytest.raises(healer.Disarmed):
        healer.validate_peer(peer)


def test_peer_validation_requires_tailnet_and_private_identity(tmp_path):
    identity = tmp_path / "id_ed25519"
    identity.write_text("test key path")
    identity.chmod(0o600)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("100.74.25.61 ssh-ed25519 test")
    peer = {
        "label": "neb-ops-gcp", "ip": "100.74.25.61", "ssh_user": "hermes",
        "identity_file": str(identity), "known_hosts": str(known_hosts),
        "maintenance_lock": "/home/hermes/.hermes/codex-health/SELF_HEAL_PAUSED",
        "health_timer": "hermes-codex-health-tmn.timer",
        "check_service": "hermes-codex-health-tmn.service",
        "heartbeat_service": "hermes-codex-heartbeat-tmn.service",
    }
    assert healer.validate_peer(peer)["ip"] == "100.74.25.61"


@pytest.mark.parametrize("mode", [0o640, 0o660, 0o604])
def test_peer_validation_rejects_group_or_world_readable_identity(tmp_path, mode):
    peer = valid_peer(tmp_path)
    pathlib.Path(peer["identity_file"]).chmod(mode)

    with pytest.raises(healer.Disarmed):
        healer.validate_peer(peer)


def test_peer_repair_rejects_empty_identity_before_ssh(tmp_path):
    peer = valid_peer(tmp_path)
    pathlib.Path(peer["identity_file"]).write_bytes(b"")
    runner = ScriptedRunner([])

    with pytest.raises(healer.Disarmed):
        healer.ssh_base(peer)
    with pytest.raises(healer.Disarmed):
        healer.repair_peer(peer, runner, fresh_heartbeat, dry_run=False)

    assert runner.calls == []


def test_peer_validation_rejects_group_or_world_writable_known_hosts(tmp_path):
    peer = valid_peer(tmp_path)
    pathlib.Path(peer["known_hosts"]).chmod(0o666)

    with pytest.raises(healer.Disarmed):
        healer.validate_peer(peer)


def test_peer_validation_rejects_openssh_token_expansion_in_file_paths(tmp_path):
    peer = valid_peer(tmp_path)
    identity = tmp_path / "%h-identity"
    identity.write_text("test-key-material")
    identity.chmod(0o600)
    peer["identity_file"] = str(identity)

    with pytest.raises(healer.Disarmed):
        healer.validate_peer(peer)


def test_peer_validation_requires_regular_identity_and_known_hosts_files(tmp_path):
    peer = valid_peer(tmp_path)
    pathlib.Path(peer["identity_file"]).unlink()
    pathlib.Path(peer["identity_file"]).mkdir()

    with pytest.raises(healer.Disarmed):
        healer.validate_peer(peer)

    peer = valid_peer(tmp_path / "known-hosts-case")
    pathlib.Path(peer["known_hosts"]).unlink()
    pathlib.Path(peer["known_hosts"]).mkdir()

    with pytest.raises(healer.Disarmed):
        healer.validate_peer(peer)


def test_peer_validation_rejects_symlinked_identity_and_known_hosts(tmp_path):
    peer = valid_peer(tmp_path / "identity-case")
    identity = pathlib.Path(peer["identity_file"])
    identity_target = identity.with_name("identity-target")
    identity_target.write_text("test identity")
    identity_target.chmod(0o600)
    identity.unlink()
    identity.symlink_to(identity_target)

    with pytest.raises(healer.Disarmed):
        healer.validate_peer(peer)

    peer = valid_peer(tmp_path / "known-hosts-case")
    known_hosts = pathlib.Path(peer["known_hosts"])
    known_hosts_target = known_hosts.with_name("known-hosts-target")
    known_hosts_target.write_text("100.74.25.61 ssh-ed25519 pinned")
    known_hosts.unlink()
    known_hosts.symlink_to(known_hosts_target)

    with pytest.raises(healer.Disarmed):
        healer.validate_peer(peer)


def test_peer_validation_errors_do_not_echo_file_contents(tmp_path):
    peer = valid_peer(tmp_path)
    secret_like_content = base64.b64encode(b"identity material").decode()
    pathlib.Path(peer["identity_file"]).write_text(secret_like_content)
    pathlib.Path(peer["identity_file"]).chmod(0o644)

    with pytest.raises(healer.Disarmed) as excinfo:
        healer.validate_peer(peer)

    assert secret_like_content not in str(excinfo.value)


def test_peer_validation_formatted_failure_does_not_echo_ip_value(tmp_path):
    peer = valid_peer(tmp_path)
    sentinel = "sentinel-ip-value-must-not-appear"
    peer["ip"] = sentinel

    with pytest.raises(healer.Disarmed) as excinfo:
        healer.validate_peer(peer)

    rendered = "".join(traceback.format_exception(excinfo.type, excinfo.value, excinfo.tb))
    assert sentinel not in rendered


def test_peer_repair_uses_pinned_host_and_fixed_systemd_commands(tmp_path):
    peer = valid_peer(tmp_path)
    runner = repair_runner()

    ok, detail = healer.repair_peer(
        peer, runner, fetch_heartbeat=lambda _: {"at": 2000}, dry_run=False
    )

    base = [
        "ssh", "-i", peer["identity_file"], "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes", "-o",
        f"UserKnownHostsFile={peer['known_hosts']}", "-o", "ConnectTimeout=10",
        f"{peer['ssh_user']}@{peer['ip']}",
    ]
    assert ok is True
    assert "verified" in detail
    assert runner.calls == [
        base + ["test", "-e", peer["maintenance_lock"]],
        base + ["systemctl", "--user", "is-enabled", peer["health_timer"]],
        base + ["systemctl", "--user", "enable", "--now", peer["health_timer"]],
        base + ["systemctl", "--user", "restart", peer["heartbeat_service"]],
        base + ["systemctl", "--user", "start", peer["check_service"]],
        base + ["systemctl", "--user", "is-enabled", peer["health_timer"]],
        base + ["systemctl", "--user", "is-active", peer["heartbeat_service"]],
    ]
    assert runner.timeouts == [20] * 7


@pytest.mark.parametrize("args", [
    ("restart", "hermes-codex-health-tmn.timer"),
    ("enable", "--now", "hermes-codex-heartbeat-tmn.service"),
    ("is-active", "hermes-codex-health-tmn.service"),
    ("sudo", "systemctl", "restart", "hermes-gateway.service"),
])
def test_peer_systemctl_rejects_operations_outside_fixed_allowlist(tmp_path, args):
    runner = ScriptedRunner([])

    with pytest.raises(healer.Disarmed):
        healer.ssh_systemctl(valid_peer(tmp_path), runner, *args)

    assert runner.calls == []


@pytest.mark.parametrize("maintenance_lock", [
    "/home/shawn_teamnebula_ai/.hermes/codex-health/SELF_HEAL_PAUSED;id",
    "/home/shawn_teamnebula_ai/../root/SELF_HEAL_PAUSED",
    "/tmp/SELF_HEAL_PAUSED",
])
def test_peer_repair_rejects_unsafe_maintenance_paths_before_ssh(
    tmp_path, maintenance_lock
):
    peer = valid_peer(tmp_path)
    peer["maintenance_lock"] = maintenance_lock
    runner = ScriptedRunner([])

    with pytest.raises(healer.Disarmed):
        healer.repair_peer(peer, runner, fresh_heartbeat, dry_run=False)

    assert runner.calls == []


def test_peer_repair_rejects_bad_stale_threshold_before_ssh(tmp_path):
    peer = valid_peer(tmp_path)
    peer["stale_after_s"] = "soon"
    runner = ScriptedRunner([])

    with pytest.raises(healer.Disarmed):
        healer.repair_peer(peer, runner, fresh_heartbeat, dry_run=False)

    assert runner.calls == []


@pytest.mark.parametrize("masked_state", ["masked", "masked-runtime"])
def test_peer_repair_leaves_masked_timer_unchanged(tmp_path, masked_state):
    peer = valid_peer(tmp_path)
    runner = ScriptedRunner([result(1), result(1, masked_state)])

    ok, detail = healer.repair_peer(peer, runner, unreachable, dry_run=False)

    assert ok is True
    assert masked_state in detail
    assert len(runner.calls) == 2


def test_peer_repair_waits_for_two_misses_and_rearms_after_recovery(tmp_path):
    state = {"peer_misses": {}, "peer_attempts": {}, "faults": {}}
    peer = valid_peer(tmp_path, label="src")

    first = healer.handle_peer(peer, state, unreachable, ScriptedRunner([]), now=1000)
    second = healer.handle_peer(peer, state, unreachable, repair_runner(), now=1100)
    recovered = healer.handle_peer(
        peer, state, fresh_heartbeat, ScriptedRunner([]), now=1200
    )

    assert first.action == "wait"
    assert second.action == "repair"
    assert second.notify is True
    assert recovered.action == "healthy"
    assert "peer.src" not in state["faults"]
    assert "src" not in state["peer_misses"]
    assert "src" not in state["peer_attempts"]


def test_peer_handler_calls_passive_heartbeat_helper_with_prior_misses(
    tmp_path, monkeypatch
):
    calls = []

    def unavailable(url, timeout):
        calls.append((url, timeout))
        raise OSError("unreachable")

    monkeypatch.setattr(healer.PEER_HEARTBEAT_OPENER, "open", unavailable)
    state = {"peer_misses": {}, "peer_attempts": {}, "faults": {}}
    peer = valid_peer(tmp_path, label="src")

    outcome = healer.handle_peer(
        peer, state, healer.peer_heartbeat, ScriptedRunner([]), now=1000
    )

    assert outcome.action == "wait"
    assert calls == [("http://100.74.25.61:8299/heartbeat", 20)]


def test_peer_heartbeat_refuses_redirect_to_second_address(tmp_path, monkeypatch):
    source_hits = []
    target_hits = []

    class QuietHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, _format, *args):
            pass

    class TargetHandler(QuietHandler):
        def do_GET(self):
            target_hits.append(self.path)
            body = json.dumps({"at": int(time.time()), "status": "ok"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    target_url = f"http://127.0.0.1:{target.server_port}/redirect-target"

    class RedirectHandler(QuietHandler):
        def do_GET(self):
            source_hits.append(self.path)
            self.send_response(302)
            self.send_header("Location", target_url)
            self.end_headers()

    redirect = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    source_url = f"http://127.0.0.1:{redirect.server_port}/heartbeat"
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    redirect_thread = threading.Thread(target=redirect.serve_forever, daemon=True)
    target_thread.start()
    redirect_thread.start()
    real_urlopen = urllib.request.urlopen
    monkeypatch.setattr(
        healer, "_peer_heartbeat_url", lambda _peer: source_url, raising=False
    )
    monkeypatch.setattr(
        healer.urllib.request,
        "urlopen",
        lambda _url, timeout: real_urlopen(source_url, timeout=timeout),
    )

    try:
        verdict, _, misses = healer.peer_heartbeat(valid_peer(tmp_path), 0)
    finally:
        redirect.shutdown()
        target.shutdown()
        redirect.server_close()
        target.server_close()
        redirect_thread.join(timeout=2)
        target_thread.join(timeout=2)

    assert verdict == "unknown"
    assert misses == 1
    assert source_hits == ["/heartbeat"]
    assert target_hits == []


def test_peer_handler_rejects_bad_stale_threshold_without_mutating_state(tmp_path):
    peer = valid_peer(tmp_path)
    peer["stale_after_s"] = "soon"
    state = {"faults": {}}
    original = json.dumps(state, sort_keys=True)
    runner = ScriptedRunner([])

    with pytest.raises(healer.Disarmed):
        healer.handle_peer(peer, state, fresh_heartbeat, runner, now=1200)

    assert json.dumps(state, sort_keys=True) == original
    assert runner.calls == []


def test_fresh_heartbeat_rearms_peer_even_when_remote_health_status_is_down(tmp_path):
    peer = valid_peer(tmp_path, label="src")
    state = {
        "peer_misses": {"src": 1},
        "peer_attempts": {"src": 1000},
        "faults": {
            "peer.src": {
                "active": True,
                "alerted": True,
                "last_attempt": 1000,
                "detail": "heartbeat unreachable",
            }
        },
    }

    outcome = healer.handle_peer(
        peer,
        state,
        lambda _: {"at": 1200, "status": "down"},
        ScriptedRunner([]),
        now=1200,
    )

    assert outcome.action == "healthy"
    assert state == {"peer_misses": {}, "peer_attempts": {}, "faults": {}}


def test_maintenance_lock_preserves_attempt_cooldown_until_heartbeat_recovers(tmp_path):
    peer = valid_peer(tmp_path, label="src")
    state = {"peer_misses": {}, "peer_attempts": {}, "faults": {}}
    healer.handle_peer(peer, state, unreachable, ScriptedRunner([]), now=1000)
    locked_runner = ScriptedRunner([result(0)])

    locked = healer.handle_peer(
        peer, state, unreachable, locked_runner, now=1100, retry_s=21600
    )
    cooldown_runner = ScriptedRunner([])
    cooldown = healer.handle_peer(
        peer, state, unreachable, cooldown_runner, now=1200, retry_s=21600
    )

    assert locked.action == "wait" and locked.notify is False
    assert state["peer_attempts"]["src"] == 1100
    assert state["peer_misses"]["src"] >= 2
    assert cooldown.action == "wait" and cooldown.notify is False
    assert cooldown_runner.calls == []


def test_continuing_peer_outage_retries_after_cooldown_without_renotifying(tmp_path):
    state = {"peer_misses": {}, "peer_attempts": {}, "faults": {}}
    peer = valid_peer(tmp_path, label="src")

    healer.handle_peer(peer, state, unreachable, ScriptedRunner([]), now=1000)
    first_repair = healer.handle_peer(
        peer, state, unreachable, repair_runner(), now=1100, retry_s=21600
    )
    cooldown_runner = ScriptedRunner([])
    cooldown = healer.handle_peer(
        peer, state, unreachable, cooldown_runner, now=1200, retry_s=21600
    )
    retry = healer.handle_peer(
        peer, state, unreachable, repair_runner(), now=22700, retry_s=21600
    )

    assert first_repair.action == "repair" and first_repair.notify is True
    assert cooldown.action == "wait" and cooldown.notify is False
    assert cooldown_runner.calls == []
    assert retry.action == "repair" and retry.notify is False
    assert state["peer_attempts"]["src"] == 22700


def test_committed_peer_repair_allowlists_match_one_way_tailnet_topology():
    tmn = json.loads((WATCHDOG / "hosts" / "tmn.json").read_text())
    observer = json.loads(
        (WATCHDOG / "hosts" / "hermes-tmn-observer.json").read_text()
    )
    src = json.loads((WATCHDOG / "hosts" / "src.json").read_text())

    assert tmn["self_heal"]["peers"] == [
        {
            "label": "src",
            "ip": "100.79.251.126",
            "ssh_user": "hermes",
            "identity_file": "~/.ssh/watchdog-repair",
            "known_hosts": "~/.ssh/watchdog-repair-known_hosts",
            "maintenance_lock": "/home/hermes/.hermes/codex-health/SELF_HEAL_PAUSED",
            "health_timer": "hermes-codex-health.timer",
            "check_service": "hermes-codex-health.service",
            "heartbeat_service": "hermes-codex-heartbeat.service",
        },
        {
            "label": "hermes-tmn-observer",
            "ip": "100.126.215.66",
            "ssh_user": "ubuntu",
            "identity_file": "~/.ssh/watchdog-repair",
            "known_hosts": "~/.ssh/watchdog-repair-known_hosts",
            "maintenance_lock": "/home/ubuntu/.watchdog-observer/SELF_HEAL_PAUSED",
            "health_timer": "codex-observer.timer",
            "check_service": "codex-observer.service",
            "heartbeat_service": "codex-observer-heartbeat.service",
        },
    ]
    assert observer["self_heal"]["peers"] == [
        {
            "label": "src",
            "ip": "100.79.251.126",
            "ssh_user": "hermes",
            "identity_file": "~/.ssh/watchdog-repair",
            "known_hosts": "~/.ssh/watchdog-repair-known_hosts",
            "maintenance_lock": "/home/hermes/.hermes/codex-health/SELF_HEAL_PAUSED",
            "health_timer": "hermes-codex-health.timer",
            "check_service": "hermes-codex-health.service",
            "heartbeat_service": "hermes-codex-heartbeat.service",
        },
        {
            "label": "neb-ops-gcp",
            "ip": "100.74.25.61",
            "ssh_user": "shawn_teamnebula_ai",
            "identity_file": "~/.ssh/watchdog-repair",
            "known_hosts": "~/.ssh/watchdog-repair-known_hosts",
            "maintenance_lock": "/home/shawn_teamnebula_ai/.hermes/codex-health/SELF_HEAL_PAUSED",
            "health_timer": "hermes-codex-health-tmn.timer",
            "check_service": "hermes-codex-health-tmn.service",
            "heartbeat_service": "hermes-codex-heartbeat-tmn.service",
        },
    ]
    assert not (src.get("self_heal") or {}).get("peers")


def test_cli_new_failed_repair_alerts_once_then_rearms_after_recovery(
    tmp_path, monkeypatch
):
    cfg_path = write_cli_config(tmp_path)
    state_path = tmp_path / "self-heal-state.json"
    timer_results = iter([
        (False, "timer repair failed"),
        (False, "timer repair failed"),
        (True, "timer recovered"),
        (False, "timer repair failed again"),
    ])
    monkeypatch.setattr(
        healer,
        "repair_health_timer",
        lambda _cfg, _runner, dry_run: next(timer_results),
    )
    monkeypatch.setattr(
        healer,
        "repair_gateway",
        lambda _cfg, _auth, _runner, dry_run: (True, "gateway healthy"),
    )
    monkeypatch.setattr(
        healer,
        "repair_credential",
        lambda *_args, **_kwargs: (True, "credential healthy"),
    )
    args = CliArgs(cfg_path, state_path)

    assert healer.run(args) == 1
    first = json.loads(state_path.read_text())
    assert first["faults"]["local.timer"]["alerted"] is True
    assert healer.run(args) == 0
    assert healer.run(args) == 0
    assert json.loads(state_path.read_text())["faults"] == {}
    assert healer.run(args) == 1


def test_cli_persists_quota_markers_from_credential_handler(tmp_path, monkeypatch):
    cfg_path = write_cli_config(tmp_path)
    state_path = tmp_path / "self-heal-state.json"
    monkeypatch.setattr(
        healer,
        "repair_health_timer",
        lambda *_args, **_kwargs: (True, "timer healthy"),
    )
    monkeypatch.setattr(
        healer,
        "repair_gateway",
        lambda *_args, **_kwargs: (True, "gateway healthy"),
    )

    def record_quota(_cfg, _cfg_path, _auth_path, state, *_args, **_kwargs):
        state["quota_attempt_reset_at"] = 2000
        state["quota_reset_at"] = 3000
        return True, "quota reset recorded"

    monkeypatch.setattr(healer, "repair_credential", record_quota)

    assert healer.run(CliArgs(cfg_path, state_path)) == 0
    saved = json.loads(state_path.read_text())
    assert saved["quota_attempt_reset_at"] == 2000
    assert saved["quota_reset_at"] == 3000


def test_cli_invokes_peer_handler_and_persists_peer_state(tmp_path, monkeypatch):
    peer = valid_peer(tmp_path / "peer", label="neb-ops-gcp")
    cfg_path = write_cli_config(tmp_path, peers=[peer], observer=True)
    state_path = tmp_path / "self-heal-state.json"
    monkeypatch.setattr(
        healer,
        "repair_health_timer",
        lambda *_args, **_kwargs: (True, "timer healthy"),
    )
    calls = []

    def handle(peer_cfg, state, fetch, runner, now, retry_s):
        calls.append((peer_cfg["label"], fetch, runner, retry_s))
        state["peer_misses"] = {peer_cfg["label"]: 2}
        state["peer_attempts"] = {peer_cfg["label"]: now}
        healer.fault_transition(
            state, f"peer.{peer_cfg['label']}", "repair failed", now
        )
        return healer.PeerResult("repair", False, "repair failed", notify=True)

    monkeypatch.setattr(healer, "handle_peer", handle)

    assert healer.run(CliArgs(cfg_path, state_path)) == 1
    saved = json.loads(state_path.read_text())
    assert calls[0][0] == "neb-ops-gcp"
    assert calls[0][3] == 21600
    assert saved["peer_misses"] == {"neb-ops-gcp": 2}
    assert saved["peer_attempts"]["neb-ops-gcp"] > 0
    assert saved["faults"]["peer.neb-ops-gcp"]["alerted"] is True


def test_cli_dry_run_has_no_state_command_network_backup_or_credential_mutation(
    tmp_path, monkeypatch
):
    peer = valid_peer(tmp_path / "peer", label="neb-ops-gcp")
    cfg_path = write_cli_config(tmp_path, peers=[peer])
    cfg = json.loads(cfg_path.read_text())
    auth_path = pathlib.Path(cfg["hermes_home"]) / "auth.json"
    auth_path.write_text(json.dumps(expired_refreshable_singleton()))
    state_path = tmp_path / "self-heal-state.json"
    original = b'{"faults":{}}\n'
    state_path.write_bytes(original)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("dry-run crossed a mutation or network boundary")

    monkeypatch.setattr(healer, "run_command", forbidden)
    monkeypatch.setattr(healer, "peer_heartbeat", forbidden)
    monkeypatch.setattr(healer, "backup_auth", forbidden)
    monkeypatch.setattr(healer, "save_state", forbidden)

    assert healer.run(CliArgs(cfg_path, state_path, dry_run=True)) == 0
    assert state_path.read_bytes() == original
    assert not (tmp_path / "backups").exists()
    assert calls == []


def test_cli_maintenance_lock_pauses_without_state_write_or_handlers(
    tmp_path, monkeypatch
):
    cfg_path = write_cli_config(tmp_path)
    cfg = json.loads(cfg_path.read_text())
    pathlib.Path(cfg["self_heal"]["maintenance_lock"]).touch()
    state_path = tmp_path / "self-heal-state.json"
    original = b'{"faults":{}}\n'
    state_path.write_bytes(original)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("maintenance lock did not pause the healer")

    monkeypatch.setattr(healer, "repair_health_timer", forbidden)
    monkeypatch.setattr(healer, "save_state", forbidden)

    assert healer.run(CliArgs(cfg_path, state_path)) == 0
    assert state_path.read_bytes() == original


def test_cli_main_redacts_disarmed_errors(monkeypatch, capsys):
    secret = "x" * 48
    monkeypatch.setattr(
        healer,
        "run",
        lambda _args: (_ for _ in ()).throw(
            healer.Disarmed(f'access_token="{secret}"')
        ),
    )

    assert healer.main([]) == 1
    stderr = capsys.readouterr().err
    assert "DISARMED" in stderr
    assert secret not in stderr
    assert "[REDACTED]" in stderr


def test_cli_config_defaults_beside_script_and_explicit_flag_still_works(
    tmp_path, monkeypatch
):
    default_dir = tmp_path / "installed"
    default_dir.mkdir()
    default_cfg = write_cli_config(default_dir)
    default_state = default_dir / "dry-state.json"
    explicit_dir = tmp_path / "explicit"
    explicit_dir.mkdir()
    explicit_cfg = write_cli_config(explicit_dir)
    explicit_state = explicit_dir / "dry-state.json"
    monkeypatch.setattr(healer, "HERE", default_dir)

    assert healer.main(["--dry-run", "--state-file", str(default_state)]) == 0
    assert healer.main([
        "--config", str(explicit_cfg), "--dry-run",
        "--state-file", str(explicit_state),
    ]) == 0
    assert default_cfg.exists()
    assert not default_state.exists()
    assert not explicit_state.exists()


def test_every_codex_role_wires_a_healer_timer_and_notifier():
    pairs = {
        "hermes-codex-self-heal.service": (
            "hermes-codex-health-notify.service",
            "%h/.hermes/codex-health/self_heal.py",
            "%h/.hermes/.env",
        ),
        "hermes-codex-self-heal-tmn.service": (
            "hermes-codex-health-tmn-notify.service",
            "%h/.hermes/codex-health/self_heal.py",
            "%h/.hermes/.env",
        ),
        "codex-observer-self-heal.service": (
            "codex-observer-notify.service",
            "%h/.watchdog-observer/self_heal.py",
            "%h/.watchdog-observer/.env",
        ),
    }
    for service, (notifier, script, env_file) in pairs.items():
        body = (WATCHDOG / "systemd" / service).read_text()
        assert "Type=oneshot" in body
        assert f"ExecStart=/usr/bin/python3 {script}" in body
        assert f"EnvironmentFile=-{env_file}" in body
        assert f"OnFailure={notifier}" in body
        assert "TimeoutStartSec=180" in body
        timer = (
            WATCHDOG / "systemd" / service.replace(".service", ".timer")
        ).read_text()
        assert "OnBootSec=2m" in timer
        assert "OnUnitActiveSec=15m" in timer
        assert "Persistent=true" in timer
        assert "WantedBy=timers.target" in timer

    assert not list((WATCHDOG / "systemd").glob("*nebos*self-heal*"))


def test_shipped_role_configs_have_exact_local_healer_settings():
    src = json.loads((WATCHDOG / "hosts" / "src.json").read_text())
    tmn = json.loads((WATCHDOG / "hosts" / "tmn.json").read_text())
    observer = json.loads(
        (WATCHDOG / "hosts" / "hermes-tmn-observer.json").read_text()
    )

    assert {k: v for k, v in src["self_heal"].items() if k != "peers"} == {
        "health_timer": "hermes-codex-health.timer",
        "check_service": "hermes-codex-health.service",
        "gateway_restart": True,
        "codex_model": "openai-codex/gpt-5.5",
        "maintenance_lock": "~/.hermes/codex-health/SELF_HEAL_PAUSED",
        "retry_s": 21600,
    }
    assert {k: v for k, v in tmn["self_heal"].items() if k != "peers"} == {
        "health_timer": "hermes-codex-health-tmn.timer",
        "check_service": "hermes-codex-health-tmn.service",
        "gateway_restart": True,
        "codex_model": "openai-codex/gpt-5.5",
        "maintenance_lock": "~/.hermes/codex-health/SELF_HEAL_PAUSED",
        "retry_s": 21600,
    }
    assert {k: v for k, v in observer["self_heal"].items() if k != "peers"} == {
        "health_timer": "codex-observer.timer",
        "check_service": "codex-observer.service",
        "gateway_restart": False,
        "maintenance_lock": "~/.watchdog-observer/SELF_HEAL_PAUSED",
        "retry_s": 21600,
    }


def test_installer_wires_healer_roles_without_adding_one_to_nebos():
    source = (WATCHDOG / "install.sh").read_text()
    assert 'HEAL_SERVICE="hermes-codex-self-heal.service"' in source
    assert 'HEAL_SERVICE="hermes-codex-self-heal-tmn.service"' in source
    assert 'HEAL_SERVICE="codex-observer-self-heal.service"' in source
    assert 'HEAL_SERVICE=""' in source
    assert 'install -m 0755 "$HERE/auth_state.py" "$DEST/auth_state.py"' in source
    assert 'install -m 0755 "$HERE/self_heal.py" "$DEST/self_heal.py"' in source
    assert 'systemctl --user enable "$HEAL_TIMER"' in source
    assert 'systemctl --user start  "$HEAL_TIMER"' in source
    assert '"$DEST/self_heal.py" --dry-run --state-file' in source
    assert "healer timer enabled" in source
    assert "healer timer active" in source
    assert "healer next elapse" in source
    assert "healer OnFailure" in source


def test_installer_preserves_healer_state_and_backups_and_checks_runtime(
    tmp_path
):
    home = tmp_path / "home"
    dest = home / ".hermes" / "codex-health"
    backups = dest / "backups"
    backups.mkdir(parents=True)
    state_path = dest / "self-heal-state.json"
    state_path.write_text('{"faults":{"keep":{"active":true}}}')
    backup_path = backups / "keep-auth.json"
    backup_path.write_text("keep")
    hermes_home = home / ".hermes"
    auth = healthy_singleton()
    auth["providers"]["openai-codex"]["tokens"]["access_token"] = token_with_exp(
        int(time.time()) + 3600
    )
    (hermes_home / "auth.json").write_text(json.dumps(auth))
    (hermes_home / "config.yaml").write_text(
        "model:\n  provider: openai-codex\n"
    )
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    trace = tmp_path / "systemctl.trace"
    systemctl = fake_bin / "systemctl"
    systemctl.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$TRACE\"\n"
        "[ \"$1\" = --user ] && shift\n"
        "case \"$1\" in\n"
        "  is-enabled) echo enabled ;;\n"
        "  is-active) echo active ;;\n"
        "  show)\n"
        "    case \"$*\" in\n"
        "      *OnFailure*)\n"
        "        case \"$2\" in\n"
        "          hermes-codex-self-heal.service) echo hermes-codex-health-notify.service ;;\n"
        "          *) echo hermes-codex-health-notify.service ;;\n"
        "        esac ;;\n"
        "      *) echo 'Mon 2026-08-31 12:00:00 UTC' ;;\n"
        "    esac ;;\n"
        "esac\n"
    )
    systemctl.chmod(0o755)
    for name, body in {
        "loginctl": "#!/bin/sh\necho yes\n",
        "tailscale": "#!/bin/sh\necho 100.79.251.126\n",
        "curl": "#!/bin/sh\nexit 0\n",
    }.items():
        command = fake_bin / name
        command.write_text(body)
        command.chmod(0o755)
    env = os.environ.copy()
    env.update({
        "HOME": str(home),
        "USER": "hermes",
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "TRACE": str(trace),
        "TELEGRAM_BOT_TOKEN": "test-token",
        "TELEGRAM_HOME_CHANNEL": "123",
    })

    completed = subprocess.run(
        ["/bin/bash", str(WATCHDOG / "install.sh"), "--host", "src"],
        text=True,
        capture_output=True,
        env=env,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert state_path.read_text() == '{"faults":{"keep":{"active":true}}}'
    assert backup_path.read_text() == "keep"
    assert (dest / "auth_state.py").exists()
    assert (dest / "self_heal.py").exists()
    assert (dest / "codex_auth_probe.py").exists()
    trace_text = trace.read_text()
    assert "enable hermes-codex-self-heal.timer" in trace_text
    assert "start hermes-codex-self-heal.timer" in trace_text
    assert "show hermes-codex-self-heal.timer" in trace_text
    assert "show hermes-codex-self-heal.service -p OnFailure --value" in trace_text
    assert "healer dry-run exited 0" in completed.stdout


def test_installer_is_bash_32_syntax_compatible():
    completed = subprocess.run(
        ["/bin/bash", "-n", str(WATCHDOG / "install.sh")],
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_command_result_is_immutable_value_object():
    command_result = result(0, "ok")

    with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
        command_result.returncode = 1


def valid_peer(tmp_path, label="neb-ops-gcp"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    identity = tmp_path / "watchdog-repair"
    identity.write_text("test-key-material")
    identity.chmod(0o600)
    known_hosts = tmp_path / "watchdog-repair-known_hosts"
    known_hosts.write_text("100.74.25.61 ssh-ed25519 test-key")
    return {
        "label": label,
        "ip": "100.74.25.61",
        "ssh_user": "shawn_teamnebula_ai",
        "identity_file": str(identity),
        "known_hosts": str(known_hosts),
        "maintenance_lock": (
            "/home/shawn_teamnebula_ai/.hermes/codex-health/SELF_HEAL_PAUSED"
        ),
        "health_timer": "hermes-codex-health-tmn.timer",
        "check_service": "hermes-codex-health-tmn.service",
        "heartbeat_service": "hermes-codex-heartbeat-tmn.service",
    }


def unreachable(_peer):
    raise OSError("unreachable")


def fresh_heartbeat(_peer):
    return {"at": 1200, "status": "ok"}


def repair_runner():
    return ScriptedRunner([
        result(1), result(1, "disabled"), result(0), result(0), result(0),
        result(0, "enabled"), result(0, "active"),
    ])
