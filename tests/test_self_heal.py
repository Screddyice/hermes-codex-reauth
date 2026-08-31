from __future__ import annotations

import base64
import dataclasses
import importlib.util
import json
import pathlib
import stat
import subprocess
import sys
import time
import traceback

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

    class TimedOutProcess:
        pid = 4321
        returncode = None

        def communicate(self, timeout=None):
            events.append(("communicate", timeout))
            if timeout is not None:
                raise subprocess.TimeoutExpired("hermes", timeout)
            self.returncode = -9
            return "", "timed out"

    def fake_popen(argv, **kwargs):
        events.append(("popen", list(argv), kwargs))
        return TimedOutProcess()

    monkeypatch.setattr(healer.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(healer.os, "killpg", lambda pid, sig: events.append(("killpg", pid, sig)))

    outcome = healer.run_command(["hermes"], timeout=120)

    assert outcome.returncode != 0
    assert events[0][2]["start_new_session"] is True
    assert [event[0] for event in events] == ["popen", "communicate", "killpg", "communicate"]


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


def test_peer_validation_requires_tailnet_and_private_identity(tmp_path):
    identity = tmp_path / "id_ed25519"
    identity.write_text("test key path")
    identity.chmod(0o600)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("100.74.25.61 ssh-ed25519 test")
    peer = {
        "label": "neb-ops-gcp", "ip": "100.74.25.61", "ssh_user": "hermes",
        "identity_file": str(identity), "known_hosts": str(known_hosts),
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


def test_command_result_is_immutable_value_object():
    command_result = result(0, "ok")

    with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
        command_result.returncode = 1


def valid_peer(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    identity = tmp_path / "id_ed25519"
    identity.write_text("test identity")
    identity.chmod(0o600)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("100.74.25.61 ssh-ed25519 pinned")
    return {
        "label": "neb-ops-gcp",
        "ip": "100.74.25.61",
        "ssh_user": "hermes",
        "identity_file": str(identity),
        "known_hosts": str(known_hosts),
        "health_timer": "hermes-codex-health-tmn.timer",
        "check_service": "hermes-codex-health-tmn.service",
        "heartbeat_service": "hermes-codex-heartbeat-tmn.service",
    }
