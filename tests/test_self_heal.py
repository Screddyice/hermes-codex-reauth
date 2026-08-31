from __future__ import annotations

import base64
import dataclasses
import importlib.util
import json
import pathlib
import stat
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
        return self.results.pop(0)


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
