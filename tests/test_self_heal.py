from __future__ import annotations

import base64
import dataclasses
import importlib.util
import json
import pathlib
import stat
import sys
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
WATCHDOG = HERE.parent / "watchdog"


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
