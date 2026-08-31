"""Fail-closed state and target-validation primitives for the watchdog healer."""
from __future__ import annotations

import dataclasses
import ipaddress
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import time

from auth_state import quota_blocked, selected_codex_credential

TAILNET = ipaddress.ip_network("100.64.0.0/10")
UNIT_TOKEN = re.compile(r"^[A-Za-z0-9_.@-]+$")
SSH_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class Disarmed(Exception):
    """The healer cannot safely continue."""


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def run_command(argv: list[str], timeout: int = 20) -> CommandResult:
    """Run one fixed local command without a shell."""
    completed = subprocess.run(
        argv,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
    )
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def systemctl(run_cmd, *args: str) -> CommandResult:
    """Run one local user-systemd command through the injected runner."""
    return run_cmd(["systemctl", "--user", *args], 20)


def repair_health_timer(cfg: dict, run_cmd, dry_run: bool) -> tuple[bool, str]:
    """Repair the configured health timer once, then prove its schedule."""
    timer, check_service = _local_timer_units(cfg)
    if dry_run:
        argv = ["systemctl", "--user", "enable", "--now", timer]
        return True, f"dry-run: {' '.join(argv)}"

    enabled = systemctl(run_cmd, "is-enabled", timer)
    enabled_state = enabled.stdout.strip().lower()
    if enabled_state in {"masked", "masked-runtime"}:
        return True, f"health timer is {enabled_state}; leaving it unchanged"

    if enabled.returncode != 0:
        if enabled_state != "disabled":
            return False, "health timer is not enabled"
        repair = systemctl(run_cmd, "enable", "--now", timer)
        if repair.returncode != 0:
            return False, "health timer enable failed"
        return _verify_timer(run_cmd, timer)

    active, next_elapse = _timer_status(run_cmd, timer)
    if active and _has_next_elapse(next_elapse):
        return True, "health timer is active and scheduled"

    restarted = systemctl(run_cmd, "restart", timer)
    if restarted.returncode != 0:
        return False, "health timer restart failed"
    started = systemctl(run_cmd, "start", check_service)
    if started.returncode != 0:
        return False, "health check service start failed"
    return _verify_timer(run_cmd, timer)


def _local_timer_units(cfg: dict) -> tuple[str, str]:
    if not isinstance(cfg, dict) or not isinstance(cfg.get("self_heal"), dict):
        raise Disarmed("self-heal configuration is malformed")
    self_heal = cfg["self_heal"]
    return (
        validate_unit(self_heal.get("health_timer"), ".timer"),
        validate_unit(self_heal.get("check_service"), ".service"),
    )


def _timer_status(run_cmd, timer: str) -> tuple[bool, str]:
    active = systemctl(run_cmd, "is-active", timer)
    next_elapse = systemctl(
        run_cmd, "show", timer, "--property=NextElapseUSecRealtime", "--value"
    )
    return active.returncode == 0 and active.stdout.strip() == "active", next_elapse.stdout.strip()


def _verify_timer(run_cmd, timer: str) -> tuple[bool, str]:
    enabled = systemctl(run_cmd, "is-enabled", timer)
    active, next_elapse = _timer_status(run_cmd, timer)
    if enabled.returncode == 0 and active and _has_next_elapse(next_elapse):
        return True, f"health timer is active and scheduled for {next_elapse}"
    return False, "health timer did not become enabled, active, and scheduled"


def _has_next_elapse(value: str) -> bool:
    return value.strip().lower() not in {"", "n/a", "[not set]"}


def repair_gateway(
    cfg: dict, auth: dict, run_cmd, dry_run: bool, sleeper=time.sleep
) -> tuple[bool, str]:
    """Restart an inactive local gateway once when passive auth state permits it."""
    if not isinstance(cfg, dict):
        raise Disarmed("self-heal configuration is malformed")
    gateway = validate_unit(cfg.get("gateway_unit"), ".service")
    self_heal = cfg.get("self_heal")
    if not isinstance(self_heal, dict):
        raise Disarmed("self-heal configuration is malformed")
    if dry_run:
        argv = ["systemctl", "--user", "restart", gateway]
        return True, f"dry-run: {' '.join(argv)}"

    current = systemctl(run_cmd, "is-active", gateway)
    if current.returncode == 0 and current.stdout.strip() == "active":
        return True, "gateway is active"

    if not _gateway_can_recover(auth):
        return False, "gateway is inactive and no recoverable credential is available"
    if not self_heal.get("gateway_restart"):
        return False, "gateway restart is disabled"

    restarted = systemctl(run_cmd, "restart", gateway)
    if restarted.returncode != 0:
        return False, "gateway restart failed"

    for attempt in range(10):
        current = systemctl(run_cmd, "is-active", gateway)
        if current.returncode == 0 and current.stdout.strip() == "active":
            return True, "gateway is active after restart"
        if attempt < 9:
            sleeper(1)
    return False, "gateway did not become active after restart"


def _gateway_can_recover(auth: dict) -> bool:
    if not isinstance(auth, dict):
        return False
    try:
        if selected_codex_credential(auth) is not None:
            return True
        exhausted, _ = quota_blocked(auth)
        pool = (auth.get("credential_pool") or {}).get("openai-codex") or []
    except (AttributeError, TypeError, ValueError):
        return False
    if not exhausted:
        return False
    if not isinstance(pool, list):
        return False
    return any(
        isinstance(entry, dict)
        and str(entry.get("last_status") or "").lower() != "dead"
        and bool((entry.get("tokens") or entry).get("refresh_token"))
        for entry in pool
    )


def load_state(path: pathlib.Path) -> dict:
    """Load valid persisted healer state, or stop before a repair action."""
    path = pathlib.Path(path)
    try:
        file_stat = path.lstat()
    except FileNotFoundError:
        return {"faults": {}}
    except OSError:
        raise Disarmed("state file is corrupt or unreadable") from None
    if not stat.S_ISREG(file_stat.st_mode):
        raise Disarmed("state file is not a regular file")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise Disarmed("state file is corrupt or unreadable") from None
    _validate_state(state)
    return state


def save_state(path: pathlib.Path, state: dict) -> None:
    """Persist healer state through a private, same-directory atomic replace."""
    _validate_state(state)
    path = pathlib.Path(path)
    temp_name = None
    try:
        fd, temp_name = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
        )
        os.chmod(temp_name, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
            json.dump(state, temp_file, separators=(",", ":"), sort_keys=True)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_name, path)
        temp_name = None
    except (OSError, TypeError, ValueError) as exc:
        raise Disarmed(f"cannot write healer state: {type(exc).__name__}") from exc
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def fault_transition(state: dict, key: str, detail: str, now: int) -> bool:
    faults = state.setdefault("faults", {})
    current = faults.get(key) or {}
    first = not bool(current.get("active"))
    faults[key] = {
        "active": True,
        "alerted": bool(current.get("alerted")) or first,
        "last_attempt": now,
        "detail": detail[:500],
    }
    return first


def clear_fault(state: dict, key: str) -> None:
    (state.get("faults") or {}).pop(key, None)


def validate_unit(value: str, suffix: str) -> str:
    """Return a single systemd unit token with the required unit type."""
    if not isinstance(value, str) or not isinstance(suffix, str):
        raise Disarmed("unit must be a valid token")
    if not suffix or not value.endswith(suffix) or not UNIT_TOKEN.fullmatch(value):
        raise Disarmed("unit must be a valid token")
    stem = value[:-len(suffix)]
    if not stem or stem.endswith((".service", ".timer")):
        raise Disarmed("unit must have one allowed suffix")
    return value


def validate_peer(peer: dict) -> dict:
    """Validate a fixed peer target before later code builds any SSH argv."""
    if not isinstance(peer, dict):
        raise Disarmed("peer configuration is malformed")

    try:
        address = ipaddress.ip_address(peer.get("ip"))
    except (TypeError, ValueError):
        raise Disarmed("peer address is invalid") from None
    if address not in TAILNET:
        raise Disarmed("peer address is outside the tailnet")

    ssh_user = peer.get("ssh_user")
    if not isinstance(ssh_user, str) or not SSH_USER.fullmatch(ssh_user):
        raise Disarmed("peer SSH user is invalid")

    validate_unit(peer.get("health_timer"), ".timer")
    validate_unit(peer.get("check_service"), ".service")
    validate_unit(peer.get("heartbeat_service"), ".service")
    _validate_private_regular_file(peer.get("identity_file"), "identity")
    _validate_regular_file(peer.get("known_hosts"), "known-hosts")
    return dict(peer)


def _validate_state(state: object) -> None:
    if not isinstance(state, dict):
        raise Disarmed("state file is malformed")
    faults = state.get("faults")
    if not isinstance(faults, dict):
        raise Disarmed("state file is malformed")
    for key, record in faults.items():
        if not isinstance(key, str) or not isinstance(record, dict):
            raise Disarmed("state file is malformed")
        if not isinstance(record.get("active"), bool):
            raise Disarmed("state file is malformed")
        if not isinstance(record.get("alerted"), bool):
            raise Disarmed("state file is malformed")
        if not isinstance(record.get("last_attempt"), int):
            raise Disarmed("state file is malformed")
        if not isinstance(record.get("detail"), str):
            raise Disarmed("state file is malformed")


def _validate_private_regular_file(value: object, label: str) -> None:
    path = _path_from_value(value, label)
    try:
        file_stat = path.lstat()
    except OSError as exc:
        raise Disarmed(f"{label} file is unavailable") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise Disarmed(f"{label} file is not regular")
    if file_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise Disarmed(f"{label} file permissions are unsafe")


def _validate_regular_file(value: object, label: str) -> None:
    path = _path_from_value(value, label)
    try:
        file_stat = path.lstat()
    except OSError as exc:
        raise Disarmed(f"{label} file is unavailable") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise Disarmed(f"{label} file is not regular")


def _path_from_value(value: object, label: str) -> pathlib.Path:
    if not isinstance(value, str) or not value:
        raise Disarmed(f"{label} file is invalid")
    return pathlib.Path(value)
