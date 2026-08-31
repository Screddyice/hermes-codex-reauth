"""Fail-closed state and target-validation primitives for the watchdog healer."""
from __future__ import annotations

import dataclasses
import ipaddress
import json
import os
import pathlib
import re
import stat
import tempfile

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


def load_state(path: pathlib.Path) -> dict:
    """Load valid persisted healer state, or stop before a repair action."""
    path = pathlib.Path(path)
    if not path.exists():
        return {"faults": {}}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Disarmed(f"state file is corrupt or unreadable: {type(exc).__name__}") from exc
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
    except ValueError as exc:
        raise Disarmed("peer address is invalid") from exc
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
