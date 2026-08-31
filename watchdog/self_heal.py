"""Fail-closed state and target-validation primitives for the watchdog healer."""
from __future__ import annotations

import base64
import dataclasses
import ipaddress
import json
import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

from auth_state import full_pool_reset_at, quota_blocked, selected_codex_credential

TAILNET = ipaddress.ip_network("100.64.0.0/10")
HERE = pathlib.Path(__file__).resolve().parent
COMMAND_CAPTURE_LIMIT = 64 * 1024
UNIT_TOKEN = re.compile(r"^[A-Za-z0-9_.@-]+$")
SSH_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
PEER_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
LOCAL_FILE_PATH = re.compile(r"^(?:~/|/)[A-Za-z0-9_./@+-]+$")
JWT_TOKEN = re.compile(r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b")
LONG_TOKEN = re.compile(r"\b[A-Za-z0-9_-]{40,}\b")
BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+\S+")
NAMED_TOKEN = re.compile(
    r"(?ix)"
    r"(?P<prefix>[\"']?(?:access_token|refresh_token|id_token|api_key|authorization)"
    r"[\"']?\s*[:=]\s*)"
    r"(?:(?P<quote>[\"'])(?P<quoted>.*?)(?P=quote)|(?P<bare>[^\s,}\]]+))"
)
TERMINAL_CREDENTIAL_CODES = frozenset({
    "refresh_token_reused",
    "invalid_grant",
    "token_revoked",
    "token_invalidated",
    "invalid_token",
    "dead",
})


class Disarmed(Exception):
    """The healer cannot safely continue."""


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclasses.dataclass(frozen=True)
class PeerResult:
    action: str
    ok: bool
    detail: str
    notify: bool = False


@dataclasses.dataclass(frozen=True)
class _PeerRepairResult:
    ok: bool
    detail: str
    skipped: bool = False


def run_command(argv: list[str], timeout: int = 20) -> CommandResult:
    """Run one fixed local command without a shell."""
    with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(
        mode="w+b"
    ) as stderr_file:
        process = subprocess.Popen(
            argv,
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
        )
        timed_out = False
        try:
            process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
        stdout = _read_command_capture(stdout_file)
        stderr = _read_command_capture(stderr_file)
        if timed_out:
            return CommandResult(124, stdout, stderr or "command timed out")
        return CommandResult(process.returncode, stdout, stderr)


def _read_command_capture(capture_file) -> str:
    capture_file.flush()
    capture_file.seek(0)
    captured = capture_file.read(COMMAND_CAPTURE_LIMIT)
    return captured.decode("utf-8", errors="replace")


def systemctl(run_cmd, *args: str) -> CommandResult:
    """Run one local user-systemd command through the injected runner."""
    return run_cmd(["systemctl", "--user", *args], 20)


def credential_action(auth: dict, now: float) -> str:
    """Choose the only safe credential action from passive Hermes state."""
    if not isinstance(auth, dict):
        return "human_2fa"
    try:
        pool = (auth.get("credential_pool") or {}).get("openai-codex") or []
        if not isinstance(pool, list) or any(not isinstance(entry, dict) for entry in pool):
            return "human_2fa"

        blocked, _ = quota_blocked(auth, now)
        recorded_reset = full_pool_reset_at(auth, 0.0)
        if blocked:
            return "wait_quota" if _renewable_pool_entries(pool) else "human_2fa"

        selected = selected_codex_credential(auth, now)
    except (AttributeError, TypeError, ValueError):
        return "human_2fa"

    if recorded_reset is not None and now >= recorded_reset:
        return "warmup" if _renewable_pool_entries(pool) else "human_2fa"
    if selected is None:
        return "human_2fa"
    if _credential_is_terminal(selected):
        alternates = [
            entry for entry in _renewable_pool_entries(pool)
            if entry is not selected and not _credential_is_terminal(entry)
        ]
        return "warmup" if alternates else "human_2fa"

    tokens = _credential_tokens(selected)
    if not tokens.get("refresh_token"):
        return "human_2fa"
    expires_at = _jwt_exp(tokens.get("access_token"))
    if expires_at is None or expires_at <= now:
        return "warmup"
    if pool and any(_credential_is_terminal(entry) for entry in pool if entry is not selected):
        return "warmup"
    if pool and _singleton_is_terminal(auth):
        return "warmup"
    return "none"


def backup_auth(
    auth_path: pathlib.Path, backup_dir: pathlib.Path, now: int
) -> pathlib.Path:
    """Create one durable private auth snapshot and retain the newest five."""
    auth_path = pathlib.Path(auth_path)
    backup_dir = pathlib.Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
    backup_path = backup_dir / f"{stamp}-auth.json"
    backup_fd = os.open(
        backup_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        os.fchmod(backup_fd, 0o600)
    finally:
        os.close(backup_fd)
    try:
        shutil.copyfile(auth_path, backup_path)
    except BaseException:
        backup_path.unlink(missing_ok=True)
        raise
    with backup_path.open("rb") as backup_file:
        os.fsync(backup_file.fileno())
    for old_path in sorted(backup_dir.glob("*-auth.json"))[:-5]:
        old_path.unlink()
    return backup_path


def run_hermes_warmup(cfg: dict, run_cmd) -> CommandResult:
    """Let Hermes perform one bounded refresh through its pinned provider."""
    if not isinstance(cfg, dict) or not isinstance(cfg.get("self_heal"), dict):
        raise Disarmed("self-heal configuration is malformed")
    model = cfg["self_heal"].get("codex_model")
    if not isinstance(model, str) or not model:
        raise Disarmed("Codex warmup model is invalid")
    return run_cmd([
        "hermes", "--safe-mode", "--provider", "openai-codex",
        "-m", model, "-z", "Reply with exactly: OK",
    ], 120)


def run_live_probe(cfg_path: pathlib.Path, run_cmd) -> CommandResult:
    """Run the pool-aware operator probe once and decide by exit code only."""
    return run_cmd([
        sys.executable,
        str(HERE / "codex_auth_probe.py"),
        "--config",
        str(pathlib.Path(cfg_path)),
    ], 40)


def repair_credential(
    cfg: dict,
    cfg_path: pathlib.Path,
    auth_path: pathlib.Path,
    state: dict,
    run_cmd,
    now: int,
    dry_run: bool,
) -> tuple[bool, str]:
    """Perform at most one backed-up Hermes refresh and one live probe."""
    _validate_state(state)
    auth_path = pathlib.Path(auth_path)
    cfg_path = pathlib.Path(cfg_path)
    auth = _read_auth(auth_path)
    action = credential_action(auth, now)
    reset_at = full_pool_reset_at(auth, 0.0)

    if action == "none":
        return True, "credential is healthy"
    if action == "human_2fa":
        return False, "credential requires human 2FA; no automated login attempted"
    if action == "wait_quota":
        when = _format_reset(reset_at)
        return True, f"quota recovery waits until recorded reset {when}"

    if reset_at is not None and now >= reset_at:
        attempted_at = state.get("quota_attempt_reset_at")
        if attempted_at == reset_at:
            return True, f"quota reset {_format_reset(reset_at)} was already attempted"

    if dry_run:
        return True, "dry-run: back up auth, run one Hermes warmup, restart gateway, run one probe"

    backup_path = backup_auth(auth_path, cfg_path.parent / "backups", now)
    if reset_at is not None and now >= reset_at:
        state["quota_attempt_reset_at"] = reset_at

    warmup = run_hermes_warmup(cfg, run_cmd)
    if warmup.returncode != 0:
        return False, _command_failure("Hermes warmup failed", warmup, backup_path)

    refreshed_auth = _read_auth(auth_path)
    if credential_action(refreshed_auth, now) == "human_2fa":
        return False, _bounded_detail(
            f"no recoverable credential after warmup; backup retained at {backup_path}"
        )
    gateway_ok, gateway_detail = repair_gateway(
        cfg,
        refreshed_auth,
        run_cmd,
        dry_run=False,
        force_restart=True,
    )
    if not gateway_ok:
        return False, _bounded_detail(f"{gateway_detail}; backup retained at {backup_path}")

    probe = run_live_probe(cfg_path, run_cmd)
    if probe.returncode == 0:
        return True, _bounded_detail(f"credential repair verified; backup retained at {backup_path}")
    if probe.returncode == 1:
        return False, _command_failure(
            "credential requires human 2FA after repair", probe, backup_path
        )
    if probe.returncode == 2:
        return False, _command_failure(
            "credential verification failed", probe, backup_path
        )
    if probe.returncode == 3:
        next_reset = full_pool_reset_at(refreshed_auth, 0.0)
        if next_reset is None:
            return False, _command_failure(
                "quota probe returned no recorded reset", probe, backup_path
            )
        state["quota_reset_at"] = next_reset
        return True, _bounded_detail(
            f"quota remains blocked until recorded reset {_format_reset(next_reset)}; "
            f"backup retained at {backup_path}"
        )
    return False, _command_failure(
        f"credential probe returned unsupported code {probe.returncode}",
        probe,
        backup_path,
    )


def _read_auth(auth_path: pathlib.Path) -> dict:
    try:
        auth = json.loads(auth_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Disarmed(f"cannot read auth state: {type(exc).__name__}") from exc
    if not isinstance(auth, dict):
        raise Disarmed("auth state is malformed")
    return auth


def _format_reset(reset_at: float | None) -> str:
    if reset_at is None:
        return "unknown"
    return str(int(reset_at)) if reset_at.is_integer() else str(reset_at)


def _command_failure(
    prefix: str, outcome: CommandResult, backup_path: pathlib.Path
) -> str:
    captured = "\n".join(part for part in (outcome.stdout, outcome.stderr) if part)
    detail = f"{prefix}; backup retained at {backup_path}"
    if captured:
        detail += f"; output: {captured}"
    return _bounded_detail(detail)


def _bounded_detail(detail: str) -> str:
    redacted = BEARER_TOKEN.sub("Bearer [REDACTED]", detail)
    redacted = NAMED_TOKEN.sub(_redact_named_token, redacted)
    redacted = JWT_TOKEN.sub("[REDACTED]", redacted)
    redacted = LONG_TOKEN.sub("[REDACTED]", redacted)
    return redacted[:500]


def _redact_named_token(match: re.Match) -> str:
    quote = match.group("quote") or ""
    return f"{match.group('prefix')}{quote}[REDACTED]{quote}"


def _credential_tokens(entry: dict) -> dict:
    tokens = entry.get("tokens") or entry
    return tokens if isinstance(tokens, dict) else {}


def _credential_is_terminal(entry: dict) -> bool:
    status = str(entry.get("last_status") or "").lower()
    error = entry.get("last_auth_error") or {}
    if not isinstance(error, dict):
        error = {}
    code = str(entry.get("last_error_code") or error.get("code") or "").lower()
    return status in TERMINAL_CREDENTIAL_CODES or code in TERMINAL_CREDENTIAL_CODES


def _renewable_pool_entries(pool: list[dict]) -> list[dict]:
    return [
        entry for entry in pool
        if _credential_tokens(entry).get("refresh_token")
        and not _credential_is_terminal(entry)
    ]


def _singleton_is_terminal(auth: dict) -> bool:
    provider = (auth.get("providers") or {}).get("openai-codex") or {}
    return isinstance(provider, dict) and _credential_is_terminal(provider)


def _jwt_exp(token: object) -> float | None:
    if not isinstance(token, str):
        return None
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return float(claims["exp"])
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


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
    cfg: dict,
    auth: dict,
    run_cmd,
    dry_run: bool,
    sleeper=time.sleep,
    force_restart: bool = False,
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

    if not force_restart:
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
        and str(entry.get("last_status") or "").lower() == "exhausted"
        and isinstance(entry.get("tokens") or entry, dict)
        and bool((entry.get("tokens") or entry).get("refresh_token"))
        for entry in pool
    )


def ssh_base(peer: dict) -> list[str]:
    """Build the pinned OpenSSH argv for one validated tailnet peer."""
    return _ssh_base(validate_peer(peer))


def _ssh_base(peer: dict) -> list[str]:
    return [
        "ssh", "-i", peer["identity_file"], "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes", "-o",
        f"UserKnownHostsFile={peer['known_hosts']}", "-o", "ConnectTimeout=10",
        f"{peer['ssh_user']}@{peer['ip']}",
    ]


def ssh_systemctl(peer: dict, run_cmd, *args: str) -> CommandResult:
    """Run one peer-specific systemd operation from the fixed allowlist."""
    validated = validate_peer(peer)
    allowed = {
        ("is-enabled", validated["health_timer"]),
        ("enable", "--now", validated["health_timer"]),
        ("restart", validated["heartbeat_service"]),
        ("start", validated["check_service"]),
        ("is-active", validated["heartbeat_service"]),
    }
    if tuple(args) not in allowed:
        raise Disarmed("peer systemd operation is not allowed")
    return run_cmd(_ssh_base(validated) + ["systemctl", "--user", *args], 20)


def peer_heartbeat(peer: dict, previous_misses: int) -> tuple[str, str, int]:
    """Fetch and classify one peer heartbeat without mutating peer state."""
    validated = validate_peer(peer)
    if isinstance(previous_misses, bool) or not isinstance(previous_misses, int):
        raise Disarmed("peer miss count is invalid")
    if previous_misses < 0:
        raise Disarmed("peer miss count is invalid")
    label = validated["label"]
    stale_after = _validate_stale_after(validated)
    url = f"http://{validated['ip']}:8299/heartbeat"
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            heartbeat = json.loads(response.read())
        if not isinstance(heartbeat, dict):
            raise ValueError("heartbeat is malformed")
        at = heartbeat.get("at")
        if isinstance(at, bool) or not isinstance(at, (int, float)):
            raise ValueError("heartbeat timestamp is malformed")
    except Exception as exc:
        misses = previous_misses + 1
        detail = f"{label} heartbeat unreachable ({type(exc).__name__}), {misses} consecutive"
        return ("peer" if misses >= 2 else "unknown"), detail, misses

    age = int(time.time() - at)
    if age > stale_after:
        return "peer", f"{label} heartbeat is stale by {age} seconds", 0
    return "ok", f"{label} heartbeat is {max(age, 0)} seconds old", 0


def repair_peer(
    peer: dict,
    run_cmd,
    fetch_heartbeat,
    dry_run: bool,
) -> tuple[bool, str]:
    """Repair one allowlisted peer timer and heartbeat, then read postconditions."""
    outcome = _repair_peer(peer, run_cmd, fetch_heartbeat, dry_run)
    return outcome.ok, outcome.detail


def _repair_peer(
    peer: dict,
    run_cmd,
    fetch_heartbeat,
    dry_run: bool,
) -> _PeerRepairResult:
    validated = validate_peer(peer)
    _validate_stale_after(validated)
    if dry_run:
        commands = [
            _ssh_base(validated) + ["test", "-e", validated["maintenance_lock"]],
            _ssh_base(validated) + [
                "systemctl", "--user", "enable", "--now", validated["health_timer"]
            ],
            _ssh_base(validated) + [
                "systemctl", "--user", "restart", validated["heartbeat_service"]
            ],
            _ssh_base(validated) + [
                "systemctl", "--user", "start", validated["check_service"]
            ],
        ]
        return _PeerRepairResult(
            True, "dry-run: " + " ; ".join(" ".join(argv) for argv in commands)
        )

    lock = run_cmd(
        _ssh_base(validated) + ["test", "-e", validated["maintenance_lock"]], 20
    )
    if lock.returncode == 0:
        return _PeerRepairResult(
            True, "peer maintenance lock is present; leaving peer unchanged", skipped=True
        )
    if lock.returncode != 1:
        return _PeerRepairResult(False, "peer maintenance lock could not be checked")

    enabled = ssh_systemctl(validated, run_cmd, "is-enabled", validated["health_timer"])
    enabled_state = enabled.stdout.strip().lower()
    if enabled_state in {"masked", "masked-runtime"}:
        return _PeerRepairResult(
            True,
            f"peer health timer is {enabled_state}; leaving it unchanged",
            skipped=True,
        )
    if enabled.returncode != 0:
        if enabled_state != "disabled":
            return _PeerRepairResult(False, "peer health timer state could not be read")
        repaired = ssh_systemctl(
            validated, run_cmd, "enable", "--now", validated["health_timer"]
        )
        if repaired.returncode != 0:
            return _PeerRepairResult(False, "peer health timer enable failed")
    elif enabled_state != "enabled":
        return _PeerRepairResult(False, "peer health timer is not enabled")

    heartbeat_restart = ssh_systemctl(
        validated, run_cmd, "restart", validated["heartbeat_service"]
    )
    if heartbeat_restart.returncode != 0:
        return _PeerRepairResult(False, "peer heartbeat restart failed")
    check_start = ssh_systemctl(validated, run_cmd, "start", validated["check_service"])
    if check_start.returncode != 0:
        return _PeerRepairResult(False, "peer health check start failed")

    enabled = ssh_systemctl(validated, run_cmd, "is-enabled", validated["health_timer"])
    active = ssh_systemctl(validated, run_cmd, "is-active", validated["heartbeat_service"])
    if enabled.returncode != 0 or enabled.stdout.strip().lower() != "enabled":
        return _PeerRepairResult(False, "peer health timer did not become enabled")
    if active.returncode != 0 or active.stdout.strip().lower() != "active":
        return _PeerRepairResult(False, "peer heartbeat service did not become active")
    try:
        heartbeat = _call_heartbeat(fetch_heartbeat, validated, 0)
    except Exception as exc:
        return _PeerRepairResult(
            False, f"peer heartbeat postcondition failed ({type(exc).__name__})"
        )
    if not _heartbeat_fetch_succeeded(heartbeat):
        return _PeerRepairResult(False, "peer heartbeat postcondition failed")
    return _PeerRepairResult(True, "peer timer, check, and heartbeat repair verified")


def handle_peer(
    peer: dict,
    state: dict,
    fetch_heartbeat,
    run_cmd,
    now: int,
    retry_s: int = 21600,
) -> PeerResult:
    """Wait for two misses, then edge-trigger one bounded peer repair."""
    validated = validate_peer(peer)
    _validate_stale_after(validated)
    _validate_state(state)
    if isinstance(now, bool) or not isinstance(now, int):
        raise Disarmed("peer repair time is invalid")
    if isinstance(retry_s, bool) or not isinstance(retry_s, int) or retry_s <= 0:
        raise Disarmed("peer retry interval is invalid")

    label = validated["label"]
    fault_key = f"peer.{label}"
    misses = state.setdefault("peer_misses", {})
    attempts = state.setdefault("peer_attempts", {})
    try:
        heartbeat = _call_heartbeat(fetch_heartbeat, validated, misses.get(label, 0))
        healthy, detail = _heartbeat_is_healthy(heartbeat, now, validated)
    except Disarmed:
        raise
    except Exception as exc:
        healthy = False
        detail = f"{label} heartbeat unreachable ({type(exc).__name__})"

    if healthy:
        misses.pop(label, None)
        attempts.pop(label, None)
        clear_fault(state, fault_key)
        return PeerResult("healthy", True, detail)

    miss_count = misses.get(label, 0) + 1
    misses[label] = miss_count
    if miss_count < 2:
        return PeerResult("wait", True, f"{detail}; first consecutive miss")

    last_attempt = attempts.get(label)
    if last_attempt is not None and now - last_attempt < retry_s:
        remaining = retry_s - (now - last_attempt)
        return PeerResult("wait", False, f"{detail}; retry in {remaining} seconds")

    attempts[label] = now
    repair = _repair_peer(validated, run_cmd, fetch_heartbeat, dry_run=False)
    if repair.skipped:
        return PeerResult("wait", True, repair.detail)
    if repair.ok:
        misses.pop(label, None)
        attempts.pop(label, None)
        clear_fault(state, fault_key)
        return PeerResult("repair", True, repair.detail)

    notify = fault_transition(state, fault_key, repair.detail, now)
    return PeerResult("repair", False, repair.detail, notify=notify)


def _heartbeat_fetch_succeeded(heartbeat: object) -> bool:
    if isinstance(heartbeat, tuple) and len(heartbeat) == 3:
        return heartbeat[0] == "ok"
    if not isinstance(heartbeat, dict):
        return False
    at = heartbeat.get("at")
    return (
        not isinstance(at, bool)
        and isinstance(at, (int, float))
        and at > 0
    )


def _call_heartbeat(fetch_heartbeat, peer: dict, previous_misses: int):
    if fetch_heartbeat is peer_heartbeat:
        return fetch_heartbeat(peer, previous_misses)
    return fetch_heartbeat(peer)


def _heartbeat_is_healthy(
    heartbeat: object, now: int, peer: dict
) -> tuple[bool, str]:
    label = peer["label"]
    if isinstance(heartbeat, tuple) and len(heartbeat) == 3:
        verdict, detail, _ = heartbeat
        return verdict == "ok", str(detail)
    if not _heartbeat_fetch_succeeded(heartbeat):
        return False, f"{label} heartbeat is malformed or unhealthy"
    stale_after = _validate_stale_after(peer)

    age = now - heartbeat["at"]
    if age > stale_after:
        return False, f"{label} heartbeat is stale by {int(age)} seconds"
    return True, f"{label} heartbeat is fresh"


def _validate_stale_after(peer: dict) -> int | float:
    stale_after = peer.get("stale_after_s", 46800)
    if isinstance(stale_after, bool) or not isinstance(stale_after, (int, float)):
        raise Disarmed("peer stale threshold is invalid")
    if stale_after <= 0:
        raise Disarmed("peer stale threshold is invalid")
    return stale_after


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

    label = peer.get("label")
    if not isinstance(label, str) or not PEER_LABEL.fullmatch(label):
        raise Disarmed("peer label is invalid")

    ssh_user = peer.get("ssh_user")
    if not isinstance(ssh_user, str) or not SSH_USER.fullmatch(ssh_user):
        raise Disarmed("peer SSH user is invalid")

    _validate_maintenance_lock(peer.get("maintenance_lock"), ssh_user)
    _validate_peer_unit(peer.get("health_timer"), ".timer")
    _validate_peer_unit(peer.get("check_service"), ".service")
    _validate_peer_unit(peer.get("heartbeat_service"), ".service")
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
    quota_attempt = state.get("quota_attempt_reset_at")
    if quota_attempt is not None and (
        isinstance(quota_attempt, bool) or not isinstance(quota_attempt, (int, float))
    ):
        raise Disarmed("state file is malformed")
    quota_reset = state.get("quota_reset_at")
    if quota_reset is not None and (
        isinstance(quota_reset, bool) or not isinstance(quota_reset, (int, float))
    ):
        raise Disarmed("state file is malformed")
    _validate_peer_state_map(state.get("peer_misses"), "misses")
    _validate_peer_state_map(state.get("peer_attempts"), "attempts")


def _validate_peer_state_map(value: object, label: str) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise Disarmed("state file is malformed")
    for peer_label, recorded in value.items():
        if not isinstance(peer_label, str) or not PEER_LABEL.fullmatch(peer_label):
            raise Disarmed("state file is malformed")
        if isinstance(recorded, bool) or not isinstance(recorded, int) or recorded < 0:
            raise Disarmed(f"peer {label} state is malformed")


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
    if file_stat.st_size == 0:
        raise Disarmed(f"{label} file is empty")
    if file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise Disarmed(f"{label} file permissions are unsafe")


def _path_from_value(value: object, label: str) -> pathlib.Path:
    if not isinstance(value, str) or not value:
        raise Disarmed(f"{label} file is invalid")
    if not LOCAL_FILE_PATH.fullmatch(value):
        raise Disarmed(f"{label} file is invalid")
    path = pathlib.Path(value).expanduser()
    if not path.is_absolute() or ".." in pathlib.PurePath(value).parts:
        raise Disarmed(f"{label} file is invalid")
    return path


def _validate_peer_unit(value: object, suffix: str) -> str:
    unit = validate_unit(value, suffix)
    if unit.startswith("-"):
        raise Disarmed("peer unit must not be an option")
    return unit


def _validate_maintenance_lock(value: object, ssh_user: str) -> str:
    if not isinstance(value, str) or not value:
        raise Disarmed("peer maintenance lock is invalid")
    path = pathlib.PurePosixPath(value)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or any(not UNIT_TOKEN.fullmatch(part) for part in path.parts[1:])
        or path.parts[:3] != ("/", "home", ssh_user)
        or path.name != "SELF_HEAL_PAUSED"
    ):
        raise Disarmed("peer maintenance lock is invalid")
    return value
