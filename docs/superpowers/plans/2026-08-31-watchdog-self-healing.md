# Watchdog Self-Healing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded local and peer repair for the Hermes Codex watchdog while preserving one-shot alerts, human 2FA, and passive healthy-state checks.

**Architecture:** A shared stdlib auth module gives the scheduled check, live probe, and healer one credential view. A new 15-minute healer repairs local timers, gateways, recoverable Codex credentials, reset quota windows, and committed peer units. A separate mode-600 state file edge-triggers repair-failure alerts and re-arms after recovery.

**Tech Stack:** Python 3 stdlib, pytest, bash 3.2-compatible installer code, systemd user services and timers, OpenSSH, Tailscale.

**Spec:** `docs/superpowers/specs/2026-08-31-watchdog-self-healing-design.md`

## Global Constraints

- Keep runtime Python stdlib-only.
- Keep `hermes_home` explicit in each non-observer host config.
- Preserve `down`, `quota`, `peer`, `sibling`, and `unknown` verdict semantics.
- Run no live Codex request during a healthy healer cycle.
- Let Hermes write OAuth tokens. The healer may back up `auth.json` but must not edit token fields.
- Do not call `hermes auth reset openai-codex`.
- Do not automate device-code login or 2FA.
- Use one Hermes warmup and one live probe per credential repair attempt.
- Require strict host-key checking and `100.64.0.0/10` addresses for peer SSH.
- Use fixed remote systemd commands, strict token validation, no `sudo`, and no user-provided shell fragments.
- Write healer state atomically with mode `0600`.
- Send one repair-failure notification per active fault and re-arm after recovery.
- Honor a maintenance lock and systemd masks.
- Keep PR #29 draft until three-host deployment and live canaries pass.
- Update the primary `README.md` in the implementation.

---

## File Map

- Create `watchdog/auth_state.py`: shared passive parsing and credential selection.
- Create `watchdog/self_heal.py`: local repair, credential recovery, peer repair, state, and CLI.
- Create `tests/test_auth_state.py`: shared auth-state behavior.
- Create `tests/test_self_heal.py`: healer unit and integration behavior.
- Modify `watchdog/codex_health_check.py`: import shared auth helpers without changing verdicts.
- Modify `watchdog/codex_auth_probe.py`: probe the selected pooled credential.
- Modify `watchdog/notify_failure.py`: render healer-specific escalation text.
- Modify `watchdog/hosts/src.json`: local healer config, no outbound peer repair.
- Modify `watchdog/hosts/tmn.json`: local healer config plus allowlisted `src` and observer repair.
- Modify `watchdog/hosts/hermes-tmn-observer.json`: local healer config plus allowlisted `src` and `neb-ops-gcp` repair.
- Create six files under `watchdog/systemd/`: three role-specific healer services and three timers.
- Modify `watchdog/install.sh`: ship healer files and units, preserve state, assert readiness.
- Modify `tests/test_codex_health_check.py`: keep extracted auth behavior protected.
- Modify `tests/test_codex_auth_probe.py`: verify pooled selection and request token.
- Modify `tests/test_notify_failure.py`: verify healer escalation and systemd wiring.
- Modify `README.md`: document repair boundaries, maintenance, state, deployment, and rollback.
- Modify `CLAUDE.md`: replace the detect-only rule with the bounded mutation contract.

---

### Task 1: Extract Shared Passive Auth State

**Files:**
- Create: `watchdog/auth_state.py`
- Create: `tests/test_auth_state.py`
- Modify: `watchdog/codex_health_check.py:220-315`
- Modify: `tests/test_codex_health_check.py`

**Interfaces:**
- Produces: `reset_at_of(entry: dict) -> float | None`
- Produces: `entry_quota_blocked(entry: dict, now: float, stale_s: int) -> tuple[bool, float | None]`
- Produces: `quota_blocked(auth: dict, now: float | None = None, stale_s: int = 21600) -> tuple[bool, str]`
- Produces: `renewable_pool_entries(auth: dict) -> list[dict]`
- Produces: `selected_codex_credential(auth: dict, now: float | None = None) -> dict | None`
- Produces: `full_pool_reset_at(auth: dict, now: float | None = None) -> float | None`

- [ ] **Step 1: Write failing shared-selection tests**

Create `tests/test_auth_state.py` with literal pool records. Do not import helpers from the existing health-check tests.

```python
from __future__ import annotations

import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
WATCHDOG = HERE.parent / "watchdog"


def load_auth_state():
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
```

- [ ] **Step 2: Run the new tests and verify RED**

Run: `pytest -q tests/test_auth_state.py`

Expected: FAIL because `watchdog/auth_state.py` does not exist.

- [ ] **Step 3: Create the shared module**

Move the current reset, quota, and renewable-entry logic from `codex_health_check.py` into `auth_state.py`. Add normalized selection without changing the health-check behavior.

```python
PROVIDER = "openai-codex"
QUOTA_STALE_S = 6 * 3600
TERMINAL_STATUSES = frozenset({"dead"})


def selected_codex_credential(auth: dict, now: float | None = None) -> dict | None:
    now = time.time() if now is None else now
    pool = (auth.get("credential_pool") or {}).get(PROVIDER) or []
    if pool:
        available = []
        for entry in renewable_pool_entries(auth):
            if str(entry.get("last_status") or "").lower() in TERMINAL_STATUSES:
                continue
            blocked, _ = entry_quota_blocked(entry, now, QUOTA_STALE_S)
            if not blocked:
                available.append(entry)
        if not available:
            return None
        return min(available, key=lambda entry: int(entry.get("priority", 0)))

    provider = (auth.get("providers") or {}).get(PROVIDER) or {}
    tokens = provider.get("tokens") or provider
    if not tokens.get("access_token") and not tokens.get("refresh_token"):
        return None
    return {
        "id": "singleton",
        "label": "singleton",
        "source": "device_code",
        "auth_type": "oauth",
        "access_token": tokens.get("access_token") or "",
        "refresh_token": tokens.get("refresh_token") or "",
        "last_status": provider.get("last_status"),
        "last_error_code": (provider.get("last_auth_error") or {}).get("code"),
    }


def full_pool_reset_at(auth: dict, now: float | None = None) -> float | None:
    now = time.time() if now is None else now
    pool = (auth.get("credential_pool") or {}).get(PROVIDER) or []
    if not pool:
        return None
    resets = []
    for entry in pool:
        blocked, reset = entry_quota_blocked(entry, now, QUOTA_STALE_S)
        if not blocked:
            return None
        if reset is None:
            return None
        resets.append(reset)
    return max(resets) if resets else None
```

Import these functions into `codex_health_check.py` and remove the duplicate definitions. Keep `PROVIDER` and `QUOTA_STALE_S` imported from the shared module.
Because the repository loads scripts with `importlib` instead of a package,
insert the watchdog directory into `sys.path` in the `_load` test helpers before
executing modules. Production script execution already places the script
directory on `sys.path`.

- [ ] **Step 4: Run focused and regression tests**

Run: `pytest -q tests/test_auth_state.py tests/test_codex_health_check.py`

Expected: PASS with the existing health verdict tests unchanged.

- [ ] **Step 5: Commit the extraction**

```bash
git add watchdog/auth_state.py watchdog/codex_health_check.py tests/test_auth_state.py tests/test_codex_health_check.py
git commit -m "refactor(watchdog): share passive Codex auth state"
```

---

### Task 2: Make the Live Probe Pool-Aware

**Files:**
- Modify: `watchdog/codex_auth_probe.py`
- Modify: `tests/test_codex_auth_probe.py`

**Interfaces:**
- Consumes: `selected_codex_credential(auth: dict, now: float | None = None) -> dict | None`
- Produces: `resolve_credential(auth_path: pathlib.Path) -> tuple[str, str]`, returning access token and label.
- Preserves exit codes: `0=OK`, `1=BROKEN`, `2=UNKNOWN`, `3=QUOTA`.

- [ ] **Step 1: Add a failing pooled-token request test**

Add a helper that writes a stale singleton plus a healthy manual pool entry. Capture the outgoing request.

```python
def test_probe_uses_selected_pool_entry_instead_of_stale_singleton(tmp_path, monkeypatch):
    singleton = jwt("acct-singleton")
    backup = jwt("acct-backup")
    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps({
        "providers": {"openai-codex": {"tokens": {
            "access_token": singleton, "refresh_token": "dead-rt"
        }}},
        "credential_pool": {"openai-codex": [
            {"id": "backup", "label": "backup", "auth_type": "oauth",
             "source": "manual:oauth", "access_token": backup,
             "refresh_token": "backup-rt", "last_status": "ok", "priority": 1}
        ]}
    }))
    seen = {}

    class Response:
        status = 200
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False

    def fake_open(req, timeout):
        seen["authorization"] = req.headers["Authorization"]
        seen["account"] = req.headers["Chatgpt-account-id"]
        return Response()

    monkeypatch.setattr(probe.urllib.request, "urlopen", fake_open)
    monkeypatch.setattr("sys.argv", ["probe", "--auth-json", str(auth)])
    assert probe.main() == 0
    assert seen == {"authorization": f"Bearer {backup}", "account": "acct-backup"}
```

Add a local `jwt(account_id: str) -> str` helper with a future `exp` claim.

```python
def jwt(account_id: str) -> str:
    claims = {
        "https://api.openai.com/auth": {"chatgpt_account_id": account_id},
        "exp": int(time.time()) + 3600,
    }
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"h.{payload}.s"
```

- [ ] **Step 2: Run the pooled test and verify RED**

Run: `pytest -q tests/test_codex_auth_probe.py::test_probe_uses_selected_pool_entry_instead_of_stale_singleton`

Expected: FAIL because the probe reads `providers.openai-codex.tokens`.

- [ ] **Step 3: Normalize credential selection in the probe**

Load `auth_state.py` from the sibling directory and resolve the selected entry.
Use the same plain sibling import as `codex_health_check.py`; update this test
file's `_load` helper to put `WATCHDOG` on `sys.path` first.

```python
def resolve_credential(auth_path: pathlib.Path) -> tuple[str, str]:
    auth = json.loads(auth_path.read_text())
    selected = selected_codex_credential(auth)
    if not selected or not selected.get("access_token"):
        raise ValueError("no probeable Codex credential")
    return str(selected["access_token"]), str(selected.get("label") or "unknown")
```

Print the label in `OK`, `BROKEN`, `UNKNOWN`, and `QUOTA` output. Never print tokens.

- [ ] **Step 4: Run the probe suite**

Run: `pytest -q tests/test_codex_auth_probe.py`

Expected: PASS for singleton and pool records.

- [ ] **Step 5: Commit the pool-aware probe**

```bash
git add watchdog/codex_auth_probe.py tests/test_codex_auth_probe.py
git commit -m "fix(watchdog): probe the active pooled credential"
```

---

### Task 3: Add Healer State and Safety Primitives

**Files:**
- Create: `watchdog/self_heal.py`
- Create: `tests/test_self_heal.py`

**Interfaces:**
- Produces: `load_state(path: pathlib.Path) -> dict`
- Produces: `save_state(path: pathlib.Path, state: dict) -> None`
- Produces: `fault_transition(state: dict, key: str, detail: str, now: int) -> bool`, where `True` means invoke first-failure escalation.
- Produces: `clear_fault(state: dict, key: str) -> None`
- Produces: `validate_unit(value: str, suffix: str) -> str`
- Produces: `validate_peer(peer: dict) -> dict`
- Produces: `CommandResult(returncode: int, stdout: str, stderr: str)`.

- [ ] **Step 1: Write failing state and validation tests**

Start `tests/test_self_heal.py` with these module and command helpers:

```python
from __future__ import annotations

import base64
import importlib.util
import json
import pathlib
import stat
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
WATCHDOG = HERE.parent / "watchdog"


def load_healer():
    spec = importlib.util.spec_from_file_location("self_heal", WATCHDOG / "self_heal.py")
    mod = importlib.util.module_from_spec(spec)
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
```

```python
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


@pytest.mark.parametrize("bad", ["x;reboot.service", "../x.service", "x.timer.service", ""])
def test_unit_validation_rejects_shell_and_path_tokens(bad):
    with pytest.raises(healer.Disarmed):
        healer.validate_unit(bad, ".service")


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
        "heartbeat_service": "hermes-codex-heartbeat-tmn.service"
    }
    assert healer.validate_peer(peer)["ip"] == "100.74.25.61"
```

- [ ] **Step 2: Run the state tests and verify RED**

Run: `pytest -q tests/test_self_heal.py`

Expected: FAIL because `watchdog/self_heal.py` does not exist.

- [ ] **Step 3: Implement atomic state and validation**

Use `tempfile.mkstemp`, `os.fsync`, `os.chmod`, and `os.replace`. Use `ipaddress.ip_address` and `ipaddress.ip_network("100.64.0.0/10")`. Accept unit tokens that match `^[A-Za-z0-9_.@-]+$` and the required suffix.

```python
@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


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
```

Reject identity files with group or world permission bits. Require a regular `known_hosts` file. Keep error strings free of file contents.

- [ ] **Step 4: Run the state suite**

Run: `pytest -q tests/test_self_heal.py`

Expected: PASS for state, permission, IP, user, path, and unit validation.

- [ ] **Step 5: Commit the safety core**

```bash
git add watchdog/self_heal.py tests/test_self_heal.py
git commit -m "feat(watchdog): add healer state and target validation"
```

---

### Task 4: Repair Local Timers and Gateways

**Files:**
- Modify: `watchdog/self_heal.py`
- Modify: `tests/test_self_heal.py`

**Interfaces:**
- Consumes: `CommandResult`, `fault_transition`, and shared auth functions.
- Produces: `run_command(argv: list[str], timeout: int = 20) -> CommandResult`
- Produces: `repair_health_timer(cfg: dict, run_cmd, dry_run: bool) -> tuple[bool, str]`
- Produces: `repair_gateway(cfg: dict, auth: dict, run_cmd, dry_run: bool) -> tuple[bool, str]`

- [ ] **Step 1: Write failing timer repair tests**

Use a deterministic fake command runner that records each argv list.

```python
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
    assert runner.calls[1] == ["systemctl", "--user", "enable", "--now",
                               "hermes-codex-health.timer"]
    assert "scheduled" in detail


def test_masked_timer_is_respected_without_mutation():
    runner = ScriptedRunner([result(1, "masked")])
    ok, detail = healer.repair_health_timer(local_cfg(), runner, dry_run=False)
    assert ok is True
    assert "masked" in detail
    assert len(runner.calls) == 1
```

- [ ] **Step 2: Run the timer tests and verify RED**

Run: `pytest -q tests/test_self_heal.py -k 'disabled_timer or masked_timer'`

Expected: FAIL because `repair_health_timer` does not exist.

- [ ] **Step 3: Implement one-attempt timer repair**

Inspect `is-enabled`, then repair. Verify `is-enabled`, `is-active`, and `NextElapseUSecRealtime` after mutation. If an enabled timer has no next elapse, restart it and start the configured check service once.

```python
def systemctl(run_cmd, *args: str) -> CommandResult:
    return run_cmd(["systemctl", "--user", *args], 20)
```

Dry-run must return the planned argv without calling the runner.

- [ ] **Step 4: Write failing gateway tests**

```python
def test_inactive_gateway_restarts_when_a_credential_can_recover():
    runner = ScriptedRunner([
        result(3, "inactive"), result(0), result(0, "active")
    ])
    auth = {"providers": {"openai-codex": {"tokens": {
        "access_token": "access", "refresh_token": "refresh"
    }}}}
    ok, detail = healer.repair_gateway(local_cfg(), auth, runner, dry_run=False)
    assert ok is True
    assert ["systemctl", "--user", "restart", "hermes-gateway.service"] in runner.calls
    assert "active" in detail


def test_terminal_credential_blocks_gateway_restart():
    runner = ScriptedRunner([result(3, "inactive")])
    auth = {"credential_pool": {"openai-codex": [{
        "id": "dead", "auth_type": "oauth", "access_token": "",
        "refresh_token": "", "last_status": "dead"
    }]}}
    ok, detail = healer.repair_gateway(local_cfg(), auth, runner, dry_run=False)
    assert ok is False
    assert "credential" in detail
    assert len(runner.calls) == 1
```

- [ ] **Step 5: Run the gateway tests and verify RED**

Run: `pytest -q tests/test_self_heal.py -k gateway`

Expected: FAIL because `repair_gateway` does not exist.

- [ ] **Step 6: Implement bounded gateway restart**

Permit restart when `selected_codex_credential` returns an entry or when `quota_blocked` reports a valid but exhausted pool. Poll `is-active` up to ten times with a one-second injected sleeper. Perform no credential mutation in this function.

- [ ] **Step 7: Run local repair tests**

Run: `pytest -q tests/test_self_heal.py -k 'timer or gateway or maintenance'`

Expected: PASS with exact command ordering.

- [ ] **Step 8: Commit local repair**

```bash
git add watchdog/self_heal.py tests/test_self_heal.py
git commit -m "feat(watchdog): repair local timers and gateways"
```

---

### Task 5: Add Credential and Reset-Aware Quota Recovery

**Files:**
- Modify: `watchdog/self_heal.py`
- Modify: `tests/test_self_heal.py`

**Interfaces:**
- Consumes: `selected_codex_credential`, `quota_blocked`, `full_pool_reset_at`.
- Produces: `backup_auth(auth_path: pathlib.Path, backup_dir: pathlib.Path, now: int) -> pathlib.Path`
- Produces: `credential_action(auth: dict, now: float) -> str`, returning `none`, `warmup`, `wait_quota`, or `human_2fa`.
- Produces: `run_hermes_warmup(cfg: dict, run_cmd) -> CommandResult`
- Produces: `run_live_probe(cfg_path: pathlib.Path, run_cmd) -> CommandResult`
- Produces: `repair_credential(cfg: dict, cfg_path: pathlib.Path, auth_path: pathlib.Path, state: dict, run_cmd, now: int, dry_run: bool) -> tuple[bool, str]`

- [ ] **Step 1: Write failing deterministic decision tests**

Add literal auth constructors to `tests/test_self_heal.py`:

```python
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
```

```python
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
```

- [ ] **Step 2: Run decision tests and verify RED**

Run: `pytest -q tests/test_self_heal.py -k credential_action`

Expected: FAIL because `credential_action` does not exist.

- [ ] **Step 3: Implement the pure decision function**

Use JWT `exp`, terminal status and error codes, renewable entries, and the full-pool reset. Treat `refresh_token_reused`, `invalid_grant`, `token_revoked`, `token_invalidated`, `invalid_token`, and `dead` as terminal for the selected entry. Allow a healthy manual entry to outrank a stale singleton.

- [ ] **Step 4: Write failing backup and one-shot tests**

```python
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
```

- [ ] **Step 5: Run backup and warmup tests and verify RED**

Run: `pytest -q tests/test_self_heal.py -k 'backup or warmup'`

Expected: FAIL because the functions do not exist.

- [ ] **Step 6: Implement backup, warmup, and probe commands**

Copy with `shutil.copyfile`, set mode `0600`, `fsync` the backup, and prune oldest names after sorting. Run Hermes with `start_new_session=True`; on timeout, kill the process group before returning failure. Run the probe with:

```python
[sys.executable, str(HERE / "codex_auth_probe.py"), "--config", str(cfg_path)]
```

Map probe exit codes without parsing human text.

- [ ] **Step 7: Write failing end-to-end credential repair tests**

Test these command sequences with temp auth files and a scripted runner:

1. expired token: backup, warmup, gateway restart, probe zero;
2. terminal token: no backup, no warmup, return human 2FA detail;
3. quota before reset: no command and no state write;
4. quota at reset: one warmup and one probe;
5. probe code three: store the new reset and stop without a second request;
6. probe code two: mark verification failure and preserve the backup.

- [ ] **Step 8: Implement credential orchestration**

Read `auth.json` again after warmup before restarting the gateway. Never restore the snapshot. Redact captured output with token patterns before logging. Set the quota attempt marker to the observed reset timestamp so the healer cannot retry the same window.

- [ ] **Step 9: Run credential tests**

Run: `pytest -q tests/test_self_heal.py -k 'credential or quota or warmup or backup or probe'`

Expected: PASS with one warmup and one probe for each eligible incident.

- [ ] **Step 10: Commit credential recovery**

```bash
git add watchdog/self_heal.py tests/test_self_heal.py
git commit -m "feat(watchdog): recover pooled Codex credentials once"
```

---

### Task 6: Add Allowlisted Peer Repair

**Files:**
- Modify: `watchdog/self_heal.py`
- Modify: `tests/test_self_heal.py`
- Modify: `watchdog/hosts/tmn.json`
- Modify: `watchdog/hosts/hermes-tmn-observer.json`

**Interfaces:**
- Consumes: `validate_peer(peer: dict) -> dict`.
- Produces: `ssh_base(peer: dict) -> list[str]`
- Produces: `ssh_systemctl(peer: dict, run_cmd, *args: str) -> CommandResult`
- Produces: `peer_heartbeat(peer: dict, previous_misses: int) -> tuple[str, str, int]`
- Produces: `repair_peer(peer: dict, run_cmd, fetch_heartbeat, dry_run: bool) -> tuple[bool, str]`

- [ ] **Step 1: Write failing SSH argv tests**

Add concrete peer helpers:

```python
def valid_peer(tmp_path, label="neb-ops-gcp"):
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
        "maintenance_lock": "/home/shawn_teamnebula_ai/.hermes/codex-health/SELF_HEAL_PAUSED",
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
        result(0, "enabled"), result(0, "active")
    ])
```

```python
def test_peer_repair_uses_pinned_host_and_fixed_systemd_commands(tmp_path):
    peer = valid_peer(tmp_path)
    runner = ScriptedRunner([
        result(1),
        result(1, "disabled"),
        result(0), result(0), result(0),
        result(0, "enabled"), result(0, "active")
    ])
    ok, detail = healer.repair_peer(
        peer, runner, fetch_heartbeat=lambda _: {"at": 2000}, dry_run=False
    )
    assert ok is True
    base = [
        "ssh", "-i", peer["identity_file"], "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes", "-o",
        f"UserKnownHostsFile={peer['known_hosts']}", "-o", "ConnectTimeout=10",
        f"{peer['ssh_user']}@{peer['ip']}"
    ]
    assert base + ["systemctl", "--user", "enable", "--now",
                   peer["health_timer"]] in runner.calls
    assert base + ["systemctl", "--user", "start",
                   peer["check_service"]] in runner.calls
```

- [ ] **Step 2: Run peer argv tests and verify RED**

Run: `pytest -q tests/test_self_heal.py -k peer_repair`

Expected: FAIL because peer repair functions do not exist.

- [ ] **Step 3: Implement fixed peer operations**

Use the validated fields to build OpenSSH argv. Test the remote maintenance lock with `test -e <path>`. Skip masked timers. Permit these remote commands:

```text
systemctl --user is-enabled <timer>
systemctl --user enable --now <timer>
systemctl --user restart <heartbeat-service>
systemctl --user start <check-service>
systemctl --user is-active <heartbeat-service>
```

No other remote executable or argument shape may pass the builder.

- [ ] **Step 4: Add failing heartbeat threshold and re-arm tests**

```python
def test_peer_repair_waits_for_two_misses_and_rearms_after_recovery(tmp_path):
    state = {"peer_misses": {}, "faults": {}}
    peer = valid_peer(tmp_path, label="src")
    first = healer.handle_peer(peer, state, unreachable, ScriptedRunner([]), now=1000)
    assert first.action == "wait"
    second = healer.handle_peer(peer, state, unreachable, repair_runner(), now=1100)
    assert second.action == "repair"
    recovered = healer.handle_peer(peer, state, fresh_heartbeat, ScriptedRunner([]), now=1200)
    assert recovered.action == "healthy"
    assert "peer.src" not in state["faults"]
```

- [ ] **Step 5: Implement peer threshold and edge state**

Use the same two-miss rule as the scheduled peer watch. Attempt one repair for the active outage, then honor `retry_s` without another notification. A fresh heartbeat clears misses, fault state, and attempt state.

- [ ] **Step 6: Add committed peer config**

Add `self_heal.peers` to `tmn.json` for `src` and the observer. Add entries to observer config for `src` and `neb-ops-gcp`. Use the approved Tailscale IPs:

```text
src: 100.79.251.126
neb-ops-gcp: 100.74.25.61
observer: 100.126.215.66
```

Reference identity and `known_hosts` paths without committing key material. Keep `src.json` peer repair empty because the one-way share does not grant `src` access to the TMN tailnet.

Use `~/.ssh/watchdog-repair` and `~/.ssh/watchdog-repair-known_hosts` on both TMN hosts. Use these fixed remote identities and units:

```json
{
  "src": {
    "ip": "100.79.251.126",
    "ssh_user": "hermes",
    "maintenance_lock": "/home/hermes/.hermes/codex-health/SELF_HEAL_PAUSED",
    "health_timer": "hermes-codex-health.timer",
    "check_service": "hermes-codex-health.service",
    "heartbeat_service": "hermes-codex-heartbeat.service"
  },
  "neb-ops-gcp": {
    "ip": "100.74.25.61",
    "ssh_user": "shawn_teamnebula_ai",
    "maintenance_lock": "/home/shawn_teamnebula_ai/.hermes/codex-health/SELF_HEAL_PAUSED",
    "health_timer": "hermes-codex-health-tmn.timer",
    "check_service": "hermes-codex-health-tmn.service",
    "heartbeat_service": "hermes-codex-heartbeat-tmn.service"
  },
  "observer": {
    "ip": "100.126.215.66",
    "ssh_user": "ubuntu",
    "maintenance_lock": "/home/ubuntu/.watchdog-observer/SELF_HEAL_PAUSED",
    "health_timer": "codex-observer.timer",
    "check_service": "codex-observer.service",
    "heartbeat_service": "codex-observer-heartbeat.service"
  }
}
```

- [ ] **Step 7: Run peer tests and config tests**

Run: `pytest -q tests/test_self_heal.py -k peer`

Run: `pytest -q tests/test_codex_health_check.py -k topology`

Expected: PASS with fixed IPs and no arbitrary command surface.

- [ ] **Step 8: Commit peer repair**

```bash
git add watchdog/self_heal.py tests/test_self_heal.py watchdog/hosts/tmn.json watchdog/hosts/hermes-tmn-observer.json
git commit -m "feat(watchdog): repair allowlisted peers over Tailscale"
```

---

### Task 7: Wire the Healer into Alerting and systemd

**Files:**
- Create: `watchdog/systemd/hermes-codex-self-heal.service`
- Create: `watchdog/systemd/hermes-codex-self-heal.timer`
- Create: `watchdog/systemd/hermes-codex-self-heal-tmn.service`
- Create: `watchdog/systemd/hermes-codex-self-heal-tmn.timer`
- Create: `watchdog/systemd/codex-observer-self-heal.service`
- Create: `watchdog/systemd/codex-observer-self-heal.timer`
- Modify: `watchdog/notify_failure.py`
- Modify: `watchdog/install.sh`
- Modify: `watchdog/hosts/src.json`
- Modify: `watchdog/hosts/tmn.json`
- Modify: `watchdog/hosts/hermes-tmn-observer.json`
- Modify: `tests/test_notify_failure.py`
- Modify: `tests/test_self_heal.py`

**Interfaces:**
- Produces CLI: `python3 self_heal.py --config PATH [--state-file PATH] [--dry-run]`.
- Produces healer exit contract: `0=healthy, repaired, paused, or continuing known fault`; `1=new failed repair or disarmed healer`.

- [ ] **Step 1: Write failing notifier and wiring tests**

```python
def test_healer_failure_message_names_repair_not_reporting(tmp_path):
    cfg = json.loads(write_cfg(tmp_path).read_text())
    text = nf.build_message(cfg, "hermes-codex-self-heal.service", "timer repair failed")
    assert "SELF-HEAL REPAIR FAILED" in text
    assert "FAILED TO REPORT" not in text


def test_every_codex_role_wires_a_healer_timer_and_notifier():
    pairs = {
        "hermes-codex-self-heal.service": "hermes-codex-health-notify.service",
        "hermes-codex-self-heal-tmn.service": "hermes-codex-health-tmn-notify.service",
        "codex-observer-self-heal.service": "codex-observer-notify.service",
    }
    for service, notifier in pairs.items():
        body = (WATCHDOG / "systemd" / service).read_text()
        assert "self_heal.py" in body
        assert f"OnFailure={notifier}" in body
        timer = (WATCHDOG / "systemd" / service.replace(".service", ".timer")).read_text()
        assert "OnUnitActiveSec=15m" in timer
        assert "Persistent=true" in timer
```

- [ ] **Step 2: Run notifier and wiring tests and verify RED**

Run: `pytest -q tests/test_notify_failure.py -k healer tests/test_self_heal.py -k cli`

Expected: FAIL because no healer units or notifier branch exist.

- [ ] **Step 3: Add the CLI orchestration**

The CLI must:

1. load and validate config;
2. resolve healer state beside the script unless overridden;
3. take a nonblocking `fcntl.flock`;
4. honor maintenance lock;
5. run local timer, gateway, credential, and peer handlers;
6. save state before returning;
7. return one only for a new failed repair or a disarmed healer.

Catch `Disarmed` in `main()` and redact errors before stderr.

- [ ] **Step 4: Add healer-aware notifier text**

Branch on `"self-heal" in unit` in `build_message`. Keep the same bounded journal tail and Telegram limit.

- [ ] **Step 5: Add role-specific systemd files**

Use this service shape with role paths and notifier names changed per host:

```ini
[Unit]
Description=Repair personal Hermes Codex watchdog faults
After=network-online.target tailscaled.service
Wants=network-online.target
OnFailure=hermes-codex-health-notify.service

[Service]
Type=oneshot
Environment="HERMES_HOME=%h/.hermes"
EnvironmentFile=-%h/.hermes/.env
ExecStart=/usr/bin/python3 %h/.hermes/codex-health/self_heal.py
TimeoutStartSec=180
```

Use this timer shape:

```ini
[Unit]
Description=Run personal Hermes watchdog self-healing every 15 minutes

[Timer]
OnBootSec=2m
OnUnitActiveSec=15m
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 6: Extend the installer**

Add role variables `HEAL_SERVICE` and `HEAL_TIMER` for the three Codex roles. Leave both empty for `nebos-claude`. Install `auth_state.py` for Codex hosts, `self_heal.py` for all three healer roles, and the probe for `src` and `tmn`.

Enable and start the healer timer. Assert enabled, active, next elapse, `OnFailure`, and a healer dry-run with a temporary state path. Do not remove `self-heal-state.json` or the backup directory.

- [ ] **Step 7: Add full shipped config**

Add exact `self_heal` objects from the spec. Add `maintenance_lock`, `retry_s=21600`, timer, service, model, and peer allowlists. Keep credentials and key contents out of JSON.

- [ ] **Step 8: Run wiring and installer tests**

Run: `pytest -q tests/test_notify_failure.py tests/test_self_heal.py`

Run: `bash -n watchdog/install.sh`

Expected: PASS, with no healer units for the NEBOS Claude role.

- [ ] **Step 9: Commit system integration**

```bash
git add watchdog/self_heal.py watchdog/notify_failure.py watchdog/install.sh watchdog/hosts watchdog/systemd tests/test_notify_failure.py tests/test_self_heal.py
git commit -m "feat(watchdog): schedule bounded self-healing"
```

---

### Task 8: Document, Verify, and Prepare Deployment

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `docs/superpowers/specs/2026-08-31-watchdog-self-healing-design.md` if implementation names changed.
- Modify: `docs/superpowers/plans/2026-08-31-watchdog-self-healing.md` to check completed steps during execution.

**Interfaces:**
- Consumes all prior task interfaces.
- Produces operator commands, maintenance procedure, rollback steps, and verification evidence.

- [ ] **Step 1: Update README behavior and operations**

Document:

- the 15-minute healer cadence;
- each repair action and its one-attempt boundary;
- `SELF_HEAL_PAUSED` maintenance lock creation and removal;
- mode-600 backup retention and the no-auto-restore rule;
- reset-aware quota behavior;
- one live probe per eligible repair;
- peer SSH allowlist and one-way Tailscale share;
- first-failure alert and recovery re-arm;
- dry-run, state paths, journal commands, rollback, and disposable-unit canary.

Replace prose that says the watchdog never repairs. Keep the device-code 2FA runbook explicit.

- [ ] **Step 2: Update repository rules**

In `CLAUDE.md`, replace `Detect only; never repairs` with the bounded rules from the spec. Keep the bans on scheduled healthy probes, direct token edits, broad SSH, automated 2FA, and `hermes auth reset`.

- [ ] **Step 3: Run focused tests**

Run:

```bash
pytest -q tests/test_auth_state.py tests/test_codex_auth_probe.py tests/test_self_heal.py tests/test_codex_health_check.py tests/test_notify_failure.py
```

Expected: all focused tests pass with no warnings.

- [ ] **Step 4: Run the complete repository gates**

Run:

```bash
pytest -q
scripts/verify.sh
bash -n watchdog/install.sh
git diff --check
```

Expected: each command exits zero.

- [ ] **Step 5: Run local-first fusion on the pure decision unit**

Extract `credential_action` and its table-driven cases to task files under the projectless `work/` directory. Run:

```bash
llmjury solve --task "$task_file" --cases "$cases_file" --entry-point credential_action --backend ollama --frontier auto --json
```

Accept the result only when exit code is zero and JSON contains `"verified": true`. Record any OpenRouter escalation and winning model in the PR body.

- [ ] **Step 6: Review the final diff against the spec**

Check each Goals, Exclusions, Repair Flows, Peer Repair, State, Failure Handling, Tests, Deployment, and Rollback requirement. Fix gaps before commit. Verify that no secret value, private key, auth snapshot, healer state, or generated `known_hosts` file is tracked.

- [ ] **Step 7: Commit documentation and final code adjustments**

```bash
git add README.md CLAUDE.md docs/superpowers/specs/2026-08-31-watchdog-self-healing-design.md docs/superpowers/plans/2026-08-31-watchdog-self-healing.md
git commit -m "docs(watchdog): document self-healing operations"
git push origin fix/watchdog-post-migration-topology
```

- [ ] **Step 8: Update draft PR #29**

Update the PR title and body with implementation scope, fresh test count, fusion result, deployment status, and remaining permission or connectivity blockers. Keep it draft.

- [ ] **Step 9: Deploy only after source verification**

Follow the spec deployment order. Create and pin SSH host keys before installing peer repair config. Deploy by `tar` plus `scp` or `gcloud compute scp`, then run `install.sh --host src`, `--host tmn`, and `--host observer` on the target users.

- [ ] **Step 10: Run non-disruptive live canaries**

Verify healer timers, dry-runs, state permissions, journal redaction, heartbeat listeners, and cross-host reachability. Use disposable user services and timers to prove local and peer systemd repair. Run at most one pool-aware Codex probe on each credential host. Do not stop a production gateway or alter a production credential for failure injection.

- [ ] **Step 11: Record live evidence and decide PR readiness**

Record unit enabled/active state, next elapses, disposable repair results, fresh heartbeat timestamps, quiet alert state, and probe exit codes. Keep the PR draft if any host, share, key pin, repair path, or alert path lacks evidence.

---

## Final Verification Checklist

- [ ] Shared auth selection matches scheduled check, probe, and healer.
- [ ] Healthy healer cycles make no Codex request.
- [ ] Credential repair creates one private backup, one warmup, and one probe.
- [ ] Terminal OAuth failures stop at the human 2FA runbook.
- [ ] Quota retry waits for the recorded reset and runs once per window.
- [ ] Local timer and gateway repairs verify postconditions.
- [ ] Peer repair accepts Tailscale IPs and fixed unit commands only.
- [ ] Maintenance locks and masks block mutation.
- [ ] First repair failure alerts once; recovery re-arms it.
- [ ] Dry-run leaves services, networks, credentials, and state unchanged.
- [ ] README and CLAUDE rules match shipped behavior.
- [ ] Full tests and syntax gates pass.
- [ ] Draft PR contains source, deployment, and live-state evidence as separate claims.
