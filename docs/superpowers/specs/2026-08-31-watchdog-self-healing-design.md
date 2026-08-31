# Watchdog Self-Healing Design

**Date:** 2026-08-31  
**Status:** Approved; implementation plan ready  
**Branch:** `fix/watchdog-post-migration-topology`  
**PR:** `Screddyice/hermes-codex-reauth#29`

**Plan:** `docs/superpowers/plans/2026-08-31-watchdog-self-healing.md`

## Problem

The watchdog detects credential, quota, gateway, timer, and peer failures. It
alerts an operator but does not repair any of them. A disabled timer caused a
six-day blind period in August. An inactive gateway can also leave a healthy
credential unused until a person restarts the service.

The retired self-healer ran a live Codex request every 30 minutes and attempted
headless device-code login. It generated 209 quota errors while finding three
credential failures. OpenAI now requires 2FA, so a headless login cannot finish
the recovery path.

The new design repairs faults from passive evidence. It spends a Codex request
after a repair action or after a recorded quota reset. It leaves device-code 2FA
to a person.

## Goals

- Restore a disabled or unscheduled health timer.
- Restart an inactive Hermes gateway when local auth state supports recovery.
- Let Hermes rotate to a usable pooled credential or refresh one OAuth grant.
- Retry an exhausted Codex pool after its recorded reset time.
- Verify credential repairs with one live probe.
- Repair fixed peer units over Tailscale SSH from approved hosts.
- Alert once when a repair fails, then re-arm after recovery.
- Preserve backups and an audit trail for credential mutations.

## Exclusions

- The healer will not automate device-code login or 2FA.
- The healer will not redeem ChatGPT usage-reset credits.
- The healer will not clear every credential status with `hermes auth reset`.
  That command also clears terminal `dead` state in the current Hermes pool.
- The healer will not restore an old OAuth backup after a failed refresh. A
  refresh may consume a single-use token before the command fails, so restoring
  the snapshot could reintroduce a revoked token.
- The healer will not run arbitrary remote shell text, use `sudo`, or repair a
  host outside the committed allowlist.
- The healer will not add a recursive guardian for its own timer.

## Approaches Considered

### 1. Extend the scheduled health check

The existing check could restart the gateway and repair credentials before it
alerts. This adds little code, but the check cannot re-enable its own disabled
timer. It also mixes detection, mutation, and delivery in one large process.

### 2. Let peers repair every fault

The observer could repair remote timers and gateways over SSH. This handles a
disabled local timer, but it gives cross-host access responsibility for local
credential work. Network loss would make the repair path unavailable at the
same time as the heartbeat.

### 3. Add a local healer with a peer backstop

This design uses one local healer on each host. The healer repairs its health
timer, gateway, credential pool, and quota state. The TMN hosts may repair fixed
timer and check units on allowlisted peers over Tailscale. Local work continues
during peer network loss, while remote repair covers a disabled health timer.

The implementation will use approach 3.

## Architecture

### Shared auth-state module

`watchdog/auth_state.py` will hold the stdlib-only auth parsing now embedded in
`codex_health_check.py`. It will expose these read operations:

- classify the provider singleton and pooled credentials;
- identify renewable, terminal, and quota-blocked pool entries;
- select the entry that a live probe should test;
- return the last quota reset time that keeps the full pool blocked.

`codex_health_check.py`, `codex_auth_probe.py`, and the new healer will use the
same classification. The scheduled check will keep its current verdicts and
alert behavior.

### Local healer

`watchdog/self_heal.py` will run from a systemd user timer every 15 minutes. It
will read one host config and maintain `self-heal-state.json` beside the script.
It will take a nonblocking file lock before any mutation.

The healer will process faults in this order:

1. maintenance lock;
2. health timer;
3. gateway;
4. credential or quota recovery;
5. peer repair.

The file named by `self_heal.maintenance_lock` blocks every mutation. The healer
will log the pause and exit zero. A systemd mask on a target unit also blocks
repair. The health check continues to observe and alert during a maintenance
lock.

### Systemd units

Each Codex role will gain one healer service and timer:

- `hermes-codex-self-heal.service` and `.timer` on `src`;
- `hermes-codex-self-heal-tmn.service` and `.timer` on `neb-ops-gcp`;
- `codex-observer-self-heal.service` and `.timer` on the observer.

Each service will use `Type=oneshot`, a 180-second timeout, and the role's
existing Telegram notifier through `OnFailure=`. Each timer will use
`OnBootSec=2m`, `OnActiveSec=2m`, `OnUnitActiveSec=15m`, and `Persistent=true`.

`watchdog/install.sh` will install, enable, start, and assert the healer units.
The installer will preserve both watchdog state files across deployment. Before
it enables a credential-host healer timer, it will validate the role's absolute
Hermes Python path, package version, auth and credential-pool module paths,
SHA-256 pins, and minimal AST contract. The observer has no credential mutation
path and omits those fields.

## Local Repair Flows

### Health timer

The healer will inspect the configured timer with fixed `systemctl --user`
arguments.

- `masked` or `masked-runtime`: log and skip.
- `disabled`: run `enable --now` once.
- enabled with no next elapse: restart the timer once, then start the health
  service once to publish a fresh heartbeat.
- enabled, active, and scheduled: record recovery and make no change.

The healer will verify enabled state, active state, and the next elapse after a
repair.

### Gateway

The healer will inspect the configured `gateway_unit` after auth classification.

- Healthy or quota-blocked credentials permit one gateway restart.
- Terminal credentials block a gateway restart because the process cannot
  restore service.
- An active gateway needs no action.

One cycle may restart the gateway once. When a due credential refresh will own
that restart, the earlier gateway step records a deferral and does not restart an
inactive gateway. The verified refresh performs the one restart before its live
probe.

The healer will poll `is-active` for up to 10 seconds after restart. A failed
restart becomes a repair fault and triggers the first-failure alert path.

### Credential pool and refresh

The healer will invoke a stdlib-only direct-refresh helper through the pinned
Hermes Python runtime. The helper will import no Hermes agent or plugin module.

Before the first credential mutation for an incident, it will copy `auth.json`
to `<healer-dir>/backups/<UTC timestamp>-auth.json`, set mode `0600`, and retain
the five newest snapshots. Logs will name the snapshot path without token data.

The healer will run one bounded direct refresh under the mutation lock when
passive state shows either condition:

- another renewable pool entry can replace the failed entry;
- an access token expired while its refresh token remains present.

The helper will validate the installed Hermes version, source hashes, OAuth
endpoint, function signatures, lock path, and pool persistence semantics before
the request. It will select one unique eligible lineage, hold Hermes'
`auth.lock` across one request and one mode-`0600` atomic write, fsync the file
and directory, and verify the persisted lineage. Manual pool entries stay
independent. A `device_code` entry updates the singleton only when both stores
held the same token pair before refresh.

Every normal credential-host cycle will execute the helper's full readiness
action before timer, gateway, credential, or peer mutation. Dry-run will remain
command-free. A package-version, hash, constant, or signature mismatch disarms
the cycle before a mutation boundary.

The healer will record the attempt in its durable state before the request. A
timeout, malformed response, or partial persistence blocks reuse of that refresh
token. The healer will restart the gateway after verified persistence, then run one pool-aware
live probe. Probe results control the outcome:

- `OK`: clear the repair fault and record recovery.
- `QUOTA`: enter the quota flow without another request.
- `BROKEN`: alert with the human device-code runbook.
- `UNKNOWN`: preserve the prior state and alert that verification failed.

After verified OAuth persistence, the healer will persist a non-secret
`gateway_restart` phase before restarting the gateway. A successful restart
advances the phase to `probe` before the request. A failed gateway restart or
probe remains one `local.credential` incident and waits for its cooldown. The
ordinary gateway handler will defer while either phase exists. At the cooldown
boundary, the healer resumes the recorded phase without another OAuth refresh.
Success clears the phase and credential fault.

The healer will not run a refresh when the selected entry has a terminal error
and no viable alternate pool entry exists. It will also stop when the pool has
no renewable entry or refresh token. A stale terminal singleton does not block a
healthy manual pool entry. The unrecoverable cases require a person to complete
2FA.

### Quota reset

The healer will make no Codex request before the latest recorded reset time for
a fully blocked pool. The first healer run at or after that time will run one
pinned direct refresh. Verified persistence gets one gateway restart and one
live probe.

The healer will not call `hermes auth reset`. Hermes pool selection already
releases entries after `last_error_reset_at`, while `auth reset` clears terminal
state that should stay quarantined.

A new 429 stores the next reset and ends the attempt. The healer will wait for
that reset before another request. It will not restart the gateway or run the
probe after a refresh-endpoint 429.

A 429 from the post-refresh live probe records a probe-specific reset. A healthy
auth file does not bypass that state. The healer makes no request before the
reset, records the attempt at the boundary, and runs one direct no-tool probe
without another OAuth refresh. A repeated 429 stores the next reset and makes no
second request in that cycle.

## Peer Repair

Peer repair uses committed host config. The healer will reject runtime values
that do not meet these rules:

- IP address belongs to `100.64.0.0/10`;
- SSH user and unit names match strict character allowlists;
- identity file exists and has no group or world permissions;
- the local process invokes SSH with an argument array;
- every remote user, path, and unit token passes a strict allowlist before SSH
  constructs the remote command;
- host-key checking uses a pinned `known_hosts` file.

Each peer entry may name a maintenance lock, health timer, check service, and
heartbeat service. The healer may run these fixed remote operations:

1. test the maintenance lock;
2. read timer and service state;
3. `systemctl --user enable --now <health timer>`;
4. `systemctl --user restart <heartbeat service>`;
5. `systemctl --user start <check service>`;
6. read state again.

The healer will skip a masked timer. It will make one remote repair attempt after
the existing two-miss heartbeat threshold. A fresh heartbeat re-arms the peer
repair state.

The one-device Tailscale share exposes `src` to the Team Nebula tailnet. It lets
`neb-ops-gcp` and the observer repair `src`. The design does not grant `src`
access to Team Nebula hosts. The observer and `neb-ops-gcp` can repair each other
inside the Team Nebula tailnet.

## State and Alerting

`self-heal-state.json` will contain one record per local or peer fault:

```json
{
  "faults": {
    "local.timer": {
      "active": true,
      "alerted": true,
      "last_attempt": 1788170000,
      "detail": "timer remained unscheduled"
    }
  }
}
```

The healer will write state with a same-directory temporary file, `fsync`, mode
`0600`, and atomic rename.

A failed repair exits nonzero after the healer saves `alerted=true`, so the
existing Telegram `OnFailure=` notifier sends one message. `notify_failure.py`
will detect healer unit names and describe the failed repair instead of claiming
that a health check failed to report. Runs during the same fault inspect passive
postconditions but block another local timer, gateway, or credential mutation
until the configured cooldown. The cycle at the exact boundary may retry once
and exits zero to prevent a repeated notification. Passive or repaired recovery
removes the active fault and re-arms a later incident.

`dry-run` will print planned commands, skip network calls, skip subprocess
mutations, and leave both state files unchanged.

## Configuration

Each role config will add a `self_heal` object. The concrete unit names and paths
will remain host-specific.

```json
{
  "self_heal": {
    "health_timer": "hermes-codex-health.timer",
    "check_service": "hermes-codex-health.service",
    "gateway_restart": true,
    "hermes_python": "/opt/hermes-agent/venv/bin/python",
    "hermes_version": "0.16.0",
    "hermes_auth_module": "/opt/hermes-agent/hermes_cli/auth.py",
    "hermes_auth_sha256": "<reviewed SHA-256>",
    "hermes_credential_pool_module": "/opt/hermes-agent/agent/credential_pool.py",
    "hermes_credential_pool_sha256": "<reviewed SHA-256>",
    "maintenance_lock": "~/.hermes/codex-health/SELF_HEAL_PAUSED",
    "retry_s": 21600,
    "peers": []
  }
}
```

Observer config will set `gateway_restart` to false and omit the Hermes runtime
and module pins.
Peer entries will include Tailscale IP, SSH user, identity path, pinned
`known_hosts`, and fixed unit names. No config will contain a private key or
token.

## Failure Handling

- Lock held: log and exit zero.
- Maintenance lock: log and exit zero.
- Missing or malformed config: fail before mutation and invoke `OnFailure=`.
- Backup failure: stop before credential mutation.
- Hermes timeout: kill the process group, preserve the backup, and mark failure.
- Probe `UNKNOWN`: stop mutation and preserve prior credential state.
- SSH timeout or host-key error: mark peer repair failure without a second SSH
  route.
- State corruption: fail closed and invoke `OnFailure=`.

The healer will redact token-shaped values from captured stdout and stderr before
writing journal output. It will cap journal excerpts to prevent alert overflow.

## Tests

Tests will use real temp files and narrow subprocess fakes at the system boundary.
They will cover:

- disabled timer repair and post-repair assertions;
- masked timer and maintenance-lock refusal;
- healthy credential plus inactive gateway restart;
- terminal credential blocking gateway and direct-refresh mutation;
- atomic mode-600 backup and five-file retention;
- one direct refresh followed by one pool-aware probe;
- one gateway restart across a due credential-repair cycle;
- full helper readiness before every normal credential-host mutation;
- quota silence before reset and one attempt after reset;
- probe-origin 429 silence before reset and one direct probe at the boundary;
- local mutation cooldown before and at the exact retry boundary;
- no use of `hermes auth reset`;
- strict peer target validation and argv construction;
- peer repair re-arm after heartbeat recovery;
- first failed repair alert and continuing-fault silence;
- healer-specific `OnFailure=` message text;
- dry-run state and mutation isolation;
- installer wiring for each Codex role.

The full repository gates remain `pytest -q`, `scripts/verify.sh`,
`bash -n watchdog/install.sh`, and `git diff --check`. The implementation will
also send the deterministic repair-decision unit through local-first LLM-Jury.

## Deployment and Live Verification

PR #29 will remain draft until the three-role topology and healer run on their
target hosts.

Deployment will follow the repository copy-and-install workflow:

1. share `src` into the Team Nebula tailnet and pin SSH host keys;
2. deploy `src`, `tmn`, and `observer` roles;
3. verify configured executables, health, heartbeat, and healer timers;
4. run healer dry-runs on each host;
5. test local and peer repair against disposable user units;
6. verify a fresh heartbeat and quiet alert state.

Live verification will not stop a production gateway or corrupt a production
credential. A disposable user service and timer will prove systemd and SSH
repair. The pool-aware probe will make at most one Codex request per host during
the deployment canary.

## Rollback

`install.sh` will retain pre-deploy files in the existing backup directory. A
rollback will disable the healer timer, restore the prior scripts and units,
run `daemon-reload`, and restart the original health and heartbeat units. The
watchdog state file and Hermes auth store will remain in place.
