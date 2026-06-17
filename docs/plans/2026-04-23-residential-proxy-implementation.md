# Residential Proxy for Codex Re-auth — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the Mac-dependency at the 10-day Codex re-auth mark by routing both servers' Chrome re-auth traffic through an always-on static residential proxy.

**Architecture:** One IPRoyal static residential IP is shared across both AWS servers. Each server runs a `gost` systemd user service that listens on `127.0.0.1:1080` and forwards to the IPRoyal endpoint with auth. The existing `codex_reauth_server.py` already probes `127.0.0.1:1080` and uses it automatically — no flow changes. A systemd `OnFailure=` hook posts to Slack (`aaa-ops` channel on Team Nebula AI workspace) if the tunnel dies. A daily cron runs a health check that verifies the returned IP matches the expected IPRoyal IP.

**Tech Stack:** Python 3 (existing reauth scripts), pytest (new, for the one code change), gost v3 (static Go binary), systemd user units, bash.

**Working branch:** `feat/residential-proxy` off `main` in `Screddyice/openclaw-codex-reauth`. Not a worktree since the repo is fresh and there's no conflicting work to isolate from.

---

## File Structure

New and modified files in the repo:

```
openclaw-codex-reauth/
├── codex_reauth_server.py              (modify: 1 line — log level change)
├── requirements.txt                    (modify: add pytest)
├── tests/                              (new directory)
│   └── test_reauth_proxy_warning.py    (new: TDD for the log change)
├── deploy/                             (new directory)
│   ├── README.md                       (new: operator-facing deploy guide)
│   ├── residential-proxy.service       (new: systemd unit template)
│   ├── residential-proxy-alert.service (new: OnFailure hook unit)
│   ├── slack-alert.sh                  (new: Slack poster for alerts)
│   ├── health-check.sh                 (new: daily IP verification)
│   └── install.sh                      (new: idempotent installer)
└── docs/plans/
    └── 2026-04-23-residential-proxy-implementation.md  (this file)
```

Each file has one responsibility:
- `residential-proxy.service` — run gost as an always-on forwarder
- `residential-proxy-alert.service` — one-shot that fires slack-alert.sh on failure
- `slack-alert.sh` — post to Slack Web API (chat.postMessage via bot token)
- `health-check.sh` — curl through the tunnel, compare returned IP to expected
- `install.sh` — download gost binary, write units, enable, start, install cron

---

## Prereq: IPRoyal signup (human action, not code)

Before any deploy task, Shawn must:

1. Sign up at https://iproyal.com — pick "Static Residential" plan, 1 IP, 1 month billing
2. From the dashboard, capture: `host`, `port`, `username`, `password` for SOCKS5 access
3. Confirm the assigned IP by viewing it in the dashboard (we'll pin this as the expected IP for health check)

Output of this step is four values + one expected IP. They get written into `~/.openclaw/residential-proxy.env` on each server during the deploy task. These values DO NOT go in the repo (`.gitignore` already covers `residential-proxy.env`).

---

## Task 1: TDD — Upgrade missing-proxy log to WARNING level

**Files:**
- Create: `tests/test_reauth_proxy_warning.py`
- Modify: `codex_reauth_server.py` (one line: `log.info` → `log.warning` inside `launch_chrome`)
- Modify: `requirements.txt` (add `pytest>=7.0`)

**Rationale:** The spec requires proxy outages to surface in `codex-reauth.log` without cross-referencing the gost service log. Currently the "no SOCKS proxy on :%d — using direct connection" line is logged at INFO level; we want WARNING so it shows up in normal log-review flow.

- [ ] **Step 1: Add pytest to requirements**

Edit `requirements.txt`:

```
playwright>=1.40.0
pytest>=7.0
```

- [ ] **Step 2: Create the failing test**

Create `tests/test_reauth_proxy_warning.py`:

```python
"""Verify that when the residential proxy is NOT reachable, codex_reauth_server
logs a WARNING (not INFO), so proxy outages surface in the reauth log."""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_missing_proxy_logs_warning(caplog):
    """When 127.0.0.1:1080 refuses the connection, we should log a WARNING
    with text indicating the proxy is expected but unreachable."""
    import codex_reauth_server as mod

    cfg = {
        "codex": {
            "chrome_path": "/bin/true",
            "chrome_profile_dir": "/tmp/test-chrome-profile",
            "cdp_port": 19333,
            "callback_host": "127.0.0.1",
            "callback_port": 11455,
            "callback_path": "/auth/callback",
            "use_xvfb": False,
            "xvfb_screen": "1280x900x24",
            "socks_proxy_port": 65530,  # unused port, connect will fail
            "socks_proxy_auto": True,
        },
    }
    log = logging.getLogger("test-codex-reauth")
    caplog.set_level(logging.DEBUG, logger="test-codex-reauth")

    # launch_chrome calls subprocess.Popen; patch it so we don't actually spawn
    with patch.object(mod.subprocess, "Popen") as popen, \
         patch.object(mod.subprocess, "run"), \
         patch.object(mod.time, "sleep"):
        popen.return_value.poll.return_value = None
        try:
            mod.launch_chrome(cfg, log)
        except Exception:
            pass  # we don't care if Chrome "launched" fake — only about the log

    msgs = [r for r in caplog.records if "no SOCKS proxy" in r.getMessage()
                                       or "residential proxy" in r.getMessage()
                                       or "proxy not reachable" in r.getMessage()]
    assert msgs, f"expected a proxy-related log record, got: {[r.getMessage() for r in caplog.records]}"
    assert any(r.levelno >= logging.WARNING for r in msgs), (
        f"expected WARNING-level log for missing proxy, "
        f"got levels: {[(r.levelname, r.getMessage()) for r in msgs]}"
    )
```

- [ ] **Step 3: Run the test to see it fail**

```bash
cd /Users/shawnreddy/projects/openclaw-codex-reauth
python3 -m venv .venv && source .venv/bin/activate
pip install -q -r requirements.txt
pip install -q playwright  # if not already
pytest tests/test_reauth_proxy_warning.py -v
```

Expected: **FAIL** — the existing code logs at INFO, so `levelno >= WARNING` assertion fails.

- [ ] **Step 4: Make the failing test pass**

Edit `codex_reauth_server.py`. Find this block inside `launch_chrome` (around line 200-215):

```python
    if cfg["codex"].get("socks_proxy_auto", True):
        import socket as _sock
        try:
            s = _sock.create_connection(("127.0.0.1", socks_port), timeout=2)
            s.close()
            chrome_args.append(f"--proxy-server=socks5://127.0.0.1:{socks_port}")
            log.info("SOCKS proxy detected on :%d — routing Chrome through residential IP", socks_port)
        except Exception:
            log.info("no SOCKS proxy on :%d — using direct connection", socks_port)
```

Change the final `log.info(...)` line to `log.warning(...)` with an explicit message:

```python
    if cfg["codex"].get("socks_proxy_auto", True):
        import socket as _sock
        try:
            s = _sock.create_connection(("127.0.0.1", socks_port), timeout=2)
            s.close()
            chrome_args.append(f"--proxy-server=socks5://127.0.0.1:{socks_port}")
            log.info("SOCKS proxy detected on :%d — routing Chrome through residential IP", socks_port)
        except Exception:
            log.warning(
                "expected residential proxy on :%d not reachable — "
                "re-auth will likely fail from datacenter IP. Check residential-proxy.service.",
                socks_port,
            )
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
pytest tests/test_reauth_proxy_warning.py -v
```

Expected: **PASS**.

- [ ] **Step 6: Commit**

```bash
git checkout -b feat/residential-proxy
git add tests/test_reauth_proxy_warning.py codex_reauth_server.py requirements.txt
git commit -m "$(cat <<'EOF'
feat: surface missing residential proxy as WARNING

When the residential SOCKS tunnel on 127.0.0.1:1080 isn't reachable, the
reauth flow now logs a WARNING instead of INFO. Datacenter-IP reauth
attempts almost always fail because OpenAI suppresses verification-email
delivery, so a missing tunnel is load-bearing information operators need
to see at a glance.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: TDD — Watchdog tracks consecutive escalation failures and alerts Slack

**Files:**
- Create: `tests/test_watchdog_escalation_alert.py`
- Modify: `codex_watchdog.py` (extend `_escalate()` with state tracking + alert)

**Rationale:** Covers the third monitoring layer from the spec: *"codex_reauth_server.py escalation fails 2x consecutive → watchdog posts Slack alert."* Without this, if both the systemd `OnFailure=` hook and the daily health-check miss a failure mode (e.g., the tunnel is up but OpenAI still rejects even the residential IP), re-auth can fail silently until Shawn notices Codex broke.

State is persisted to `~/.hermes-oauth/watchdog-escalation-state.json` so consecutive failures are tracked across cron runs. Reset to 0 on any success.

- [ ] **Step 1: Write the failing test**

Create `tests/test_watchdog_escalation_alert.py`:

```python
"""Verify the watchdog alerts Slack after 2 consecutive escalation failures
and resets the counter on success."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def watchdog(tmp_path, monkeypatch):
    import codex_watchdog as mod
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(mod, "ESCALATION_STATE_FILE", str(state_file))
    return mod, state_file


def test_single_failure_does_not_alert(watchdog, monkeypatch):
    mod, state_file = watchdog
    alerts = []
    monkeypatch.setattr(mod, "_alert_slack", lambda msg: alerts.append(msg))
    # Point SERVER_REAUTH_SCRIPT at something that always exits non-zero
    monkeypatch.setattr(mod, "SERVER_REAUTH_SCRIPT", "/bin/false")

    rc = mod._escalate()
    assert rc != 0
    assert alerts == []  # first failure does not alert
    state = json.loads(state_file.read_text())
    assert state["consecutive_failures"] == 1


def test_two_consecutive_failures_alert(watchdog, monkeypatch):
    mod, state_file = watchdog
    alerts = []
    monkeypatch.setattr(mod, "_alert_slack", lambda msg: alerts.append(msg))
    monkeypatch.setattr(mod, "SERVER_REAUTH_SCRIPT", "/bin/false")

    mod._escalate()  # failure 1
    mod._escalate()  # failure 2 → alert

    assert len(alerts) == 1
    assert "2" in alerts[0]
    state = json.loads(state_file.read_text())
    assert state["consecutive_failures"] == 2


def test_success_resets_counter(watchdog, monkeypatch):
    mod, state_file = watchdog
    alerts = []
    monkeypatch.setattr(mod, "_alert_slack", lambda msg: alerts.append(msg))

    # First, rack up a failure
    monkeypatch.setattr(mod, "SERVER_REAUTH_SCRIPT", "/bin/false")
    mod._escalate()
    assert json.loads(state_file.read_text())["consecutive_failures"] == 1

    # Then a success resets
    monkeypatch.setattr(mod, "SERVER_REAUTH_SCRIPT", "/bin/true")
    rc = mod._escalate()
    assert rc == 0
    assert json.loads(state_file.read_text())["consecutive_failures"] == 0
```

- [ ] **Step 2: Run the test to see it fail**

```bash
cd /Users/shawnreddy/projects/openclaw-codex-reauth
source .venv/bin/activate
pytest tests/test_watchdog_escalation_alert.py -v
```

Expected: **FAIL** — `ESCALATION_STATE_FILE` and `_alert_slack` don't exist yet in `codex_watchdog.py`.

- [ ] **Step 3: Implement state tracking + alerting in `codex_watchdog.py`**

Add these module-level constants near the top of `codex_watchdog.py`, right after the existing `OAUTH_CACHE` line:

```python
ESCALATION_STATE_FILE = os.path.expanduser("~/.hermes-oauth/watchdog-escalation-state.json")
ESCALATION_ALERT_THRESHOLD = 2
SLACK_ALERT_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deploy", "slack-alert.sh")
PROXY_ENV_FILE = os.path.expanduser("~/.openclaw/residential-proxy.env")
```

Add these two helpers above the existing `_escalate()` function:

```python
def _load_escalation_state() -> dict:
    try:
        with open(ESCALATION_STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"consecutive_failures": 0}


def _save_escalation_state(state: dict) -> None:
    os.makedirs(os.path.dirname(ESCALATION_STATE_FILE), exist_ok=True)
    with open(ESCALATION_STATE_FILE, "w") as f:
        json.dump(state, f)


def _alert_slack(message: str) -> None:
    """Post a Slack alert via the shared slack-alert.sh script. Non-fatal on
    failure — we never want the watchdog to crash because Slack is down."""
    if not os.path.exists(SLACK_ALERT_SCRIPT):
        log.error("slack-alert.sh not found at %s; cannot send alert", SLACK_ALERT_SCRIPT)
        return
    cmd = [
        "bash", "-c",
        f'set -a; [ -f "{PROXY_ENV_FILE}" ] && source "{PROXY_ENV_FILE}"; set +a; '
        f'bash "{SLACK_ALERT_SCRIPT}" codex-watchdog "$1"',
        "_",
        message,
    ]
    try:
        subprocess.run(cmd, check=False, timeout=15)
    except Exception as e:
        log.error("failed to invoke slack-alert.sh: %s", e)
```

Also add `import json` at the top if not already present (it should be, for the existing token cache logic).

Replace the existing `_escalate()` function with this version that tracks state:

```python
def _escalate() -> int:
    if not os.path.exists(SERVER_REAUTH_SCRIPT):
        log.error("escalation target not found: %s", SERVER_REAUTH_SCRIPT)
        return 3
    log.info("escalating to codex_reauth_server.py")
    result = subprocess.run(
        [sys.executable, SERVER_REAUTH_SCRIPT],
        capture_output=False,
    )
    log.info("codex_reauth_server.py exited %d", result.returncode)

    state = _load_escalation_state()
    if result.returncode == 0:
        if state.get("consecutive_failures", 0) > 0:
            log.info("escalation recovered after %d failure(s)", state["consecutive_failures"])
        state["consecutive_failures"] = 0
    else:
        state["consecutive_failures"] = state.get("consecutive_failures", 0) + 1
        log.warning(
            "escalation failed (exit %d); consecutive failures: %d",
            result.returncode, state["consecutive_failures"],
        )
        if state["consecutive_failures"] >= ESCALATION_ALERT_THRESHOLD:
            _alert_slack(
                f"codex reauth escalation has failed {state['consecutive_failures']} times in a row "
                f"(last exit code: {result.returncode}). Likely causes: residential proxy down, "
                f"IPRoyal IP rotated, or OpenAI rejecting even the residential IP. "
                f"Manual intervention: verify `systemctl --user status residential-proxy.service` "
                f"and/or fall back to Mac tunnel."
            )
    _save_escalation_state(state)
    return result.returncode
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
pytest tests/test_watchdog_escalation_alert.py -v
```

Expected: all three tests **PASS**.

- [ ] **Step 5: Verify the earlier Task 1 test still passes (regression check)**

```bash
pytest tests/ -v
```

Expected: both test files pass, nothing broken.

- [ ] **Step 6: Commit**

```bash
git add tests/test_watchdog_escalation_alert.py codex_watchdog.py
git commit -m "$(cat <<'EOF'
feat: watchdog alerts Slack after 2 consecutive escalation failures

Persists consecutive-failure count to
~/.hermes-oauth/watchdog-escalation-state.json. When the count reaches 2,
the watchdog invokes deploy/slack-alert.sh with context about likely
causes (proxy down, IP rotated, OpenAI rejection). Counter resets to 0 on
any successful escalation. Alert failures are non-fatal — the watchdog
never crashes because Slack is unreachable.

Covers the third monitoring layer from the residential-proxy design spec
(the other two: systemd OnFailure hook and daily cron health check).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Create systemd unit template for residential-proxy.service

**Files:**
- Create: `deploy/residential-proxy.service`

**Rationale:** This is the always-on gost forwarder. User unit so it runs as `ubuntu` without needing root privileges.

- [ ] **Step 1: Create the unit file**

Create `deploy/residential-proxy.service`:

```ini
[Unit]
Description=Residential SOCKS5 proxy forwarder (gost to upstream residential IP)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=%h/.openclaw/residential-proxy.env
ExecStart=/usr/local/bin/gost -L socks5://127.0.0.1:1080 -F "socks5://${IPROYAL_USER}:${IPROYAL_PASS}@${IPROYAL_HOST}:${IPROYAL_PORT}"
Restart=always
RestartSec=10
StandardOutput=append:%h/.hermes-oauth/residential-proxy.log
StandardError=append:%h/.hermes-oauth/residential-proxy.log
OnFailure=residential-proxy-alert.service

[Install]
WantedBy=default.target
```

- [ ] **Step 2: Sanity-check with systemd-analyze (optional, if systemd available locally)**

If working locally on Linux: `systemd-analyze verify deploy/residential-proxy.service`. Expected: no errors.

If on Mac (no systemd), skip — we'll validate on the server during deploy.

- [ ] **Step 3: Commit**

```bash
git add deploy/residential-proxy.service
git commit -m "feat: add systemd unit for residential proxy forwarder

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Create the Slack alert one-shot unit + script

**Files:**
- Create: `deploy/residential-proxy-alert.service`
- Create: `deploy/slack-alert.sh`

**Rationale:** When the forwarder crashes or fails to start, systemd's `OnFailure=` hook runs this one-shot unit, which invokes a bash script that posts to Slack via the `nebula_assist` bot token. Slack channel: `aaa-ops` (`C09FLJDCAJD`).

- [ ] **Step 1: Create the alert unit**

Create `deploy/residential-proxy-alert.service`:

```ini
[Unit]
Description=Slack alert for residential proxy failures

[Service]
Type=oneshot
EnvironmentFile=%h/.openclaw/residential-proxy.env
ExecStart=/bin/bash %h/codex-reauth/deploy/slack-alert.sh residential-proxy "forwarder service has failed or crashed — re-auth will fall back to direct connection which will fail at the 10-day mark. Run the Mac tunnel as manual fallback."
```

- [ ] **Step 2: Create the Slack alert script**

Create `deploy/slack-alert.sh`:

```bash
#!/usr/bin/env bash
# Post a Slack message via chat.postMessage using a bot token.
#
# Usage: slack-alert.sh <component> <message>
#
# Env vars required (loaded from EnvironmentFile in the calling systemd unit):
#   SLACK_BOT_TOKEN  — xoxb-... with chat:write scope
#   SLACK_CHANNEL_ID — e.g., C09FLJDCAJD (aaa-ops)
#
# Exits non-zero if the post fails, so systemd logs the failure.

set -euo pipefail

COMPONENT="${1:-unknown}"
MESSAGE="${2:-no message}"
HOSTNAME_TAG=$(hostname -s)
TS=$(date -Iseconds)

if [[ -z "${SLACK_BOT_TOKEN:-}" || -z "${SLACK_CHANNEL_ID:-}" ]]; then
  echo "slack-alert: SLACK_BOT_TOKEN or SLACK_CHANNEL_ID unset; cannot alert" >&2
  exit 2
fi

TEXT=":rotating_light: *[${HOSTNAME_TAG}] ${COMPONENT} alert* — ${TS}
${MESSAGE}"

PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({'channel': sys.argv[1], 'text': sys.argv[2]}))
" "$SLACK_CHANNEL_ID" "$TEXT")

RESP=$(curl -sS -X POST \
  -H "Authorization: Bearer ${SLACK_BOT_TOKEN}" \
  -H "Content-Type: application/json; charset=utf-8" \
  --data-binary "$PAYLOAD" \
  https://slack.com/api/chat.postMessage)

OK=$(printf '%s' "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('ok', False))")
if [[ "$OK" != "True" ]]; then
  echo "slack-alert: post failed: $RESP" >&2
  exit 3
fi
```

- [ ] **Step 3: Make the script executable**

```bash
chmod +x deploy/slack-alert.sh
```

- [ ] **Step 4: Smoke-test the script locally (dry-run via env)**

```bash
# Use the known-good nebula_assist token to verify the script posts correctly.
# Channel: aaa-ops (C09FLJDCAJD)
TOKEN=$(ssh neb-server 'jq -r .SLACK_BOT_TOKEN ~/.openclaw/openclaw.json 2>/dev/null || grep -h "xoxb-" ~/.openclaw/*.json 2>/dev/null | head -1 | sed -E "s/.*\"(xoxb-[^\"]+)\".*/\1/"')
SLACK_BOT_TOKEN="$TOKEN" \
SLACK_CHANNEL_ID="C09FLJDCAJD" \
bash deploy/slack-alert.sh test "ignore, this is a slack-alert.sh smoke test from the implementation plan"
```

Expected: zero exit code, a message appears in `#aaa-ops`.

**If it fails**, investigate (token expired? channel renamed?) before proceeding. The whole alerting design depends on this.

- [ ] **Step 5: Commit**

```bash
git add deploy/residential-proxy-alert.service deploy/slack-alert.sh
git commit -m "feat: add Slack alerting for residential proxy failures

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Create the daily health-check script

**Files:**
- Create: `deploy/health-check.sh`

**Rationale:** gost can be running but the upstream IPRoyal endpoint could be down, or IPRoyal could have silently rotated our IP. Once a day we curl an IP echo service through the tunnel and compare to the expected IP.

- [ ] **Step 1: Create the script**

Create `deploy/health-check.sh`:

```bash
#!/usr/bin/env bash
# Daily health check: curl through the residential SOCKS proxy and verify
# the returned public IP matches IPROYAL_EXPECTED_IP. Post to Slack on
# mismatch or curl failure.
#
# Run via cron, e.g. 0 9 * * * /home/ubuntu/codex-reauth/deploy/health-check.sh
#
# Env vars required (sourced from ~/.openclaw/residential-proxy.env):
#   IPROYAL_EXPECTED_IP — the IP we should see
#   SLACK_BOT_TOKEN, SLACK_CHANNEL_ID — for alerts

set -euo pipefail

ENV_FILE="${HOME}/.openclaw/residential-proxy.env"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERT="${SCRIPT_DIR}/slack-alert.sh"

EXPECTED="${IPROYAL_EXPECTED_IP:-}"
if [[ -z "$EXPECTED" ]]; then
  echo "health-check: IPROYAL_EXPECTED_IP not set in $ENV_FILE" >&2
  exit 2
fi

# 10s total timeout; SOCKS handshake + IP echo should be fast
OBSERVED=$(curl -sS --max-time 10 --socks5 127.0.0.1:1080 https://api.ipify.org || true)

if [[ -z "$OBSERVED" ]]; then
  bash "$ALERT" residential-proxy "health check failed: could not reach api.ipify.org through SOCKS tunnel. Tunnel may be down."
  exit 3
fi

if [[ "$OBSERVED" != "$EXPECTED" ]]; then
  bash "$ALERT" residential-proxy "health check IP mismatch: expected ${EXPECTED}, got ${OBSERVED}. IPRoyal may have rotated our IP."
  exit 4
fi

echo "$(date -Iseconds) health-check OK (${OBSERVED})"
```

- [ ] **Step 2: Make it executable**

```bash
chmod +x deploy/health-check.sh
```

- [ ] **Step 3: Commit**

```bash
git add deploy/health-check.sh
git commit -m "feat: add daily health check for residential proxy IP

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Create the idempotent install script

**Files:**
- Create: `deploy/install.sh`

**Rationale:** One command to stand up the whole thing on a server. Idempotent so re-running is safe (for upgrades or credential rotation).

- [ ] **Step 1: Create the script**

Create `deploy/install.sh`:

```bash
#!/usr/bin/env bash
# Idempotent installer for the residential proxy sidecar.
#
# Assumes:
#   - Running as the `ubuntu` user on the target server
#   - This repo is checked out at ~/codex-reauth
#   - ~/.openclaw/residential-proxy.env exists with:
#       IPROYAL_HOST, IPROYAL_PORT, IPROYAL_USER, IPROYAL_PASS,
#       IPROYAL_EXPECTED_IP, SLACK_BOT_TOKEN, SLACK_CHANNEL_ID
#
# Safe to re-run.

set -euo pipefail

GOST_VERSION="${GOST_VERSION:-3.0.0}"
GOST_URL="https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_linux_amd64.tar.gz"
GOST_BIN="/usr/local/bin/gost"

REPO_DIR="${REPO_DIR:-$HOME/codex-reauth}"
DEPLOY_DIR="$REPO_DIR/deploy"
ENV_FILE="$HOME/.openclaw/residential-proxy.env"
UNIT_DIR="$HOME/.config/systemd/user"

log() { echo "[install] $*"; }

# 1. Verify prereqs
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: $ENV_FILE does not exist. Create it with IPRoyal credentials first." >&2
  exit 1
fi
chmod 600 "$ENV_FILE"

# 2. Install gost if missing or wrong version
if ! command -v gost >/dev/null 2>&1 || ! gost -V 2>&1 | grep -q "$GOST_VERSION"; then
  log "installing gost v$GOST_VERSION"
  TMP=$(mktemp -d)
  trap "rm -rf $TMP" EXIT
  curl -sSL "$GOST_URL" | tar -xz -C "$TMP"
  sudo install -m 0755 "$TMP/gost" "$GOST_BIN"
  log "gost installed: $(gost -V 2>&1 | head -1)"
else
  log "gost already present: $(gost -V 2>&1 | head -1)"
fi

# 3. Ensure systemd user dir exists
mkdir -p "$UNIT_DIR"
mkdir -p "$HOME/.hermes-oauth"

# 4. Install systemd units
cp "$DEPLOY_DIR/residential-proxy.service" "$UNIT_DIR/residential-proxy.service"
cp "$DEPLOY_DIR/residential-proxy-alert.service" "$UNIT_DIR/residential-proxy-alert.service"

# 5. Enable lingering so user services run without a login session
sudo loginctl enable-linger "$USER" >/dev/null 2>&1 || true

# 6. Reload systemd, enable, start
systemctl --user daemon-reload
systemctl --user enable residential-proxy.service
systemctl --user restart residential-proxy.service

# 7. Wait up to 10s for the forwarder to come up
for i in 1 2 3 4 5 6 7 8 9 10; do
  if nc -z 127.0.0.1 1080 2>/dev/null; then
    log "tunnel listening on 127.0.0.1:1080"
    break
  fi
  sleep 1
done

# 8. Verify egress IP matches expected
# shellcheck disable=SC1090
source "$ENV_FILE"
OBSERVED=$(curl -sS --max-time 10 --socks5 127.0.0.1:1080 https://api.ipify.org || true)
if [[ -z "$OBSERVED" ]]; then
  echo "ERROR: could not reach api.ipify.org through the tunnel" >&2
  systemctl --user status residential-proxy.service --no-pager | tail -20
  exit 2
fi
if [[ "$OBSERVED" != "${IPROYAL_EXPECTED_IP:-}" ]]; then
  echo "ERROR: tunnel egress IP mismatch: expected ${IPROYAL_EXPECTED_IP}, got $OBSERVED" >&2
  exit 3
fi
log "tunnel egress verified: $OBSERVED"

# 9. Install daily health-check cron (idempotent)
CRON_LINE="0 9 * * * $DEPLOY_DIR/health-check.sh >> $HOME/.hermes-oauth/residential-proxy-healthcheck.log 2>&1"
( crontab -l 2>/dev/null | grep -vF "$DEPLOY_DIR/health-check.sh"; echo "$CRON_LINE" ) | crontab -
log "daily health-check cron installed"

log "install complete"
```

- [ ] **Step 2: Make it executable**

```bash
chmod +x deploy/install.sh
```

- [ ] **Step 3: Commit**

```bash
git add deploy/install.sh
git commit -m "feat: add idempotent installer for residential proxy sidecar

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Write the operator-facing deploy guide

**Files:**
- Create: `deploy/README.md`

**Rationale:** Shawn (or anyone else operating this) needs a clear runbook separate from the design spec.

- [ ] **Step 1: Create deploy/README.md**

Create `deploy/README.md`:

````markdown
# deploy/ — Residential Proxy Sidecar

Installs a static residential SOCKS5 forwarder alongside the codex-reauth
toolkit. Used to bypass OpenAI's datacenter-IP refusal during headless
re-auth from AWS servers.

## One-time: sign up for IPRoyal

1. Go to https://iproyal.com → Static Residential → 1 IP → 1 month
2. In the dashboard, note the assigned IP (the "expected IP")
3. Note the SOCKS5 credentials: `host`, `port`, `username`, `password`

## Per-server install

On each server (run as `ubuntu`):

```bash
# 1. Clone / pull the repo to ~/codex-reauth (if not already)
git clone https://github.com/Screddyice/openclaw-codex-reauth.git ~/codex-reauth
# OR if already present:
cd ~/codex-reauth && git pull

# 2. Create the env file (NOT committed)
cat > ~/.openclaw/residential-proxy.env <<'EOF'
IPROYAL_HOST=proxy.iproyal.com
IPROYAL_PORT=12321
IPROYAL_USER=YOUR_USERNAME
IPROYAL_PASS=YOUR_PASSWORD
IPROYAL_EXPECTED_IP=203.0.113.42
SLACK_BOT_TOKEN=xoxb-...
SLACK_CHANNEL_ID=C09FLJDCAJD
EOF
chmod 600 ~/.openclaw/residential-proxy.env

# 3. Run the installer
bash ~/codex-reauth/deploy/install.sh
```

Expected final log line: `[install] install complete`.

## Verify

```bash
# Service is running and listening
systemctl --user status residential-proxy.service --no-pager | head -15

# Tunnel egress is the expected residential IP
curl --socks5 127.0.0.1:1080 https://api.ipify.org && echo

# Cron installed
crontab -l | grep health-check
```

## Rotate credentials

If IPRoyal credentials or Slack token change:

```bash
vim ~/.openclaw/residential-proxy.env
systemctl --user restart residential-proxy.service
bash ~/codex-reauth/deploy/health-check.sh  # confirm still OK
```

## Uninstall

```bash
systemctl --user stop residential-proxy.service
systemctl --user disable residential-proxy.service
rm ~/.config/systemd/user/residential-proxy.service
rm ~/.config/systemd/user/residential-proxy-alert.service
systemctl --user daemon-reload
crontab -l | grep -v "residential-proxy\|health-check.sh" | crontab -
```

## Fallback when this breaks

If the residential proxy path is broken (IPRoyal outage, credential issue,
OpenAI rejecting even the residential IP), fall back to the original Mac
SOCKS tunnel flow:

1. On Shawn's Mac (home Wi-Fi): `bash ~/codex-reauth/mac_proxy_tunnel.sh`
2. On the affected server: `~/codex-reauth/venv/bin/python ~/codex-reauth/codex_reauth_server.py`

The server-side script auto-detects whichever SOCKS5 endpoint is reachable
on `127.0.0.1:1080` — it doesn't care whether it's gost (IPRoyal) or ssh
reverse-tunnel (Mac).
````

- [ ] **Step 2: Commit**

```bash
git add deploy/README.md
git commit -m "docs: add operator runbook for residential proxy deploy

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Push branch and open PR

**Files:** none (git + gh actions)

- [ ] **Step 1: Push the branch**

```bash
cd /Users/shawnreddy/projects/openclaw-codex-reauth
git push -u origin feat/residential-proxy
```

- [ ] **Step 2: Open a PR**

```bash
gh pr create --title "feat: residential proxy sidecar for unattended Codex re-auth" --body "$(cat <<'EOF'
## Summary

- Adds a systemd sidecar (`residential-proxy.service`) that runs gost as a SOCKS5 forwarder on `127.0.0.1:1080`, routing through an IPRoyal static residential IP
- Upgrades the "missing tunnel" log line from INFO → WARNING so proxy outages surface in the reauth log
- Slack alerting via `OnFailure=` hook on the service + daily health check cron
- Installer script + operator runbook in `deploy/`

Implements the design in `docs/specs/2026-04-23-residential-proxy-codex-reauth-design.md`.

## Test plan

- [x] Local pytest on the log-level change: `pytest tests/test_reauth_proxy_warning.py -v` → passes
- [x] `slack-alert.sh` smoke-tested against `#aaa-ops` with known-good token
- [ ] Install on `neb-server`; verify egress IP matches IPRoyal assigned IP; dry-run reauth confirms `SOCKS proxy detected on :1080`
- [ ] Install on `cliqk-server` (openclaw alias); same verification
- [ ] Wait for natural 10-day re-auth on either server and confirm it succeeds without Mac

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Confirm PR URL is returned; do not merge yet**

Deploy tasks (Tasks 8 and 9) run against the PR branch so we can verify the scripts work before merging to main. We merge after both servers are deployed and verified.

---

## Task 9: Deploy to NEB server (lower-risk first)

**Files:** none (remote execution)

**Preconditions:**
- IPRoyal account created, one static residential IP assigned
- Shawn knows the five values: `IPROYAL_HOST`, `IPROYAL_PORT`, `IPROYAL_USER`, `IPROYAL_PASS`, `IPROYAL_EXPECTED_IP`
- `nebula_assist` Slack bot token is known (already used successfully)

- [ ] **Step 1: SSH into NEB server and fetch the feature branch**

```bash
ssh neb-server '
  if [[ ! -d ~/codex-reauth/.git ]]; then
    # Repo not yet a git checkout — back up, clone, restore configs
    if [[ -d ~/codex-reauth ]]; then
      mv ~/codex-reauth ~/codex-reauth.bak-$(date +%Y%m%d-%H%M%S)
    fi
    git clone https://github.com/Screddyice/openclaw-codex-reauth.git ~/codex-reauth
    # Restore real configs from the backup if present
    LATEST_BAK=$(ls -td ~/codex-reauth.bak-* 2>/dev/null | head -1)
    if [[ -n "$LATEST_BAK" ]]; then
      for f in config.server.json config.mac.json venv; do
        [[ -e "$LATEST_BAK/$f" ]] && cp -r "$LATEST_BAK/$f" ~/codex-reauth/ || true
      done
    fi
  fi
  cd ~/codex-reauth && git fetch origin && git checkout feat/residential-proxy
  git status
'
```

Expected: `On branch feat/residential-proxy`, clean tree.

- [ ] **Step 2: Create the env file with real IPRoyal credentials**

Replace the placeholders with the actual values Shawn captured from IPRoyal.

```bash
ssh neb-server 'cat > ~/.openclaw/residential-proxy.env' <<'EOF'
IPROYAL_HOST=REPLACE_ME
IPROYAL_PORT=REPLACE_ME
IPROYAL_USER=REPLACE_ME
IPROYAL_PASS=REPLACE_ME
IPROYAL_EXPECTED_IP=REPLACE_ME
SLACK_BOT_TOKEN=REPLACE_WITH_NEBULA_ASSIST_TOKEN  # fetch with: ssh neb-server 'jq -r .SLACK_BOT_TOKEN ~/.openclaw/openclaw.json' (or wherever the existing token is stored)
SLACK_CHANNEL_ID=C09FLJDCAJD
EOF
ssh neb-server 'chmod 600 ~/.openclaw/residential-proxy.env'
```

- [ ] **Step 3: Run the installer**

```bash
ssh neb-server 'bash ~/codex-reauth/deploy/install.sh'
```

Expected final line: `[install] install complete`.

If it errors on the egress IP check, `systemctl --user status residential-proxy.service --no-pager | tail -20` will show gost's output — usually an auth error or unreachable upstream.

- [ ] **Step 4: Verify the tunnel**

```bash
ssh neb-server 'curl -sS --socks5 127.0.0.1:1080 https://api.ipify.org && echo' 
```

Expected: the IPRoyal residential IP.

- [ ] **Step 5: Dry-run the reauth flow to confirm the WARNING→INFO transition**

```bash
ssh neb-server '~/codex-reauth/venv/bin/python ~/codex-reauth/codex_reauth_server.py --dry-run 2>&1 | grep -E "SOCKS proxy|residential proxy"'
```

Expected: line starting with `SOCKS proxy detected on :1080 — routing Chrome through residential IP` (INFO level, meaning tunnel is up). If you see the WARNING line from Task 1, the tunnel is not reachable — re-check earlier steps.

- [ ] **Step 6: Smoke-test the alert path**

Force a failure to confirm Slack alerts fire end-to-end.

```bash
ssh neb-server 'systemctl --user stop residential-proxy.service; sleep 2; bash ~/codex-reauth/deploy/health-check.sh || true'
```

Expected: an alert message posts to `#aaa-ops` mentioning `neb-server` and "tunnel may be down". Then bring it back:

```bash
ssh neb-server 'systemctl --user start residential-proxy.service; sleep 3; bash ~/codex-reauth/deploy/health-check.sh'
```

Expected: `health-check OK (<ip>)`.

- [ ] **Step 7: Leave it running, watch logs for 1 hour**

```bash
ssh neb-server 'tail -F ~/.hermes-oauth/residential-proxy.log'
```

Expected: quiet (no restarts, no errors). Ctrl-C when satisfied.

---

## Task 10: Deploy to Cliqk server

**Files:** none (remote execution)

Identical to Task 8 but against the `openclaw` SSH alias. Same Slack token and channel — alerts for both servers post to `#aaa-ops` on the NEB workspace (this was an explicit simplification in the design; split later if needed).

- [ ] **Step 1: Fetch branch on Cliqk**

```bash
ssh cliqk-server '
  if [[ ! -d ~/codex-reauth/.git ]]; then
    if [[ -d ~/codex-reauth ]]; then
      mv ~/codex-reauth ~/codex-reauth.bak-$(date +%Y%m%d-%H%M%S)
    fi
    git clone https://github.com/Screddyice/openclaw-codex-reauth.git ~/codex-reauth
    LATEST_BAK=$(ls -td ~/codex-reauth.bak-* 2>/dev/null | head -1)
    if [[ -n "$LATEST_BAK" ]]; then
      for f in config.server.json config.mac.json venv; do
        [[ -e "$LATEST_BAK/$f" ]] && cp -r "$LATEST_BAK/$f" ~/codex-reauth/ || true
      done
    fi
  fi
  cd ~/codex-reauth && git fetch origin && git checkout feat/residential-proxy
  git status
'
```

- [ ] **Step 2: Create env file on Cliqk**

```bash
ssh cliqk-server 'cat > ~/.openclaw/residential-proxy.env' <<'EOF'
IPROYAL_HOST=REPLACE_ME
IPROYAL_PORT=REPLACE_ME
IPROYAL_USER=REPLACE_ME
IPROYAL_PASS=REPLACE_ME
IPROYAL_EXPECTED_IP=REPLACE_ME
SLACK_BOT_TOKEN=REPLACE_WITH_NEBULA_ASSIST_TOKEN  # fetch with: ssh neb-server 'jq -r .SLACK_BOT_TOKEN ~/.openclaw/openclaw.json' (or wherever the existing token is stored)
SLACK_CHANNEL_ID=C09FLJDCAJD
EOF
ssh cliqk-server 'chmod 600 ~/.openclaw/residential-proxy.env'
```

- [ ] **Step 3: Install + verify + smoke-test alert on Cliqk**

Repeat Task 9 steps 3–7 with `ssh cliqk-server ...` instead of `ssh neb-server ...`.

---

## Task 11: Merge PR and close out

**Files:** none

- [ ] **Step 1: Verify both servers show as healthy**

```bash
ssh neb-server 'bash ~/codex-reauth/deploy/health-check.sh'
ssh cliqk-server    'bash ~/codex-reauth/deploy/health-check.sh'
```

Both should log `health-check OK (<ip>)`.

- [ ] **Step 2: Merge the PR**

```bash
gh pr merge feat/residential-proxy --squash
```

- [ ] **Step 3: Final pull on both servers to align with main**

```bash
ssh neb-server 'cd ~/codex-reauth && git checkout main && git pull'
ssh cliqk-server    'cd ~/codex-reauth && git checkout main && git pull'
```

- [ ] **Step 4: Mark the plan complete in MEMORY**

Add a project memory entry:

```
project_residential-proxy-deployed.md:
---
name: Residential proxy for Codex re-auth deployed
description: IPRoyal static residential SOCKS5 forwarder deployed to both NEB and Cliqk servers via gost sidecar; eliminates Mac dependency at 10-day OAuth re-auth mark
type: project
---

Deployed 2026-04-23. Both servers route Chrome through a shared IPRoyal static residential IP during re-auth.

**Why:** OpenAI suppresses verification-email delivery from AWS datacenter IPs, breaking the headless re-auth flow every 10 days unless a residential IP is used.

**How to apply:** When Codex/openclaw re-auth breaks, first check #aaa-ops for residential-proxy alerts. If the tunnel is down, fall back to the Mac SOCKS tunnel (mac_proxy_tunnel.sh). Rotate IPRoyal creds by editing ~/.openclaw/residential-proxy.env and restarting residential-proxy.service.
```

- [ ] **Step 5: Live validation (deferred)**

Real end-to-end validation happens at the next natural 10-day re-auth on either server (no action required now — just watch `#aaa-ops` and the watchdog.log). If re-auth succeeds without Mac involvement, the project is complete.

---

## Rollback

If anything goes wrong during deploy:

```bash
# On the affected server:
systemctl --user stop residential-proxy.service
systemctl --user disable residential-proxy.service
# The existing codex-reauth flow still works via the Mac SOCKS tunnel,
# no gost dependency. Nothing else needs to be reverted.
```

The Mac fallback flow (`codex_reauth_mac.py` + `mac_proxy_tunnel.sh`) is untouched by this change and always available as tier-2 recovery.
