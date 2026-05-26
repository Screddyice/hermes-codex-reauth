#!/usr/bin/env python3
"""Mac-side REACTIVE Codex re-auth trigger.

Replaces the old pre-emptive 6h health-poll (mac-codex-watchdog.py). This script
does NOT check token health and does NOT refresh anything pre-emptively. It only
reacts: it checks each server for a `reauth-requested.flag` that the server-side
watchdog writes when Codex OAuth has actually broken (invalid_grant, escalation
failed past threshold, disconnect Slack alert already fired). Only then does it
run the interactive Mac re-auth flow (codex_reauth_mac.py), which opens a browser
for you to finish the OpenAI login once, then pushes fresh tokens to all servers.

Design contract (per Shawn): fire ONLY after a server has confirmed broken and
the disconnect notification has fired. Never pre-emptive.

Runs via a LaunchAgent (Aqua session, so it can open a browser) every hour.
Throttled to one attempt per THROTTLE_HOURS so an unattended outage doesn't pop
a browser tab every hour.

Exit codes: 0 nothing-to-do or re-auth succeeded; non-zero if a re-auth attempt
was made and failed (flags left in place for the next tick to retry).
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

SERVERS = ["neb-server", "cliqk-server", "trc-server"]
REMOTE_FLAG = "~/.openclaw-oauth/reauth-requested.flag"
REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REAUTH_SCRIPT = os.path.join(REPO_DIR, "codex_reauth_mac.py")
LOG_FILE = os.path.expanduser("~/.openclaw-oauth/mac-reauth-trigger.log")
LAST_ATTEMPT_FILE = os.path.expanduser("~/.openclaw-oauth/mac-reauth-last-attempt")
THROTTLE_HOURS = 3
SSH_OPTS = ["-o", "ConnectTimeout=15", "-o", "BatchMode=yes"]


def log(msg: str) -> None:
    p = Path(LOG_FILE)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} mac-reauth-trigger {msg}\n")


def servers_requesting() -> list[str]:
    """Return the list of servers whose reauth-requested flag is set."""
    hits = []
    for alias in SERVERS:
        try:
            r = subprocess.run(
                ["ssh", *SSH_OPTS, alias, f"test -f {REMOTE_FLAG}"],
                capture_output=True, text=True, timeout=40,
            )
            if r.returncode == 0:
                hits.append(alias)
        except Exception as e:
            log(f"flag check for {alias} errored (treating as no-flag): {e}")
    return hits


def recently_attempted() -> bool:
    try:
        last = float(Path(LAST_ATTEMPT_FILE).read_text().strip())
    except Exception:
        return False
    return (time.time() - last) < THROTTLE_HOURS * 3600


def record_attempt() -> None:
    Path(LAST_ATTEMPT_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(LAST_ATTEMPT_FILE).write_text(str(time.time()))


def clear_flags(servers: list[str]) -> None:
    for alias in servers:
        try:
            subprocess.run(
                ["ssh", *SSH_OPTS, alias, f"rm -f {REMOTE_FLAG}"],
                capture_output=True, text=True, timeout=40,
            )
            log(f"cleared reauth flag on {alias}")
        except Exception as e:
            log(f"failed to clear flag on {alias}: {e}")


def main() -> int:
    hits = servers_requesting()
    if not hits:
        # Quiet success — nothing broken. Don't log every tick (avoid noise).
        return 0

    if recently_attempted():
        log(f"reauth requested by {hits} but throttled (attempted <{THROTTLE_HOURS}h ago); skipping")
        return 0

    if not os.path.exists(REAUTH_SCRIPT):
        log(f"ERROR: re-auth script missing at {REAUTH_SCRIPT}")
        return 3

    log(f"reauth requested by {hits} — launching interactive Mac re-auth flow")
    record_attempt()
    try:
        result = subprocess.run([sys.executable, REAUTH_SCRIPT], timeout=600)
        rc = result.returncode
    except subprocess.TimeoutExpired:
        log("re-auth flow timed out (no browser login completed in time); will retry next eligible tick")
        return 13
    except Exception as e:
        log(f"re-auth flow errored: {e}")
        return 14

    if rc == 0:
        # Clear flags on ALL servers — one re-auth pushes fresh tokens fleet-wide.
        clear_flags(SERVERS)
        log("re-auth succeeded; fresh tokens pushed; cleared flags on all servers")
    else:
        log(f"re-auth flow exited {rc}; leaving flags for retry")
    return rc


if __name__ == "__main__":
    sys.exit(main())
