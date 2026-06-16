#!/usr/bin/env python3
"""Codex token watchdog — the scheduled entry point.

This is what cron runs. Reactive only: never refreshes proactively. Waits
for the access token to actually expire, then performs the cheap refresh
on the next tick. Worst-case downtime between expiry and detection is one
cron interval (15min by default).

Logic:
  1. Read the current openai-codex:codex-cli profile from auth-profiles.json.
  2. If it still has positive life left (hours_left > REFRESH_BUFFER_HOURS,
     where REFRESH_BUFFER_HOURS=0 means "wait for actual expiry"), do
     nothing. Exit 0.
  3. Otherwise call OpenAI's token endpoint with the current refresh_token.
     a. Success → write the new tokens, done. Exit 0.
     b. invalid_grant / refresh_token_reused → the chain is broken.
        Escalate: run codex_reauth_server.py. Exit with whatever it returns.
     c. 5xx / timeout → transient. Don't escalate. Exit 2 so cron logs it.

Install as a 15-minute cron job on each server:

  */15 * * * * /home/ubuntu/codex-reauth/venv/bin/python \\
               /home/ubuntu/codex-reauth/codex_watchdog.py \\
               >> /home/ubuntu/.openclaw-oauth/watchdog.log 2>&1
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time

from auth_profiles import (
    discover_paths,
    read_codex_cli_native,
    read_current,
    write_codex_cli_native,
    write_token_cache,
    write_tokens,
)
from codex_oauth import (
    CodexTokens,
    id_token_expires_ms_from_jwt,
    refresh_access_token,
)

REFRESH_BUFFER_HOURS = 0  # reactive: refresh only after the token has actually expired
DEFAULT_GLOBS = [
    "~/.openclaw/auth-profiles.json",
    "~/.openclaw/agents/*/agent/auth-profiles.json",
]
OAUTH_CACHE = "~/.openclaw/oauth-token-cache.json"
ESCALATION_STATE_FILE = os.path.expanduser("~/.openclaw-oauth/watchdog-escalation-state.json")
ESCALATION_ALERT_THRESHOLD = 2
SLACK_ALERT_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deploy", "slack-alert.sh")
PROXY_ENV_FILE = os.path.expanduser("~/.openclaw/residential-proxy.env")
SERVER_REAUTH_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "codex_reauth_server.py"
)
# Written when OAuth is confirmed broken (escalation failed past threshold) and
# the disconnect alert has fired. The Mac-side reactive trigger watches for this
# flag and runs the interactive Mac re-auth flow. Cleared when the server
# recovers (healthy refresh or successful escalation).
REAUTH_FLAG_FILE = os.path.expanduser("~/.openclaw-oauth/reauth-requested.flag")
LOG_DIR = os.path.expanduser("~/.openclaw-oauth")
os.makedirs(LOG_DIR, exist_ok=True)

log = logging.getLogger("codex-watchdog")
log.setLevel(logging.INFO)
log.handlers.clear()
fmt = logging.Formatter("%(asctime)s watchdog %(levelname)s %(message)s")
fh = logging.FileHandler(os.path.join(LOG_DIR, "watchdog.log"))
fh.setFormatter(fmt); log.addHandler(fh)
sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(fmt); log.addHandler(sh)


def _is_invalid_grant(err: Exception) -> bool:
    msg = str(err).lower()
    return (
        "invalid_grant" in msg
        or "refresh_token_reused" in msg
        or "refresh token" in msg
        or "400" in msg
    )


def main() -> int:
    paths = discover_paths(DEFAULT_GLOBS)
    current = read_current(paths)
    source = "openclaw"
    if not current:
        # Fall back to Codex CLI's native ~/.codex/auth.json — relevant on hosts
        # where the Codex CLI was authenticated directly (e.g., via Mac → server
        # token push) but openclaw's auth-profiles.json hasn't been seeded yet.
        current = read_codex_cli_native()
        source = "codex-cli"
    if not current:
        log.error("no existing openai-codex tokens found in openclaw or ~/.codex/auth.json — escalating")
        return _escalate()

    expires_ms = int(current.get("expires", 0))
    id_expires_ms = int(current.get("id_token_expires", 0))
    now_ms = int(time.time() * 1000)
    hours_left = (expires_ms - now_ms) / 3_600_000
    # id_token TTL only matters when one is actually present (id_expires_ms > 0).
    id_hours_left = (id_expires_ms - now_ms) / 3_600_000 if id_expires_ms > 0 else None
    if id_hours_left is not None:
        log.info(
            "read tokens from source=%s, access %.1fh / id_token %.1fh remaining",
            source, hours_left, id_hours_left,
        )
    else:
        log.info("read tokens from source=%s, access %.1fh remaining (no id_token)", source, hours_left)

    # Healthy only when the access token has life AND (no id_token OR the
    # id_token also has life). An access-fresh / id_token-expired pair must fall
    # through to the refresh path — refresh now requests a fresh id_token, so the
    # rot can finally self-heal instead of being declared "healthy" forever.
    access_healthy = hours_left > REFRESH_BUFFER_HOURS
    id_healthy = id_hours_left is None or id_hours_left > REFRESH_BUFFER_HOURS
    if access_healthy and id_healthy:
        log.info("token healthy — no action")
        _clear_reauth_flag()
        return 0
    if access_healthy and not id_healthy:
        log.info(
            "access token healthy but id_token expired (%.1fh past) — forcing refresh to mint a fresh id_token",
            -id_hours_left if id_hours_left is not None else 0,
        )

    refresh_tok = current.get("refresh")
    if not refresh_tok:
        log.error("profile has no refresh token — escalating")
        return _escalate()

    if not access_healthy:
        log.info("access token expired (%.1fh past expiry), attempting reactive refresh", -hours_left)
    else:
        log.info("refreshing to heal an expired id_token while access is still valid")
    try:
        tokens: CodexTokens = refresh_access_token(refresh_tok)
    except Exception as e:
        if _is_invalid_grant(e):
            log.error("refresh returned invalid_grant — escalating: %s", e)
            return _escalate()
        log.warning("refresh failed transiently: %s", e)
        return 2

    # Dual-write: keep both stores in lock-step so Codex CLI itself and openclaw
    # agents both see fresh tokens after a refresh. write_codex_cli_native is a
    # no-op if ~/.codex/auth.json doesn't exist on this host.
    openclaw_updated = write_tokens(paths, tokens)
    write_token_cache(OAUTH_CACHE, tokens)
    codex_cli_updated = write_codex_cli_native(tokens)
    new_hours = (tokens.expires_ms - now_ms) / 3_600_000
    log.info(
        "API refresh OK, new access token expires in %.1fh (openclaw=%d codex-cli=%s)",
        new_hours, openclaw_updated, "yes" if codex_cli_updated else "no",
    )

    # Post-refresh verification: confirm the refresh actually minted a usable
    # id_token. If OpenAI's refresh grant still declined to return one (or
    # returned an already-expired one — server-side scope refusal), do NOT return
    # 0 with a half-fresh store: escalate to a full interactive login that can
    # mint a real id_token. write_codex_cli_native has already dropped any dead
    # id_token and stamped needs_reauth, so the gap is never a stale-token gap.
    id_exp_ms = id_token_expires_ms_from_jwt(tokens.id_token or "")
    if not tokens.id_token or (id_exp_ms and id_exp_ms <= int(time.time() * 1000)):
        log.error(
            "refresh succeeded but id_token is still %s — escalating for full reauth",
            "absent" if not tokens.id_token else "expired",
        )
        return _escalate()

    new_id_hours = (id_exp_ms - now_ms) / 3_600_000 if id_exp_ms else 0
    log.info("refresh minted a fresh id_token (%.1fh remaining)", new_id_hours)
    _clear_reauth_flag()
    return 0


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


def _set_reauth_flag() -> None:
    """Signal the Mac-side reactive trigger that this server needs a fresh
    interactive re-auth. The Mac watches for this flag and runs the Mac re-auth
    flow only after it appears — never pre-emptively."""
    try:
        with open(REAUTH_FLAG_FILE, "w") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {os.uname().nodename}\n")
        log.info("wrote reauth-requested flag for Mac trigger: %s", REAUTH_FLAG_FILE)
    except Exception as e:
        log.error("failed to write reauth flag: %s", e)


def _clear_reauth_flag() -> None:
    """Remove the reauth-requested flag once the server is healthy again, so the
    Mac trigger stops acting on a stale request."""
    try:
        os.remove(REAUTH_FLAG_FILE)
        log.info("cleared reauth-requested flag (server recovered)")
    except FileNotFoundError:
        pass
    except Exception as e:
        log.error("failed to clear reauth flag: %s", e)


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
        _clear_reauth_flag()
    else:
        state["consecutive_failures"] = state.get("consecutive_failures", 0) + 1
        log.warning(
            "escalation failed (exit %d); consecutive failures: %d",
            result.returncode, state["consecutive_failures"],
        )
        if state["consecutive_failures"] >= ESCALATION_ALERT_THRESHOLD:
            _alert_slack(
                "Codex login on this server keeps failing. The automatic "
                f"refresh tried {state['consecutive_failures']} times in a row "
                "and couldn't recover.\n\n"
                "Your Mac watches for this and will re-auth automatically — just "
                "finish the OpenAI login when the browser opens on your Mac "
                "(within the hour). To trigger it immediately, on your Mac run:\n"
                "  cd ~/projects/Screddyice/openclaw-codex-reauth && python3 codex_reauth_mac.py\n\n"
                "Until then, any agent that uses Codex on this box will be stuck."
            )
            # Signal the Mac-side reactive trigger (only after the disconnect
            # alert has fired — never pre-emptively).
            _set_reauth_flag()
    _save_escalation_state(state)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
