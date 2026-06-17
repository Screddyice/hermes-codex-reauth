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
               >> /home/ubuntu/.hermes-oauth/watchdog.log 2>&1
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
    read_hermes_pool,
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
# Monitor-only deployment (set WATCHDOG_MONITOR_ONLY=1 in the cron env): the
# watchdog ONLY checks Hermes health and never reads or refreshes any codex
# token store. Use this on the Hermes box (neb-brain-hostinger), where a stray
# ~/.codex/auth.json shares the same OpenAI account as the live Hermes pool — a
# refresh there would rotate the shared token and break Hermes. Monitoring is
# all we want on that host.
MONITOR_ONLY = os.environ.get("WATCHDOG_MONITOR_ONLY", "") == "1"
# LEGACY openclaw store (openclaw retired) — fallback for un-migrated hosts only.
# The live Hermes credential source is ~/.hermes/auth.json (see read_hermes_pool).
DEFAULT_GLOBS = [
    "~/.openclaw/auth-profiles.json",
    "~/.openclaw/agents/*/agent/auth-profiles.json",
]
OAUTH_CACHE = "~/.openclaw/oauth-token-cache.json"
ESCALATION_STATE_FILE = os.path.expanduser("~/.hermes-oauth/watchdog-escalation-state.json")
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
REAUTH_FLAG_FILE = os.path.expanduser("~/.hermes-oauth/reauth-requested.flag")
LOG_DIR = os.path.expanduser("~/.hermes-oauth")
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
    now_ms = int(time.time() * 1000)
    if MONITOR_ONLY:
        # Hermes box: never touch a codex token store (rotating the shared
        # OpenAI refresh token would break the live Hermes pool). Just monitor.
        log.info("monitor-only mode — checking Hermes health, not touching any codex token store")
        _monitor_hermes(now_ms)
        return 0
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
        # No openclaw / codex-cli store on this host. It may be a Hermes-only box
        # (neb-brain-hostinger): Hermes owns its own credential store and its own
        # re-login, so here we only MONITOR it (read-only) — we never refresh or
        # escalate on Hermes' behalf, which would rotate the shared refresh token
        # out from under the live gateway.
        if read_hermes_pool() is not None:
            log.info("no openclaw/codex-cli store on this host — Hermes box, monitoring only")
            _monitor_hermes(now_ms)
            return 0
        log.error("no existing openai-codex tokens found in openclaw or ~/.codex/auth.json — escalating")
        return _escalate()

    expires_ms = int(current.get("expires", 0))
    id_expires_ms = int(current.get("id_token_expires", 0))
    hours_left = (expires_ms - now_ms) / 3_600_000

    # REACTIVE ONLY (Hermes-safe): act solely when the ACCESS token has actually
    # expired. A live access token means this box is up — codex CLI and Hermes
    # both authorize on the access token — so we do NOTHING even if the id_token
    # has expired. The id_token heals for free on the next genuine refresh (the
    # refresh now carries the openid scope). We deliberately do NOT rotate the
    # shared OpenAI refresh token just to freshen a latent id_token: that
    # rotation would invalidate Hermes' pooled copy of the same account
    # (refresh_token_reused). Latent id_token rot is harmless; needless rotation
    # is not.
    if hours_left > REFRESH_BUFFER_HOURS:
        if id_expires_ms and id_expires_ms <= now_ms:
            log.info(
                "source=%s, access %.1fh remaining; id_token expired but latent — "
                "no action (heals on next real refresh; not rotating the shared token)",
                source, hours_left,
            )
        else:
            log.info("source=%s, access %.1fh remaining — token healthy, no action", source, hours_left)
        _clear_reauth_flag()
        _monitor_hermes(now_ms)
        return 0

    refresh_tok = current.get("refresh")
    if not refresh_tok:
        log.error("profile has no refresh token — escalating")
        return _escalate()

    log.info("access token expired (%.1fh past expiry), attempting reactive refresh", -hours_left)
    try:
        tokens: CodexTokens = refresh_access_token(refresh_tok)
    except Exception as e:
        if _is_invalid_grant(e):
            log.error("refresh returned invalid_grant — escalating: %s", e)
            return _escalate()
        log.warning("refresh failed transiently: %s", e)
        return 2

    # Dual-write: keep both stores in lock-step so Codex CLI itself and any
    # legacy openclaw profiles both see fresh tokens after a refresh.
    # write_codex_cli_native is a no-op if ~/.codex/auth.json doesn't exist here.
    legacy_profiles_updated = write_tokens(paths, tokens)
    write_token_cache(OAUTH_CACHE, tokens)
    codex_cli_updated = write_codex_cli_native(tokens)
    new_hours = (tokens.expires_ms - now_ms) / 3_600_000
    log.info(
        "API refresh OK, new access token expires in %.1fh (legacy-profiles=%d codex-cli=%s)",
        new_hours, legacy_profiles_updated, "yes" if codex_cli_updated else "no",
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
    # An actual refresh happened — the ONLY routine event worth a notification.
    # Healthy no-op ticks stay silent.
    _notify_refresh(source, new_hours, new_id_hours)
    _clear_reauth_flag()
    _monitor_hermes(now_ms)
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


def _notify_refresh(source: str, access_hours: float, id_hours: float) -> None:
    """Notify ONLY when an actual refresh happened — the single routine event
    worth a ping. Healthy no-op ticks never notify (that was the noise we are
    cutting). Best-effort; never crashes the watchdog."""
    try:
        host = os.uname().nodename
    except Exception:
        host = "this host"
    msg = (
        f"Codex token refreshed on {host} (source={source}). "
        f"New access token valid ~{access_hours:.0f}h"
        + (f", id_token ~{id_hours:.0f}h." if id_hours else ".")
    )
    _alert_slack(msg)


def _monitor_hermes(now_ms: int) -> None:
    """READ-ONLY Hermes health check (neb-brain-hostinger).

    Never writes Hermes' store: Hermes (hermes-gateway) is the sole writer, and
    force-writing it both races the live gateway and rotates the shared OpenAI
    refresh token (the refresh_token_reused collision). We only alert — and ONLY
    when Hermes is ACTUALLY down: its access token is expired AND it has flagged
    relogin_required. Silent (info-log only) otherwise, on every other host the
    file is absent and this is a no-op."""
    try:
        h = read_hermes_pool()
    except Exception as e:  # never let a monitor read break the watchdog
        log.warning("hermes health read failed (non-fatal): %s", e)
        return
    if not h:
        return  # no Hermes credential store on this host
    acc_ms = int(h.get("expires", 0))
    acc_hours = (acc_ms - now_ms) / 3_600_000 if acc_ms else 0.0
    access_down = bool(acc_ms) and acc_ms <= now_ms
    if access_down and h.get("relogin_required"):
        log.error("Hermes codex auth is DOWN (access expired %.1fh ago + relogin_required)", -acc_hours)
        _alert_slack(
            "Hermes (Hostinger) codex auth is down: its access token has expired "
            "and the credential pool needs an interactive re-login. Re-auth Hermes "
            "on the box via its own flow to restore agent access."
        )
    else:
        log.info(
            "hermes health: access %.1fh remaining, relogin_required=%s — ok",
            acc_hours, bool(h.get("relogin_required")),
        )


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
