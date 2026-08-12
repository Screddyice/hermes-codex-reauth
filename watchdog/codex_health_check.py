#!/usr/bin/env python3
"""Watch the Codex credential a Hermes gateway runs on. Detect and alert only.

SILENT WHEN HEALTHY. Alerts only on the transition into failure, because a check
that pings you while everything is fine is noise you learn to ignore.

This is the canonical version, shared by every host. Everything host-specific --
which auth store to read, which gateway unit, which channels to alert, and the
runbook prose -- lives in ``config.json`` next to this file. See ``hosts/``.

NOTHING HERE MUTATES ANYTHING. It never refreshes a token, never launches a
browser, never writes auth.json. OpenAI now mandates 2FA on sign-in, so the old
headless device-code self-heal cannot work by construction: recovery is a human
at a browser, and the only useful thing software can do is notice quickly and
say so clearly.

Detection deliberately does NOT trust ``hermes auth status``: on 2026-07-29 that
reported ``logged in`` for a credential with zero pooled entries and no refresh
token at all. It reads auth.json directly and trusts Hermes' own
``last_auth_error`` record, which is written when a real refresh fails.

Alerting:
  ok   -> down : one alert on every configured channel
  down -> down : quiet for renotify_s, then a single reminder (no new ticket)
  down -> ok   : silent re-arm, no "recovered" message
  unknown      : never pages, never changes state (parse/network trouble)

EXIT CODES -- a watchdog that fails silently is worse than no watchdog, so every
way this can stop working is loud:
  0  ran correctly (healthy, quiet, or alert fully delivered)
  1  DISARMED or delivery failed -- something needs a human. Paired with
     OnFailure= in the systemd unit.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

HOME = pathlib.Path.home()
HERE = pathlib.Path(__file__).resolve().parent
PROVIDER = "openai-codex"
COMPOSIO_EXEC = "https://backend.composio.dev/api/v3/tools/execute/GMAIL_SEND_EMAIL"
LINEAR_URL = "https://api.linear.app/graphql"
SLACK_URL = "https://slack.com/api/chat.postMessage"


class Disarmed(Exception):
    """The watchdog cannot do its job. Always loud, never swallowed.

    Every ``except`` that used to return a benign value and exit 0 raises this
    instead. A monitoring system reporting success while blind is the single
    worst outcome available to it.
    """


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------

def load_config(path: pathlib.Path) -> dict:
    """Load per-host config. Any problem is fatal and loud.

    ``hermes_home`` intentionally has NO default. The two hosts this replaced
    disagreed on it (``~/.hermes`` vs ``~/.hermes/profiles/tmn``), and a shared
    default would silently point the TMN box at its stale root auth.json and
    report a confident, wrong "ok" -- exactly the defect fixed on 2026-07-29.
    A missing value must stop the run, not pick a plausible path.
    """
    try:
        cfg = json.loads(path.read_text())
    except Exception as e:
        raise Disarmed(f"cannot read config {path}: {type(e).__name__}: {e}")

    if not cfg.get("hermes_home"):
        raise Disarmed(
            f"config {path} has no 'hermes_home'. Refusing to guess: the wrong "
            f"auth store yields a confident false 'ok'."
        )
    for key in ("host_label", "gateway_unit"):
        if not cfg.get(key):
            raise Disarmed(f"config {path} is missing required key {key!r}")
    if not (cfg.get("channels") or {}):
        raise Disarmed(f"config {path} declares no alert channels; nothing could page")

    return cfg


def env_val(name: str, hermes_home: pathlib.Path) -> str:
    """Resolve a secret from the process env, falling back to .env files.

    The fallback is load-bearing on the TMN box: its gateway unit loads only the
    profile .env, which does not carry SLACK_BOT_TOKEN -- that lives in the root
    ~/.hermes/.env.
    """
    v = (os.environ.get(name) or "").strip()
    if v:
        return v
    for envf in (hermes_home / ".env", HOME / ".hermes" / ".env", HOME / ".env"):
        try:
            for line in envf.read_text().splitlines():
                line = line.strip()
                if line.startswith(name + "="):
                    val = line[len(name) + 1:].strip()
                    if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                        val = val[1:-1]
                    if val.strip():
                        return val.strip()
        except Exception:
            pass
    return ""


# --------------------------------------------------------------------------
# detection
# --------------------------------------------------------------------------

def gateway_uses_codex(config_yaml: pathlib.Path) -> bool:
    """True when the gateway is actually configured on codex.

    Distinguishes "config unreadable" (Disarmed -- we cannot tell, so be loud)
    from "readable, but the gateway legitimately moved off codex" (False --
    genuinely not applicable, stay quiet). The version this replaces collapsed
    both into False, so a YAML typo silently disarmed the watchdog.
    """
    import re
    try:
        text = config_yaml.read_text()
    except Exception as e:
        raise Disarmed(f"cannot read {config_yaml}: {type(e).__name__}: {e}")
    m = re.search(r"^model:\s*$", text, re.M)
    if not m:
        return False
    block = text[m.end():]
    stop = re.search(r"^[^\s-]", block, re.M)
    block = block[: stop.start()] if stop else block
    p = re.search(r"^\s+provider:\s*(\S+)", block, re.M)
    return (p.group(1).strip().strip("'\"").lower() if p else "") == PROVIDER


def _exp_of(access_token: str):
    if not access_token or access_token.count(".") != 2:
        return None
    p = access_token.split(".")[1]
    p += "=" * (-len(p) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(p)).get("exp")
    except Exception:
        return None


def lineage(refresh_token: str) -> str:
    """Short fingerprint of the refresh token.

    Two hosts holding the same credential is what took both boxes down in July:
    the refresh token is single-use and rotates, so a shared lineage means each
    refresh invalidates the other host. Printing it in every alert makes that
    visible by inspection instead of requiring an incident to discover.
    """
    if not refresh_token:
        return "none"
    return hashlib.sha256(refresh_token.encode()).hexdigest()[:8]


def gateway_active(unit: str) -> tuple[bool, str]:
    """Is the gateway actually running? Codex auth can be perfect while the bot is dead."""
    try:
        r = subprocess.run(
            ["systemctl", "--user", "is-active", unit],
            capture_output=True, text=True, timeout=20,
        )
        return r.stdout.strip() == "active", r.stdout.strip() or "unknown"
    except Exception as e:
        return True, f"uncheckable ({type(e).__name__})"


def detect(auth_path: pathlib.Path, gateway_unit: str) -> tuple[str, str]:
    try:
        d = json.loads(auth_path.read_text())
    except Exception as e:
        raise Disarmed(f"cannot read {auth_path}: {type(e).__name__}: {e}")

    prov = (d.get("providers") or {}).get(PROVIDER) or {}
    pool = (d.get("credential_pool") or {}).get(PROVIDER) or []
    if not prov and not pool:
        return "down", "no Codex credential at all (providers block empty, pool empty)"

    toks = prov.get("tokens") or {}
    refresh = toks.get("refresh_token") or ""
    access = toks.get("access_token") or ""
    exp = _exp_of(access)
    now = time.time()
    fp = lineage(refresh)

    err = prov.get("last_auth_error") or {}
    if err:
        code = str(err.get("code") or "")
        relogin = bool(err.get("relogin_required"))
        at = str(err.get("at") or "")
        last_refresh = str(prov.get("last_refresh") or "")
        # Only trust an error newer than the last successful refresh; a stale
        # record from a since-repaired outage must not page forever.
        if at and last_refresh and at > last_refresh:
            if relogin or code == "refresh_token_reused":
                return "down", (f"{code or 'auth error'} at {at} "
                                f"(relogin_required={relogin}, lineage={fp})")

    if not refresh:
        return "down", "credential has NO refresh token — it cannot renew and will not recover on its own"

    if exp and exp <= now:
        return "down", (f"access token expired "
                        f"{time.strftime('%Y-%m-%dT%H:%MZ', time.gmtime(exp))} "
                        f"and nothing refreshed it (lineage={fp})")

    up, raw = gateway_active(gateway_unit)
    if not up:
        return "down", (f"codex credential is healthy but {gateway_unit} is {raw} — "
                        f"the bot is down for a different reason (lineage={fp})")

    when = time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime(exp)) if exp else "unknown"
    return "ok", f"refresh token present (lineage={fp}), access token valid to {when}, gateway {raw}"


# --------------------------------------------------------------------------
# channels
# --------------------------------------------------------------------------

def send_email(cfg_ch: dict, subject: str, body: str, api_key: str) -> None:
    to = list(cfg_ch["to"])
    args = {"recipient_email": to[0], "subject": subject, "body": body, "is_html": False}
    if len(to) > 1:
        args["extra_recipients"] = to[1:]
    req = urllib.request.Request(
        COMPOSIO_EXEC,
        data=json.dumps({"user_id": cfg_ch["composio_user_id"], "arguments": args}).encode(),
        headers={"x-api-key": api_key, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=45) as r:
        resp = json.loads(r.read())
    # Require an explicit success. The version this replaces also accepted "has a
    # data key and no error key", which let some delivery failures read as sent.
    if resp.get("successful") is not True:
        raise RuntimeError("composio email error: " + json.dumps(resp)[:400])


def slack_post(cfg_ch: dict, text: str, token: str) -> None:
    req = urllib.request.Request(
        SLACK_URL,
        data=json.dumps({"channel": cfg_ch["channel"], "text": text,
                         "unfurl_links": False}).encode(),
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/json; charset=utf-8"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        resp = json.loads(r.read())
    if not resp.get("ok"):
        raise RuntimeError("slack error: " + json.dumps(resp)[:300])


def linear_create(cfg_ch: dict, title: str, description: str, api_key: str) -> str:
    query = """
    mutation IssueCreate($teamId: String!, $title: String!, $description: String!, $assigneeId: String!) {
      issueCreate(input: {teamId: $teamId, title: $title, description: $description, assigneeId: $assigneeId}) {
        success
        issue { id identifier url }
      }
    }"""
    req = urllib.request.Request(
        LINEAR_URL,
        data=json.dumps({"query": query, "variables": {
            "teamId": cfg_ch["team"], "title": title,
            "description": description, "assigneeId": cfg_ch["assignee"],
        }}).encode(),
        headers={"Authorization": api_key, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=45) as r:
        resp = json.load(r)
    if resp.get("errors"):
        raise RuntimeError("linear error: " + json.dumps(resp["errors"])[:300])
    issue = (((resp.get("data") or {}).get("issueCreate") or {}).get("issue")) or {}
    return issue.get("url") or issue.get("identifier") or "(created)"




# --------------------------------------------------------------------------
# message bodies
# --------------------------------------------------------------------------

def _joined(cfg: dict, key: str) -> str:
    return "\n".join(cfg.get(key) or [])


def alert_text(cfg: dict, detail: str, ticket: str | None) -> str:
    return (
        f"{cfg['bot_label']} on {cfg['host_label']} can no longer sign in to Codex, "
        f"so it has stopped answering.\n\n"
        f"What the check saw: {detail}\n\n"
        + (f"Linear ticket: {ticket}\n\n" if ticket else "")
        + _joined(cfg, "runbook") + "\n\n"
        + _joined(cfg, "context_note") + "\n\n"
        "You will not get another message about this for 24 hours, and none at all "
        "once it is working again.\n\n"
        f"-- Automated check on {cfg['host_label']} (codex-health)."
    )


def ticket_body(cfg: dict, detail: str) -> str:
    return (
        f"The Hermes gateway on `{cfg['host_label']}` can no longer sign in to Codex, "
        f"so `{cfg['bot_label']}` has stopped answering.\n\n"
        f"**What the check saw:** {detail}\n\n"
        f"### Fix\n\n```\n{_joined(cfg, 'runbook')}\n```\n\n"
        f"### Context\n\n{_joined(cfg, 'context_note')}\n\n"
        f"_Auto-filed by the {cfg['host_label']} codex-health check._"
    )


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

def load_state(path: pathlib.Path) -> dict:
    if not path.exists():
        return {"status": "ok", "last_alert": 0, "ticket_url": None}
    try:
        return json.loads(path.read_text())
    except Exception as e:
        # Do NOT fall back to a default here. Silently resetting to "ok" would
        # turn an ongoing outage into a fabricated recovery and re-arm the edge
        # detector, so the next check reports a brand-new first failure.
        raise Disarmed(f"state file {path} is corrupt: {type(e).__name__}: {e}")


def save_state(path: pathlib.Path, s: dict) -> None:
    try:
        path.write_text(json.dumps(s, indent=2))
    except Exception as e:
        raise Disarmed(f"cannot write state {path}: {type(e).__name__}: {e}")


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def run(args) -> int:
    cfg = load_config(pathlib.Path(args.config).expanduser())
    hermes_home = pathlib.Path(os.path.expanduser(cfg["hermes_home"]))
    auth_path = hermes_home / "auth.json"
    config_yaml = hermes_home / "config.yaml"
    state_path = pathlib.Path(args.state_file).expanduser() if args.state_file else HERE / "state.json"
    renotify_s = int(cfg.get("renotify_s", 24 * 3600))

    # Always say which credential was inspected. Reading the wrong auth store is
    # the highest-consequence bug available here and it is invisible otherwise.
    print(f"host={cfg['host_label']} auth={auth_path} state={state_path}")

    if not args.force_down and not gateway_uses_codex(config_yaml):
        print(f"{cfg['host_label']} gateway is not configured on {PROVIDER} — not applicable, silent")
        return 0

    status, detail = (("down", "forced by --force-down") if args.force_down
                      else detect(auth_path, cfg["gateway_unit"]))

    if status == "unknown":
        print(f"status=unknown ({detail}) — no action, state untouched")
        return 0

    st = load_state(state_path)
    prev = st.get("status", "ok")
    now = int(time.time())

    alert = False
    if status == "down":
        if prev != "down":
            alert, why = True, "ok->down (first failure)"
        elif now - int(st.get("last_alert", 0)) >= renotify_s:
            alert, why = True, "still down, reminder"
        else:
            why = "still down, inside quiet window"
    else:
        why = "healthy (silent by design)" if prev == "ok" else "recovered (silent re-arm)"

    channels = cfg["channels"]

    if args.dry_run:
        print(f"status={status} prev={prev} detail={detail!r} action={why}")
        if alert:
            for name in ("slack", "email", "linear"):
                ch = channels.get(name)
                if not ch or getattr(args, f"no_{name}"):
                    continue
                if name == "linear":
                    print(f"\n--- LINEAR -> team {ch['team']} ---\n{cfg['ticket_title']}")
                elif name == "slack":
                    print(f"\n--- SLACK -> {ch['channel']} ---\n{alert_text(cfg, detail, None)}")
                else:
                    print(f"\n--- EMAIL -> {ch['to']} ---\nSubject: {cfg['subject']}\n\n"
                          f"{alert_text(cfg, detail, None)}")
        return 0

    delivered, failures = 0, []

    if alert:
        ticket = st.get("ticket_url")
        # One ticket per outage: file on the first failure, not on reminders.
        ch = channels.get("linear")
        if ch and not args.no_linear and prev != "down":
            key = env_val(ch["key_env"], hermes_home)
            if not key:
                failures.append(f"linear: {ch['key_env']} unresolvable")
            else:
                try:
                    ticket = linear_create(ch, cfg["ticket_title"],
                                           ticket_body(cfg, detail), key)
                    st["ticket_url"] = ticket
                    delivered += 1
                    print(f"linear ticket: {ticket}")
                except Exception as e:
                    failures.append(f"linear: {type(e).__name__}: {e}")

        ch = channels.get("slack")
        if ch and not args.no_slack:
            tok = env_val(ch["token_env"], hermes_home)
            if not tok:
                failures.append(f"slack: {ch['token_env']} unresolvable")
            else:
                try:
                    slack_post(ch, alert_text(cfg, detail, ticket), tok)
                    delivered += 1
                    print(f"slack -> {ch['channel']}")
                except Exception as e:
                    failures.append(f"slack: {type(e).__name__}: {e}")

        ch = channels.get("email")
        if ch and not args.no_email:
            key = env_val(ch["key_env"], hermes_home)
            if not key:
                failures.append(f"email: {ch['key_env']} unresolvable")
            else:
                try:
                    send_email(ch, cfg["subject"], alert_text(cfg, detail, ticket), key)
                    delivered += 1
                    print(f"emailed {ch['to']}")
                except Exception as e:
                    failures.append(f"email: {type(e).__name__}: {e}")

        st["last_alert"] = now
        print(f"status=down ({why}) | {detail}")
    else:
        if status == "ok":
            st["ticket_url"] = None      # re-arm so the next outage files a fresh ticket
        print(f"status={status} action={why} | {detail}")

    st["status"] = status
    save_state(state_path, st)

    # An outage nobody was told about is indistinguishable from no outage. If we
    # decided to alert and every channel failed, that is a hard failure -- the
    # version this replaces printed the errors and still exited 0. It surfaces in
    # `systemctl --user status` and the journal; by explicit decision there is no
    # second escalation channel, so this is the only trace.
    if alert and delivered == 0:
        for f in failures:
            print(f"  DELIVERY FAILURE: {f}", file=sys.stderr)
        print("ALERTED BUT NOTHING WAS DELIVERED — no one has been told", file=sys.stderr)
        return 1

    for f in failures:
        print(f"  partial delivery failure: {f}", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Alert when a Hermes host's Codex sign-in breaks. Detect only; never repairs.")
    ap.add_argument("--config", default=str(HERE / "config.json"),
                    help="per-host config (default: config.json next to this script)")
    ap.add_argument("--state-file", default=None,
                    help="override state path — use for drills so they cannot "
                         "write production state and suppress a real outage")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force-down", action="store_true",
                    help="exercise the alert path (bypasses detection entirely)")
    ap.add_argument("--no-email", action="store_true")
    ap.add_argument("--no-slack", action="store_true")
    ap.add_argument("--no-linear", action="store_true")
    args = ap.parse_args()
    try:
        return run(args)
    except Disarmed as e:
        print(f"WATCHDOG DISARMED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
