#!/usr/bin/env bash
# Install the codex watchdog on a Hermes host. Idempotent; safe to re-run.
#
#   ./install.sh --host hostinger        # user ubuntu,  ~/.hermes
#   ./install.sh --host tmn              # user screddy, ~/.hermes/profiles/tmn
#
# No usernames or absolute home paths are hardcoded — everything derives from
# $HOME and $USER, because the two hosts run as different users.
#
# It ENDS IN ASSERTIONS rather than assumptions. A watchdog that reports a
# successful install while sitting disarmed is the failure this whole project
# exists to remove, so this script refuses to print success unless it has
# verified the timer is enabled, scheduled, and that the script actually runs.
#
# It never touches state.json. A fresh install must not reset an in-progress
# outage to "ok" and re-arm the edge detector.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# CHECK_SRC differs per target because the Claude watchdog is a different script,
# not another config: codex is judged from local auth.json state, Claude only from
# a live call, since its token is an opaque string with no local metadata.
CHECK_SRC="$HERE/codex_health_check.py"
case "$HOST" in
  hostinger)    DEST="$HOME/.hermes/codex-health";               TIMER="hermes-codex-health.timer";     SERVICE="hermes-codex-health.service";     NOTIFY="hermes-codex-health-notify.service";     BEAT="hermes-codex-heartbeat.service" ;;
  tmn)          DEST="$HOME/.hermes/profiles/tmn/codex-health";  TIMER="hermes-codex-health-tmn.timer"; SERVICE="hermes-codex-health-tmn.service"; NOTIFY="hermes-codex-health-tmn-notify.service"; BEAT="hermes-codex-heartbeat-tmn.service" ;;
  nebos-claude) DEST="$HOME/.hermes/profiles/tmn/claude-health"; TIMER="nebos-claude-health.timer";     SERVICE="nebos-claude-health.service";     NOTIFY="nebos-claude-health-notify.service"
                CHECK_SRC="$HERE/claude_health_check.py" ;;
  neb-ops)      DEST="$HOME/.watchdog-observer";                 TIMER="codex-observer.timer";          SERVICE="codex-observer.service";          NOTIFY="codex-observer-notify.service" ;;
  *) echo "usage: $0 --host {hostinger|tmn|nebos-claude|neb-ops}" >&2; exit 2 ;;
esac

CFG_SRC="$HERE/hosts/$HOST.json"
UNIT_DIR="$HOME/.config/systemd/user"
log() { echo "[install] $*"; }

[[ -f "$CFG_SRC" ]] || { echo "missing config $CFG_SRC" >&2; exit 1; }

# --- 1. script + config (never state.json) ---
mkdir -p "$DEST" "$UNIT_DIR"
install -m 0755 "$CHECK_SRC" "$DEST/check.py"
install -m 0644 "$CFG_SRC"   "$DEST/config.json"
# The live probe is a codex triage tool; the Claude watchdog already probes live,
# so shipping it there would just be a second thing that can rot.
if [[ "$HOST" != "nebos-claude" && "$HOST" != "neb-ops" ]]; then
  install -m 0755 "$HERE/codex_auth_probe.py" "$DEST/codex_auth_probe.py"
fi
# The last-resort escalator lives beside the check it backs up, and reads that
# check's config.json for host labels and hermes_home.
install -m 0755 "$HERE/notify_failure.py" "$DEST/notify_failure.py"
# The peer watch: this host serves its own heartbeat, and reads the other box's.
if [[ -n "${BEAT:-}" ]]; then
  install -m 0755 "$HERE/heartbeat_server.py" "$DEST/heartbeat_server.py"
fi
log "installed check.py + config.json + notify_failure.py -> $DEST"

# --- 2. systemd units ---
install -m 0644 "$HERE/systemd/$SERVICE" "$UNIT_DIR/$SERVICE"
install -m 0644 "$HERE/systemd/$TIMER"   "$UNIT_DIR/$TIMER"
install -m 0644 "$HERE/systemd/$NOTIFY"  "$UNIT_DIR/$NOTIFY"
[[ -n "${BEAT:-}" ]] && install -m 0644 "$HERE/systemd/$BEAT" "$UNIT_DIR/$BEAT"
systemctl --user daemon-reload
log "installed units $SERVICE + $TIMER + $NOTIFY${BEAT:+ + $BEAT}"

# --- 3. enable ---
systemctl --user enable "$TIMER" >/dev/null
systemctl --user start  "$TIMER"
if [[ -n "${BEAT:-}" ]]; then
  systemctl --user enable "$BEAT" >/dev/null
  systemctl --user restart "$BEAT"
fi

# A monotonic timer (OnUnitActiveSec) can end up enabled+active with NO next
# elapse when the service has not run recently — that is how a re-enabled timer
# silently never fires. These use OnCalendar so it should not happen, but assert
# it rather than trust it.
if [[ -z "$(systemctl --user show "$TIMER" -p NextElapseUSecRealtime --value)" ]]; then
  log "timer has no next elapse — priming by running the service once"
  systemctl --user start "$SERVICE" || true
fi

# --- 4. assertions: refuse to claim success without proof ---
fail=0
check() { # check <label> <actual> <expected>
  if [[ "$2" == "$3" ]]; then log "OK    $1 = $2"; else log "FAIL  $1 = $2 (want $3)"; fail=1; fi
}

check "timer enabled" "$(systemctl --user is-enabled "$TIMER" 2>&1)" "enabled"
check "timer active"  "$(systemctl --user is-active  "$TIMER" 2>&1)" "active"
check "linger"        "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" "yes"

NEXT="$(systemctl --user show "$TIMER" -p NextElapseUSecRealtime --value)"
if [[ -n "$NEXT" ]]; then log "OK    next elapse = $NEXT"; else log "FAIL  timer has no scheduled next run"; fail=1; fi

# The OnFailure wiring is the whole point of the escalator, and a missing
# directive is invisible until the day it was supposed to fire. Assert it.
if systemctl --user show "$SERVICE" -p OnFailure --value | grep -q "$NOTIFY"; then
  log "OK    OnFailure = $NOTIFY"
else
  log "FAIL  $SERVICE has no OnFailure=$NOTIFY"; fail=1
fi

# Prove the escalator can resolve its own credentials. It is the last thing that
# will ever speak, so "it was never going to work" must surface at install time.
if OUT="$(/usr/bin/python3 "$DEST/notify_failure.py" --unit "$SERVICE" --dry-run 2>&1 | head -1)"; then
  log "OK    escalator ready: $OUT"
else
  log "FAIL  escalator cannot resolve TELEGRAM_BOT_TOKEN / TELEGRAM_HOME_CHANNEL:"
  echo "$OUT" | sed 's/^/          /'; fail=1
fi

# The heartbeat is what the OTHER box reads to know this one is alive, so a
# silently dead server here disables the peer's only view of this host.
if [[ -n "${BEAT:-}" ]]; then
  sleep 1
  check "heartbeat server" "$(systemctl --user is-active "$BEAT" 2>&1)" "active"
  TSIP="$(tailscale ip -4 2>/dev/null | head -1)"
  if [[ -n "$TSIP" ]] && curl -fsS -m 8 "http://$TSIP:8299/heartbeat" >/dev/null 2>&1; then
    log "OK    heartbeat reachable on http://$TSIP:8299/heartbeat"
  else
    # A missing heartbeat.json before the first run is expected, so only a dead
    # listener counts as failure here.
    if [[ -n "$TSIP" ]] && curl -sS -m 8 -o /dev/null -w '%{http_code}' "http://$TSIP:8299/heartbeat" 2>/dev/null | grep -q '^[0-9]'; then
      log "OK    heartbeat listener up on $TSIP:8299 (no heartbeat written yet)"
    else
      log "FAIL  heartbeat not reachable on $TSIP:8299"; fail=1
    fi
  fi
fi

# Prove the installed script actually runs and resolves the intended credential.
if OUT="$(/usr/bin/python3 "$DEST/check.py" --dry-run --state-file /tmp/install-probe-$$.json 2>&1)"; then
  log "OK    dry-run exited 0"
  echo "$OUT" | sed 's/^/          /'
else
  log "FAIL  dry-run exited non-zero:"; echo "$OUT" | sed 's/^/          /'; fail=1
fi
rm -f "/tmp/install-probe-$$.json"

if [[ "$fail" -ne 0 ]]; then
  echo "[install] INSTALL INCOMPLETE — see FAIL lines above" >&2
  exit 1
fi

log "install complete on $HOST"
