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

case "$HOST" in
  hostinger) DEST="$HOME/.hermes/codex-health";               TIMER="hermes-codex-health.timer";     SERVICE="hermes-codex-health.service" ;;
  tmn)       DEST="$HOME/.hermes/profiles/tmn/codex-health";  TIMER="hermes-codex-health-tmn.timer"; SERVICE="hermes-codex-health-tmn.service" ;;
  *) echo "usage: $0 --host {hostinger|tmn}" >&2; exit 2 ;;
esac

CFG_SRC="$HERE/hosts/$HOST.json"
UNIT_DIR="$HOME/.config/systemd/user"
log() { echo "[install] $*"; }

[[ -f "$CFG_SRC" ]] || { echo "missing config $CFG_SRC" >&2; exit 1; }

# --- 1. script + config (never state.json) ---
mkdir -p "$DEST" "$UNIT_DIR"
install -m 0755 "$HERE/codex_health_check.py" "$DEST/check.py"
install -m 0644 "$CFG_SRC"                    "$DEST/config.json"
install -m 0755 "$HERE/codex_auth_probe.py"   "$DEST/codex_auth_probe.py"
log "installed check.py + config.json + codex_auth_probe.py -> $DEST"

# --- 2. systemd units ---
install -m 0644 "$HERE/systemd/$SERVICE" "$UNIT_DIR/$SERVICE"
install -m 0644 "$HERE/systemd/$TIMER"   "$UNIT_DIR/$TIMER"
systemctl --user daemon-reload
log "installed units $SERVICE + $TIMER"

# --- 3. enable ---
systemctl --user enable "$TIMER" >/dev/null
systemctl --user start  "$TIMER"

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
