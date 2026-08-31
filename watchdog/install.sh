#!/usr/bin/env bash
# Install the codex watchdog on a Hermes host. Idempotent; safe to re-run.
#
#   ./install.sh --host src              # user hermes,   ~/.hermes
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
# It never touches state.json, self-heal-state.json, or healer backups. A fresh
# install must not re-arm an outage edge or discard credential evidence.
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
HEAL_SERVICE=""
HEAL_TIMER=""
HEAL_NOTIFY=""
case "$HOST" in
  src)          DEST="$HOME/.hermes/codex-health";               TIMER="hermes-codex-health.timer";     SERVICE="hermes-codex-health.service";     NOTIFY="hermes-codex-health-notify.service";     BEAT="hermes-codex-heartbeat.service"
                HEAL_SERVICE="hermes-codex-self-heal.service";     HEAL_TIMER="hermes-codex-self-heal.timer"; HEAL_NOTIFY="hermes-codex-self-heal-notify.service" ;;
  tmn)          DEST="$HOME/.hermes/codex-health";               TIMER="hermes-codex-health-tmn.timer"; SERVICE="hermes-codex-health-tmn.service"; NOTIFY="hermes-codex-health-tmn-notify.service"; BEAT="hermes-codex-heartbeat-tmn.service"
                HEAL_SERVICE="hermes-codex-self-heal-tmn.service"; HEAL_TIMER="hermes-codex-self-heal-tmn.timer"; HEAL_NOTIFY="hermes-codex-self-heal-tmn-notify.service" ;;
  nebos-claude) DEST="$HOME/.hermes/profiles/tmn/claude-health"; TIMER="nebos-claude-health.timer";     SERVICE="nebos-claude-health.service";     NOTIFY="nebos-claude-health-notify.service"
                CHECK_SRC="$HERE/claude_health_check.py"; HEAL_SERVICE=""; HEAL_TIMER=""; HEAL_NOTIFY="" ;;
  observer)     DEST="$HOME/.watchdog-observer";                 TIMER="codex-observer.timer";          SERVICE="codex-observer.service";          NOTIFY="codex-observer-notify.service";     BEAT="codex-observer-heartbeat.service"; CFG_NAME="hermes-tmn-observer"
                HEAL_SERVICE="codex-observer-self-heal.service"; HEAL_TIMER="codex-observer-self-heal.timer"; HEAL_NOTIFY="codex-observer-self-heal-notify.service" ;;
  *) echo "usage: $0 --host {src|tmn|nebos-claude|observer}" >&2; exit 2 ;;
esac

CFG_SRC="$HERE/hosts/${CFG_NAME:-$HOST}.json"
UNIT_DIR="$HOME/.config/systemd/user"
log() { echo "[install] $*"; }

[[ -f "$CFG_SRC" ]] || { echo "missing config $CFG_SRC" >&2; exit 1; }

# --- 1. script + config (never state.json) ---
mkdir -p "$DEST" "$UNIT_DIR"
if [[ -n "$HEAL_SERVICE" ]]; then
  # A healer that cannot create private credential backups must fail at install,
  # before its first scheduled mutation reaches that boundary.
  install -d -m 0700 "$DEST/backups"
fi
install -m 0755 "$CHECK_SRC" "$DEST/check.py"
install -m 0644 "$CFG_SRC"   "$DEST/config.json"
# The Codex check and healer share one passive auth classifier. The observer
# imports it even though observer mode never reads a local credential.
if [[ "$HOST" != "nebos-claude" ]]; then
  install -m 0755 "$HERE/auth_state.py" "$DEST/auth_state.py"
fi
# The live probe is a codex triage tool; the Claude watchdog already probes live,
# so shipping it there would just be a second thing that can rot.
if [[ "$HOST" != "nebos-claude" && "$HOST" != "observer" ]]; then
  install -m 0755 "$HERE/codex_auth_probe.py" "$DEST/codex_auth_probe.py"
fi
# The three Codex roles run the bounded healer. NEBOS Claude has no healer.
if [[ -n "$HEAL_SERVICE" ]]; then
  install -m 0755 "$HERE/self_heal.py" "$DEST/self_heal.py"
  install -m 0755 "$HERE/hermes_codex_refresh.py" "$DEST/hermes_codex_refresh.py"
fi
# The last-resort escalator lives beside the check it backs up, and reads that
# check's config.json for host labels and hermes_home.
install -m 0755 "$HERE/notify_failure.py" "$DEST/notify_failure.py"
# The peer watch: this host serves its own heartbeat, and reads the other box's.
if [[ -n "${BEAT:-}" ]]; then
  install -m 0755 "$HERE/heartbeat_server.py" "$DEST/heartbeat_server.py"
fi
log "installed check.py + config.json + notify_failure.py -> $DEST"

# Validate credential-host dependencies before the healer timer can start. The
# systemd manager does not inherit an interactive shell's PATH, so every
# credential role pins and validates its Hermes executable in config.json.
if [[ -n "$HEAL_SERVICE" ]]; then
  if OUT="$(/usr/bin/python3 "$DEST/self_heal.py" --check-readiness 2>&1)"; then
    log "OK    healer readiness: $OUT"
  else
    log "FAIL  healer readiness: $OUT"
    exit 1
  fi
fi

# --- 2. systemd units ---
install -m 0644 "$HERE/systemd/$SERVICE" "$UNIT_DIR/$SERVICE"
install -m 0644 "$HERE/systemd/$TIMER"   "$UNIT_DIR/$TIMER"
install -m 0644 "$HERE/systemd/$NOTIFY"  "$UNIT_DIR/$NOTIFY"
[[ -n "${BEAT:-}" ]] && install -m 0644 "$HERE/systemd/$BEAT" "$UNIT_DIR/$BEAT"
if [[ -n "$HEAL_SERVICE" ]]; then
  install -m 0644 "$HERE/systemd/$HEAL_SERVICE" "$UNIT_DIR/$HEAL_SERVICE"
  install -m 0644 "$HERE/systemd/$HEAL_TIMER" "$UNIT_DIR/$HEAL_TIMER"
  install -m 0644 "$HERE/systemd/$HEAL_NOTIFY" "$UNIT_DIR/$HEAL_NOTIFY"
fi
systemctl --user daemon-reload
log "installed units $SERVICE + $TIMER + $NOTIFY${BEAT:+ + $BEAT}${HEAL_SERVICE:+ + $HEAL_SERVICE + $HEAL_TIMER + $HEAL_NOTIFY}"

# --- 3. enable ---
systemctl --user enable "$TIMER" >/dev/null
systemctl --user start  "$TIMER"
if [[ -n "$HEAL_SERVICE" ]]; then
  systemctl --user enable "$HEAL_TIMER" >/dev/null
  systemctl --user start  "$HEAL_TIMER"
fi
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

if [[ -n "$HEAL_SERVICE" ]]; then
  check "healer timer enabled" "$(systemctl --user is-enabled "$HEAL_TIMER" 2>&1)" "enabled"
  check "healer timer active"  "$(systemctl --user is-active  "$HEAL_TIMER" 2>&1)" "active"
  HEAL_NEXT="$(systemctl --user show "$HEAL_TIMER" -p NextElapseUSecMonotonic --value)"
  HEAL_NEXT_NORMALIZED="$(printf '%s' "$HEAL_NEXT" | tr '[:upper:]' '[:lower:]')"
  case "$HEAL_NEXT_NORMALIZED" in
    ""|n/a|infinity|infinite|never|-)
      log "FAIL  healer timer has no scheduled next run"; fail=1 ;;
    *) log "OK    healer next elapse = $HEAL_NEXT" ;;
  esac
  if systemctl --user show "$HEAL_SERVICE" -p OnFailure --value | grep -q "$HEAL_NOTIFY"; then
    log "OK    healer OnFailure = $HEAL_NOTIFY"
  else
    log "FAIL  $HEAL_SERVICE has no OnFailure=$HEAL_NOTIFY"; fail=1
  fi
fi

# Prove the escalator can resolve its own credentials. It is the last thing that
# will ever speak, so "it was never going to work" must surface at install time.
if OUT="$(/usr/bin/python3 "$DEST/notify_failure.py" --unit "$SERVICE" --dry-run 2>&1 | head -1)"; then
  log "OK    escalator ready: $OUT"
else
  log "FAIL  escalator cannot resolve TELEGRAM_BOT_TOKEN / TELEGRAM_HOME_CHANNEL:"
  echo "$OUT" | sed 's/^/          /'; fail=1
fi

if [[ -n "$HEAL_SERVICE" ]]; then
  if OUT="$(/usr/bin/python3 "$DEST/notify_failure.py" --unit "$HEAL_SERVICE" --dry-run 2>&1 | head -1)"; then
    log "OK    healer escalator ready: $OUT"
  else
    log "FAIL  healer escalator cannot resolve TELEGRAM_BOT_TOKEN / TELEGRAM_HOME_CHANNEL:"
    echo "$OUT" | sed 's/^/          /'; fail=1
  fi
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

# Prove the installed scripts run without touching either live state file.
PROBE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/watchdog-install.XXXXXX")"
CHECK_PROBE_STATE="$PROBE_DIR/check-state.json"
HEAL_PROBE_STATE="$PROBE_DIR/healer-state.json"
cleanup_probe_dir() {
  rm -f "$CHECK_PROBE_STATE" "$HEAL_PROBE_STATE"
  rmdir "$PROBE_DIR" 2>/dev/null || true
}
trap cleanup_probe_dir EXIT

if OUT="$(/usr/bin/python3 "$DEST/check.py" --dry-run --state-file "$CHECK_PROBE_STATE" 2>&1)"; then
  log "OK    dry-run exited 0"
  echo "$OUT" | sed 's/^/          /'
else
  log "FAIL  dry-run exited non-zero:"; echo "$OUT" | sed 's/^/          /'; fail=1
fi

if [[ -n "$HEAL_SERVICE" ]]; then
  if OUT="$(/usr/bin/python3 "$DEST/self_heal.py" --dry-run --state-file "$HEAL_PROBE_STATE" 2>&1)"; then
    log "OK    healer dry-run exited 0"
    echo "$OUT" | sed 's/^/          /'
  else
    log "FAIL  healer dry-run exited non-zero:"
    echo "$OUT" | sed 's/^/          /'; fail=1
  fi
fi

if [[ "$fail" -ne 0 ]]; then
  echo "[install] INSTALL INCOMPLETE — see FAIL lines above" >&2
  exit 1
fi

log "install complete on $HOST"
