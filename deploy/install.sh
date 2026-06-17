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
GOST_SHA256="${GOST_SHA256:-7b74e679872d1431da152d5df4b3192f660af54c0930bb8de296d10d5603863d}"
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
  trap 'rm -rf "${TMP:-}"' EXIT
  curl -sSL "$GOST_URL" -o "$TMP/gost.tar.gz"
  echo "$GOST_SHA256  $TMP/gost.tar.gz" | sha256sum -c -
  tar -xz -C "$TMP" -f "$TMP/gost.tar.gz"
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
LISTENING=0
for i in {1..10}; do
  if (echo > /dev/tcp/127.0.0.1/1080) 2>/dev/null; then
    LISTENING=1
    log "tunnel listening on 127.0.0.1:1080"
    break
  fi
  sleep 1
done
if [[ "$LISTENING" -ne 1 ]]; then
  echo "ERROR: gost did not start listening on 127.0.0.1:1080 within 10s" >&2
  systemctl --user status residential-proxy.service --no-pager | tail -20
  exit 4
fi

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
