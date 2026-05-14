#!/usr/bin/env bash
# Daily health check for the residential SOCKS proxy.
#
# Probes through the local gost forwarder (127.0.0.1:1080) and verifies the
# observed public IP matches IPROYAL_EXPECTED_IP. On failure, attempts to
# self-heal by restarting residential-proxy.service before alerting. Slack is
# only invoked on edge transitions (ok -> fail), so chronic failures don't
# spam the channel.
#
# Run via cron, e.g. 0 9 * * * /home/ubuntu/codex-reauth/deploy/health-check.sh
#
# Env vars required (sourced from ~/.openclaw/residential-proxy.env):
#   IPROYAL_EXPECTED_IP — the IP we should see
#   SLACK_BOT_TOKEN, SLACK_CHANNEL_ID — for alerts
#
# Exit codes: 0 OK, 2 misconfig, 3 SOCKS unreachable, 4 IP mismatch.

set -euo pipefail

ENV_FILE="${HOME}/.openclaw/residential-proxy.env"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERT="${SCRIPT_DIR}/slack-alert.sh"
STATE_FILE="${HOME}/.openclaw/residential-proxy.state"

EXPECTED="${IPROYAL_EXPECTED_IP:-}"
if [[ -z "$EXPECTED" ]]; then
  echo "health-check: IPROYAL_EXPECTED_IP not set in $ENV_FILE" >&2
  exit 2
fi

probe() {
  # 3x SOCKS5 handshake with 30s timeout — residential pools commonly drop
  # individual connections under load; a single 10s shot produced false positives.
  local max_attempts=3 timeout=30 i observed=""
  for i in $(seq 1 "$max_attempts"); do
    observed=$(curl -sS --max-time "$timeout" --socks5 127.0.0.1:1080 https://api.ipify.org 2>/dev/null || true)
    [[ -n "$observed" ]] && break
    [[ "$i" -lt "$max_attempts" ]] && sleep 2
  done
  printf '%s' "$observed"
}

classify() {
  local obs="$1"
  if [[ -z "$obs" ]]; then echo "unreachable"; return; fi
  if [[ "$obs" != "$EXPECTED" ]]; then echo "ip_mismatch"; return; fi
  echo "ok"
}

OBSERVED=$(probe)
STATUS=$(classify "$OBSERVED")

# Self-heal: restart gost once and re-probe before deciding to alert.
# gost periodically wedges (accepts SOCKS5 locally but can't relay upstream);
# a clean restart almost always recovers it.
if [[ "$STATUS" != "ok" ]]; then
  echo "$(date -Iseconds) initial status=${STATUS} observed='${OBSERVED}'; restarting residential-proxy.service" >&2
  systemctl --user restart residential-proxy.service 2>/dev/null || true
  sleep 5
  OBSERVED=$(probe)
  STATUS=$(classify "$OBSERVED")
fi

LAST_STATUS="$(cat "$STATE_FILE" 2>/dev/null || echo "ok")"

case "$STATUS" in
  ok)
    echo "$(date -Iseconds) health-check OK (${OBSERVED})"
    echo "ok" > "$STATE_FILE"
    exit 0
    ;;
  unreachable)
    MSG="SOCKS5 handshake to IPRoyal failed (no response from local gost forwarder after auto-restart). Local proxy may be wedged or IPRoyal upstream is genuinely unreachable. Manual diagnosis required."
    CODE=3
    ;;
  ip_mismatch)
    MSG="Egress IP mismatch after gost auto-restart: expected ${EXPECTED}, got ${OBSERVED}. IPRoyal sticky session may have rotated."
    CODE=4
    ;;
esac

# Edge-trigger Slack: only alert on ok -> fail transition. Chronic failure
# stays silent; recovery is also silent (next OK probe resets state, so a
# fresh outage will alert again).
if [[ "$LAST_STATUS" == "ok" ]]; then
  bash "$ALERT" residential-proxy "$MSG" || true
fi
echo "fail" > "$STATE_FILE"
exit "$CODE"
