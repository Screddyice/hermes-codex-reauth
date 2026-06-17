# deploy/ — Residential Proxy Sidecar

Installs a static residential SOCKS5 forwarder alongside the codex-reauth
toolkit. Used to bypass OpenAI's datacenter-IP refusal during headless
re-auth from AWS servers.

## One-time: sign up for IPRoyal

1. Go to https://iproyal.com — Static Residential → 1 IP → 1 month
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
mkdir -p ~/.openclaw && chmod 700 ~/.openclaw
cat > ~/.openclaw/residential-proxy.env <<'EOF'
IPROYAL_HOST=proxy.iproyal.com
IPROYAL_PORT=12321
IPROYAL_USER=YOUR_USERNAME
IPROYAL_PASS=YOUR_PASSWORD
IPROYAL_EXPECTED_IP=203.0.113.42
SLACK_BOT_TOKEN=YOUR_SLACK_BOT_TOKEN
SLACK_CHANNEL_ID=C09FLJDCAJD
EOF
chmod 600 ~/.openclaw/residential-proxy.env

# 3. Run the installer
bash ~/codex-reauth/deploy/install.sh
```

Expected final log line: `[install] install complete`.

If the installer exits non-zero, fix the underlying issue (usually a
typo in the env file or an IPRoyal auth failure) and re-run — the script
is idempotent.

## Verify

```bash
# Service is running and listening
systemctl --user status residential-proxy.service --no-pager | head -15

# Tunnel egress is the expected residential IP
curl --socks5 127.0.0.1:1080 https://api.ipify.org && echo

# Cron installed
crontab -l | grep health-check

# Manual health check
bash ~/codex-reauth/deploy/health-check.sh
```

## Rotate credentials

If IPRoyal credentials, the pinned IP, or the Slack token change:

```bash
vim ~/.openclaw/residential-proxy.env
systemctl --user restart residential-proxy.service
bash ~/codex-reauth/deploy/health-check.sh  # confirm still OK
```

## Upgrade gost

Override the version and hash at install time:

```bash
GOST_VERSION=3.1.0 GOST_SHA256=<pinned-hash> bash ~/codex-reauth/deploy/install.sh
```

The hash comes from the release's `checksums.txt` — verify before pinning.

## Uninstall

```bash
systemctl --user stop residential-proxy.service
systemctl --user disable residential-proxy.service
rm ~/.config/systemd/user/residential-proxy.service
rm ~/.config/systemd/user/residential-proxy-alert.service
systemctl --user daemon-reload
crontab -l | grep -vF "$HOME/codex-reauth/deploy/health-check.sh" | crontab -
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

## Failure modes and what alerts look like

Three layers of alerts, all to the same Slack channel (`aaa-ops`, ID
`C09FLJDCAJD` on Team Nebula AI):

| Layer | Trigger | What the alert says |
|---|---|---|
| systemd `OnFailure=` | `residential-proxy.service` crashes or fails to start | "forwarder service has failed or crashed — re-auth will fall back to direct connection which will fail at the 10-day mark. Run the Mac tunnel as manual fallback." |
| Daily cron health check | 9 AM local: egress IP doesn't match `IPROYAL_EXPECTED_IP` or tunnel unreachable | "health check IP mismatch: expected X, got Y. IPRoyal may have rotated our IP." OR "could not reach api.ipify.org through SOCKS tunnel." |
| Watchdog escalation | `codex_reauth_server.py` has failed 2+ times in a row (counted in `~/.hermes-oauth/watchdog-escalation-state.json`) | "codex reauth escalation has failed N times in a row (last exit code: X). Likely causes: residential proxy down, IPRoyal IP rotated, or OpenAI rejecting even the residential IP." |
