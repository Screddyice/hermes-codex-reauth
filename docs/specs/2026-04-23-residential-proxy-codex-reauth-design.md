# Residential Proxy Sidecar for Codex Re-auth

**Date:** 2026-04-23
**Status:** Approved, ready for implementation plan
**Scope:** Both openclaw servers (neb-server, cliqk-server / openclaw alias)

## Problem

openclaw runs OpenAI Codex (`openai-codex/gpt-5.4`) via OAuth on both AWS EC2 servers. OpenAI's refresh token chain breaks roughly every 10 days, requiring a full browser re-auth. The existing server-side re-auth flow (`codex_reauth_server.py`) is designed to handle this headlessly via a Gmail-driven magic-link/code flow, but it fails every time with `acted_on_email=False` because OpenAI never actually sends the verification email when the login comes from an AWS datacenter IP.

Current workaround: Shawn's Mac runs a reverse SSH SOCKS tunnel (`mac_proxy_tunnel.sh`) that routes Chrome through his residential ISP. This works but requires Shawn's Mac to be powered on and at home at exactly the moment a re-auth is needed. That dependency is what this project eliminates.

### Evidence

- `~/.hermes-oauth/codex-reauth.log` on both servers shows repeated attempts ending with `ERROR no /auth/callback received within timeout (acted_on_email=False)`
- Every failed attempt logs `no SOCKS proxy on :1080, using direct connection` — the residential path was not available
- Most recent attempt on neb-server (2026-04-21) failed the same way
- Gmail credentials are healthy (valid refresh token for `shawn.reddy1@gmail.com`) — Gmail access is NOT the bottleneck

### Root cause

OpenAI's login page detects `new device + AWS datacenter IP + headless browser fingerprint` and either (a) Cloudflare Turnstile silently fails so the form never submits, or (b) OpenAI accepts the form but suppresses email delivery to avoid bot abuse. Either way, the Gmail-driven flow has nothing to act on.

## Goals

- Re-auth succeeds autonomously at the 10-day mark with zero dependency on Shawn's Mac being online
- Works for both NEB and Cliqk servers
- No changes to the core re-auth flow logic, gateway units, or token storage
- Mac-based re-auth remains as a manual fallback

## Non-goals

- Replacing OpenAI OAuth with API keys
- Building a fallback to a second residential proxy provider (accept single-provider risk for now)
- IP rotation (a static IP is the whole point)
- Changing anything about the watchdog escalation logic

## Architecture

```
IPRoyal Static Residential IP (single dedicated IP)
        |
        |  SOCKS5 with user:pass auth
        v
+--------------------------+    +--------------------------+
| neb-server               |    | cliqk-server             |
|                          |    |                          |
| residential-proxy.service|    | residential-proxy.service|
|  (gost, :1080 -> IPRoyal)|    |  (gost, :1080 -> IPRoyal)|
|                          |    |                          |
| codex_reauth_server.py   |    | codex_reauth_server.py   |
|  (probes :1080, routes   |    |  (unchanged)             |
|   Chrome through it)     |    |                          |
+--------------------------+    +--------------------------+
```

Both servers share one IPRoyal account and one residential IP. From OpenAI's perspective this represents the single human (Shawn) who runs both accounts, matching the pattern they already see when Shawn logs in from his Mac.

## Components

### New per server

1. **`gost` binary** at `/usr/local/bin/gost` (Go, ~10MB, static)
2. **`~/.config/systemd/user/residential-proxy.service`** — always-on unit, `Restart=always`, reads upstream endpoint from env file, listens on `127.0.0.1:1080`
3. **`~/.openclaw/residential-proxy.env`** — mode 600, owned by `ubuntu`, contains:
   - `IPROYAL_HOST`
   - `IPROYAL_PORT`
   - `IPROYAL_USER`
   - `IPROYAL_PASS`
4. **Slack alert hook** for the systemd unit's `OnFailure`

### Credentials source of truth

- IPRoyal account credentials also mirrored into `/Users/shawnreddy/projects/.env` on Shawn's Mac under the unprefixed shared keys section (both companies use the same endpoint)

### Code change

Single edit to `codex_reauth_server.py`:

- Default `socks_proxy_auto` stays True
- Add an explicit WARNING-level log line when the tunnel is expected but not reachable, so proxy outages surface in the reauth log without needing to cross-reference the gost service log
- No change to the flow logic, Chrome args, Playwright, Gmail polling, callback, or token write

## Monitoring and alerting

Three failure modes, each alerted via direct Slack bot tokens (not Composio, per project rules):

| Failure mode | Detection | Alert channel |
|---|---|---|
| `residential-proxy.service` crashes or repeatedly fails to start | systemd user `OnFailure=` directive invokes a shell that posts to Slack | company-specific ops channel |
| Daily tunnel health check fails | Cron at 09:00 local runs `curl --socks5 127.0.0.1:1080 https://api.ipify.org`, posts if non-2xx or if the returned IP doesn't match the expected IPRoyal IP | Same |
| `codex_reauth_server.py` escalation fails 2x consecutive | Existing watchdog tracks consecutive failures, posts when threshold hit | Same |

Alerts include: server name (neb / cliqk), failure mode, and the recommended fallback ("run Mac tunnel from laptop").

## Fallback: local Mac restore

**If the residential proxy path fails for any reason** (IPRoyal outage, credential issue, OpenAI rejecting even the residential IP), the existing Mac-based flow remains the manual fallback. No changes to `codex_reauth_mac.py` or `mac_proxy_tunnel.sh`. Procedure when an alert fires:

1. Open Shawn's Mac, ensure on home Wi-Fi
2. Run `~/codex-reauth/mac_proxy_tunnel.sh` to bring up the reverse SOCKS tunnel to both servers
3. On each affected server, trigger `codex_reauth_server.py` manually (the script detects `127.0.0.1:1080` from the Mac tunnel just like it detects the gost tunnel)
4. Tokens get written, gateway restarts, back to normal

This fallback is explicit and documented so Shawn always has a way out even if the residential proxy path is broken. Mac path is tier-2; residential proxy is tier-1.

## Configuration

**Per-server systemd unit** (`~/.config/systemd/user/residential-proxy.service`):

```ini
[Unit]
Description=Residential SOCKS5 proxy forwarder (IPRoyal)
After=network-online.target

[Service]
Type=simple
EnvironmentFile=%h/.openclaw/residential-proxy.env
ExecStart=/usr/local/bin/gost -L socks5://:1080 -F "socks5://${IPROYAL_USER}:${IPROYAL_PASS}@${IPROYAL_HOST}:${IPROYAL_PORT}"
Restart=always
RestartSec=10
OnFailure=residential-proxy-alert.service

[Install]
WantedBy=default.target
```

**Alert unit** (`~/.config/systemd/user/residential-proxy-alert.service`): one-shot that `curl -X POST` to a Slack webhook with the failure details.

## Rollout plan

1. Sign up for IPRoyal Static Residential (1 IP, 1 month to start)
2. Locally verify the tunnel works from Shawn's Mac (curl through it, confirm residential IP returned)
3. Install gost + unit + env on neb-server first (lower impact since it's more actively used)
4. Verify on neb: `curl --socks5 127.0.0.1:1080 https://api.ipify.org` returns IPRoyal IP
5. Run `codex_reauth_server.py --dry-run` on neb, confirm the log shows `SOCKS proxy detected on :1080` and the full flow completes
6. Replicate on cliqk-server (openclaw alias)
7. Wait for a natural 10-day re-auth on either server to validate end-to-end in production
8. If either server fails, fall back to Mac tunnel per the Fallback section

## Testing

- **Unit-level:** gost binary health check via `curl --socks5 ... api.ipify.org`
- **Integration:** `codex_reauth_server.py --dry-run` with the tunnel up; confirm the log reaches `tokens acquired` line
- **End-to-end:** live 10-day re-auth on each server. Success criteria: tokens get written, gateway restarts, no Slack alert
- **Failure injection:** stop the systemd unit manually, trigger a reauth, confirm Slack alert fires and the reauth logs show the expected warning

## Security considerations

- IPRoyal credentials never leave the server filesystem or Shawn's `.env`
- `residential-proxy.env` is mode 600, owned by `ubuntu`
- gost listens only on `127.0.0.1`, never exposed externally
- No new inbound surface area; the only outbound connection is the SOCKS5 handshake to IPRoyal
- Slack webhook URLs treated as secrets, stored in the same env file

## Cost

- IPRoyal Static Residential: approximately $7/month for one dedicated IP
- Zero additional compute cost (gost is negligible memory/CPU)
- No hardware purchase

## Open questions

None for the spec. Provider (IPRoyal), topology (one shared IP), alerting (Slack), and rollout order (NEB first) are all decided.
