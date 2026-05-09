# openclaw-codex-reauth

Headless, unattended re-authentication for OpenAI Codex CLI OAuth on remote servers (OpenClaw fleet or any server running `codex`).

When Codex's refresh-token chain breaks (OpenAI rotates / expires the refresh token roughly every 10 days), Codex stops working until a human opens a browser and logs back in. This project automates that re-login on each server so the loop self-heals with no operator involvement.

## Architecture

Each server runs two things on a schedule:

1. **Watchdog** (`codex_watchdog.py`, cron every 3h): cheap check on token TTL. If the access token is still healthy, exit. If it's near expiry, try an API refresh. If the refresh chain is broken (`invalid_grant`), escalate to the recovery flow. (Older docs and the script's docstring suggested 15 min — 3h is the production-tuned cadence with the recovery escalation in place; brief downtime up to one tick is acceptable because the recovery auto-heals it.)

2. **Recovery** (`codex_reauth_server.py`, invoked by the watchdog on escalation): launches a real Chrome over CDP, walks the OpenAI auth URL, submits the configured email, waits for OpenAI's verification email to arrive in Gmail (via read-only Gmail API), extracts the magic link or 6-digit code, completes the login, catches the auth callback on localhost, exchanges the code for fresh tokens, writes them into the server's `auth-profiles.json`, and restarts the OpenClaw gateway.

A Mac-side companion script (`codex_reauth_mac.py`) runs the same flow from a real desktop browser and pushes fresh tokens to servers via SSH. Used as a manual tier-2 fallback when the headless server flow fails.

### Dual-write to Codex CLI 0.128.0+

Codex CLI 0.128.0 introduced a dedicated token store at `~/.codex/auth.json` (richer schema with `tokens.id_token`, `tokens.account_id`, `auth_mode`, `last_refresh`). Both the `codex` CLI itself and OpenClaw consume the same OAuth tokens but read them from different files.

To keep both stores in lock-step, every refresh and every fresh login writes to **both**:

- OpenClaw's `auth-profiles.json` (and `oauth-token-cache.json`)
- Codex CLI's `~/.codex/auth.json` (merged — non-token fields like `auth_mode` are preserved; missing `id_token` on a refresh response keeps the existing one)

The watchdog also reads from `~/.codex/auth.json` as a fallback if OpenClaw's profile is missing — useful for hosts where `codex login` was run directly (or tokens were pushed there from a Mac) before OpenClaw was configured.

## The datacenter-IP problem

OpenAI's login page silently rejects new-device attempts from datacenter IPs (AWS, GCP, Azure, etc.) by suppressing email delivery. The headless server flow only works when the server's outbound traffic appears to come from a residential IP.

Two supported patterns:

- **Reverse SSH SOCKS tunnel from a home device** (the original Mac-based approach — see `socks_proxy.py`). The server's Chrome launches with `--proxy-server=socks5://127.0.0.1:1080` and exits through a trusted residential connection.
- **Static residential proxy service** (recommended for fully unattended operation). A static residential IP (e.g., via IPRoyal) is reachable from both servers via a small `gost` sidecar on `127.0.0.1:1080`. Same code path, no home device required. Covered in `docs/specs/2026-04-23-residential-proxy-codex-reauth-design.md`.

Either way, `codex_reauth_server.py` auto-detects a SOCKS proxy on `127.0.0.1:1080` and uses it.

## Quick start

```bash
# 1. On each server
git clone https://github.com/Screddyice/openclaw-codex-reauth.git ~/codex-reauth
cd ~/codex-reauth
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
playwright install chromium

# 2. Copy the example configs and fill them in
cp config.server.example.json config.server.json
#   edit: openai_email, chrome_path, systemd unit names

# 3. Seed a Gmail OAuth credential that can read the inbox that receives
#    OpenAI's verification emails. Store as ~/.openclaw/gmail-oauth-credentials.json:
#      { "client_id", "client_secret", "refresh_token", "token_uri", "email" }

# 4. Install the watchdog on a 3h cron (recovery escalation handles brief downtime)
crontab -l 2>/dev/null | { cat; echo "0 */3 * * * $HOME/codex-reauth/venv/bin/python $HOME/codex-reauth/codex_watchdog.py >> $HOME/.openclaw-oauth/watchdog.log 2>&1"; } | crontab -

# 5. Bring up a residential exit (one of the two patterns above) so the
#    recovery flow has a non-datacenter IP to use.
```

### Bring-up validation checklist

Before declaring a new server "self-healing," verify all of these. If any fail, the watchdog will eventually go silent on the first refresh-chain break — and you'll find out when an agent stops responding:

```bash
# 1. Binaries on PATH
which google-chrome-stable Xvfb gost
# 2. Credentials in place
ls ~/.openclaw/gmail-oauth-credentials.json ~/.openclaw/residential-proxy.env
# 3. Residential proxy systemd unit running
systemctl --user is-active residential-proxy.service
# 4. Watchdog cron present
crontab -l | grep codex_watchdog.py
# 5. End-to-end smoke test: real OAuth via Chrome+Xvfb+Gmail+residential proxy
~/codex-reauth/venv/bin/python ~/codex-reauth/codex_reauth_server.py
#    Expect ~25s runtime; final lines should be:
#      "wrote N auth-profiles.json files + oauth-token-cache.json + codex-cli-native=yes"
#      "restarted openclaw-gateway"
```

If you hand-seeded `~/.openclaw/auth-profiles.json` from `oauth-token-cache.json` rather than letting `codex_reauth_server.py` create it, double-check that `lastGood` is a **dict** keyed by provider, not a bare string:

```json
"lastGood": { "openai-codex": "openai-codex:codex-cli" }
```

`auth_profiles.write_tokens()` normalizes a string lastGood defensively (so the headless flow no longer crashes on the first run), but the canonical shape is still the dict form.

## Files

| File | Purpose |
|---|---|
| `codex_watchdog.py` | 15-min scheduled entrypoint; API refresh or escalate |
| `codex_reauth_server.py` | Headless recovery flow (server side) |
| `codex_reauth_mac.py` | Manual recovery from a real Mac; pushes tokens to servers via SSH |
| `codex_oauth.py` | Codex OAuth client (authorize URL, token exchange, refresh) |
| `auth_profiles.py` | Read/write `auth-profiles.json` (OpenClaw's token store) |
| `gmail_reader.py` | Read-only Gmail API helper for catching OpenAI verification emails |
| `socks_proxy.py` | Minimal SOCKS5 server for the reverse-tunnel pattern |
| `one_shot_reauth.py` | Operator-invoked variant for one-off auth captures |
| `config.server.example.json` | Template for server-side config |
| `config.mac.example.json` | Template for Mac-side config |
| `docs/specs/` | Design documents for major changes |

## Status

Production on two servers (NEB / Cliqk). API-level refresh is reliable. Headless recovery is reliable when a residential exit is available; see `docs/specs/2026-04-23-residential-proxy-codex-reauth-design.md` for the current work to make the residential exit always-available.

## License

MIT
