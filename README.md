# OpenClaw OAuth Manager

OpenClaw OAuth Manager is a generic, open-source toolkit for keeping OpenClaw servers authenticated. It monitors token expiry, attempts API-level refresh where supported, coordinates token sharing across a fleet of servers via S3, and falls back to headless browser recovery when all else fails. It supports Claude (Anthropic), ChatGPT (OpenAI), Gemini (Google), and Perplexity.

## Supported Providers

| Provider | API Refresh | Headless Recovery | Token TTL |
|----------|------------|-------------------|-----------|
| Claude (Anthropic) | Yes | Magic link (Gmail API) | ~10 days |
| ChatGPT (OpenAI) | No | Google Sign-In | Session-based |
| Gemini (Google) | Yes | Google Sign-In | ~60 min |
| Perplexity | No (API key only) | N/A | Never expires |

## Quick Start

```bash
pip install -r requirements.txt
python3 configure.py
python3 oauth_manager.py check
```

## Server Roles

- **standalone** — manages its own tokens independently; no coordination with other servers.
- **authority** — holds the canonical token, refreshes it, and pushes it to S3 for receivers to pull.
- **receiver** — pulls tokens from S3 published by an authority; does not perform its own recovery.

## Recovery Layers

1. **API Refresh** — use the provider's token refresh endpoint if supported (Claude, Gemini).
2. **S3 Pull** — if this server is a receiver, pull a fresh token from S3 uploaded by the authority.
3. **S3 Push** — if this server is the authority and holds a valid token, push it to S3.
4. **Headless Recovery** — launch real Chrome via CDP, log in through the provider's web UI, and capture fresh tokens.

## Residential Proxy (Webshare)

Datacenter / server IPs get provider sign-in blocked and the verification email suppressed, so headless recovery fails from a server. Routing the headless Chrome login through a **Webshare residential proxy** makes provider sign-in (Claude, ChatGPT, Gemini, Perplexity) behave like a normal home connection. This replaces the retired IPRoyal `gost` SOCKS5 residential proxy (decommissioned 2026-05-26).

The proxy is provider-agnostic: it attaches once at Chrome launch (`launch_chrome_cdp`), so all flows route through it.

Two auth modes (set via config):

- **`ip_auth` (default, recommended)** — Chrome points directly at the Webshare endpoint (`http://p.webshare.io:80`) with **no credentials on disk**. You whitelist the server's egress IP in the Webshare dashboard (Proxy → IP Authorization).
- **`userpass`** — a tiny pure-stdlib forwarder (`proxy_forwarder.py`) binds **127.0.0.1 only**, injects `Proxy-Authorization: Basic …` toward Webshare, and Chrome points at `127.0.0.1:<local_forwarder_port>`. Use this when you can't whitelist a static IP. Chrome's `--proxy-server` cannot carry `user:pass@` inline, which is why the forwarder exists. Credentials live only in the gitignored `config.json`.

Config block (secrets only in `config.json`, never `config.example.json`):

```json
  "proxy": {
    "enabled": false,
    "mode": "ip_auth",
    "endpoint": "p.webshare.io:80",
    "username": "",
    "password": "",
    "local_forwarder_port": 1080
  }
```

**Loopback bypass (automatic):** the OAuth callback is served on `localhost:<callback_port>` (default 19876). Whenever the proxy is enabled, Chrome is launched with `--proxy-bypass-list=localhost;127.0.0.1;[::1];<-loopback>` so the callback is **never** routed through the residential proxy — otherwise the callback never arrives and every flow fails. You don't have to configure this; it's added for you.

Set it up interactively:

```bash
python3 configure.py --reconfigure proxy
```

See `docs/DEPLOY-webshare-proxy.md` for the full IP-whitelist runbook (and an important caveat about live OpenAI sign-in).

## Commands

```bash
python3 oauth_manager.py check             # Check token validity and refresh if needed
python3 oauth_manager.py refresh           # Force a refresh attempt
python3 oauth_manager.py recover           # Force headless browser recovery
python3 oauth_manager.py status            # Print current token status
```

All commands accept `--config <path>` to point at a non-default config file.

## Automated Scheduling

Run `python3 configure.py` to generate a cron job (Linux) or launchd plist (macOS) that calls `oauth_manager.py check` on the interval defined by `check_interval_minutes` in your config.

## Gmail API Setup

Gmail API credentials are required for Claude magic-link recovery. Run the setup script to authorize access and store a refresh token:

```bash
python3 setup_gmail.py
```

Follow the prompts to complete the OAuth flow. Credentials are saved into the `gmail` section of your config.

## Configuration

Copy `config.example.json` to `config.json` and fill in the fields for your provider, credentials, and optional S3/Slack settings.

To reconfigure a specific section interactively:

```bash
python3 configure.py --reconfigure s3
python3 configure.py --reconfigure gmail
python3 configure.py --reconfigure slack
python3 configure.py --reconfigure proxy
```

See `config.example.json` for all available fields and their defaults.

## License

MIT
