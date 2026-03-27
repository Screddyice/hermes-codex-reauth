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
```

See `config.example.json` for all available fields and their defaults.

## License

MIT
