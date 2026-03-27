# OpenClaw OAuth Manager — Design Spec

## Overview

A generic, open-source toolkit for keeping OpenClaw servers authenticated. Handles the full token lifecycle: API refresh, multi-server distribution, failure detection, and headless browser recovery as a last resort.

Works for single-server setups (standalone) or multi-server fleets (authority + receivers).

## Goals

- **Generic**: No hardcoded server names, IPs, or org-specific config. Everything is user-configured.
- **Layered recovery**: Each layer escalates to the next only when the previous fails.
- **Interactive setup**: A guided wizard (`python3 configure.py`) walks new users through configuration.
- **Self-contained**: One repo, one config file, one entry point.

## Non-Goals

- Managing OpenClaw installation itself (assumes OpenClaw is already installed)
- Web UI or dashboard

---

## Architecture

### Recovery Layers

Executed in order. Each layer only fires if the previous one didn't resolve the issue.

| Layer | What it does | When it runs |
|-------|-------------|--------------|
| 1. **API Refresh** | Use refresh token to get new access token via provider OAuth endpoint | Token below threshold. Claude and Gemini only — ChatGPT has no API refresh flow. |
| 2. **S3 Pull** | Download fresher token from shared S3 bucket | Multi-server only. Local token expired or stale vs S3 |
| 3. **S3 Push** | Authority pushes fresh tokens to S3 + remotes via SSH | Authority role only. After successful refresh |
| 4. **Headless Recovery** | Launch real Chrome, log in via browser, extract fresh tokens | All other layers failed. Works for all providers. Rate-limited (cooldown persisted to `~/.openclaw-oauth/last-headless-attempt`). |

### Server Roles

Configured in `config.json` via `"role"` field:

| Role | Behavior |
|------|----------|
| `standalone` | Refreshes its own tokens. No distribution. Falls back to headless recovery. |
| `authority` | Refreshes tokens and distributes to S3 + remote servers. Falls back to headless recovery. |
| `receiver` | Pulls from S3. Opportunistically attempts API self-refresh if it has a refresh token (receivers may or may not have one depending on how tokens were distributed). Falls back to headless recovery. |

### Unified Health Loop

One entry point replaces the previous separate cron jobs (watchdog, selfheal, authority refresh, S3 pull):

```
python3 oauth_manager.py check
```

Flow:
1. Read all local `auth-profiles.json` files (see Auth Profiles section below)
2. Find the best (longest-lived) token for the configured provider
3. If token is healthy (above threshold) and role is not authority: exit
4. If role is authority: also probe remote servers, push if any are stale
5. If token is below threshold or expired: run recovery layers in order
6. Log result, send Slack notification on failure (if configured)

All commands accept `--config /path/to/config.json` to override the default config location.

### Entry Points

```bash
python3 configure.py                          # Interactive setup wizard
python3 oauth_manager.py check                # Run health check + recovery (cron target)
python3 oauth_manager.py refresh              # Force API refresh
python3 oauth_manager.py recover              # Force headless browser recovery
python3 oauth_manager.py status               # Print token health for all local profiles
python3 oauth_manager.py --config /path.json  # Use custom config path
python3 configure.py --reconfigure gmail      # Reconfigure just the Gmail section
```

---

## Auth Profiles (`auth-profiles.json`)

OpenClaw stores credentials in JSON files at known locations:

### File Locations (glob pattern)

```
~/.openclaw/auth-profiles.json
~/.openclaw/agents/*/agent/auth-profiles.json
```

All matching files are scanned for tokens and updated when new tokens are written.

### File Schema

```json
{
  "profiles": {
    "<profile-key>": {
      "type": "oauth",
      "provider": "<provider-name>",
      "access": "<access-token>",
      "refresh": "<refresh-token>",
      "expires": 1711900000000,
      "scopes": ["user:inference", "user:profile"],
      "subscriptionType": "max",
      "rateLimitTier": "default_claude_max_20x"
    }
  },
  "lastGood": {
    "<provider-name>": "<profile-key>"
  }
}
```

### Profile Keys by Provider

| Provider | Profile Key | Provider Name |
|----------|------------|---------------|
| `claude` | `openai-codex:codex-cli` | `openai-codex` |
| `chatgpt` | `openai:oauth` | `openai` |
| `gemini` | `google-gemini:oauth` | `google-gemini` |
| `perplexity` | `perplexity:api_key` | `perplexity` |

`expires` is Unix epoch in **milliseconds** (not applicable to Perplexity — API keys don't expire). When writing tokens, also set `lastGood[provider_name] = profile_key` and remove any stale `<provider>:api_key` entries from `profiles`.

**Gemini token storage note:** Gemini CLI natively stores tokens in the OS keychain (macOS Keychain / Linux libsecret), not in `auth-profiles.json`. This tool writes Gemini tokens to `auth-profiles.json` for consistency with the distribution system, and optionally syncs to the keychain if `keytar` is available. Set `FORCE_ENCRYPTED_FILE=1` on the Gemini CLI to use file-based storage instead of keychain.

### S3 Token Format

Tokens stored in S3 use the same schema, wrapped in a version envelope:

```json
{
  "version": 1,
  "profiles": {
    "<profile-key>": { ... same oauth object ... }
  }
}
```

S3 PutObject is atomic — no locking needed. Receivers compare `expires` timestamps to decide whether S3 is fresher than local (via `should_update_from_s3()`).

S3 uses default server-side encryption (SSE-S3). Users who need KMS encryption can configure their S3 bucket policy independently.

---

## File Structure

```
openclaw-oauth/
├── oauth_manager.py          # Unified entry point: check, refresh, recover, status
├── token_refresh.py          # API-based token refresh (provider-agnostic)
├── token_distribute.py       # S3 upload/download + SSH push to remotes
├── token_logic.py            # Pure decision functions (no I/O, fully tested)
├── headless_reauth.py        # Chrome CDP headless browser recovery (existing, adapted)
├── configure.py              # Interactive setup wizard + --reconfigure
├── setup_gmail.py            # Gmail OAuth setup helper (existing)
├── test_token_logic.py       # Unit tests for decision logic
├── config.example.json       # Annotated template config
├── requirements.txt          # Python dependencies
├── .gitignore
├── LICENSE                   # MIT
├── README.md                 # Updated: covers full system
└── docs/
    └── this spec
```

---

## Setup Wizard (`configure.py`)

Interactive, step-by-step configuration. Detects environment and pre-fills defaults.

### Flow

```
Step 1: Environment Detection (automatic)
  - OS (macOS / Linux)
  - Chrome location (auto-detect common paths)
  - Existing OpenClaw install (~/.openclaw/)
  - Python version, installed packages

Step 2: Server Role
  "How are you using this?"
  [1] Single server (standalone)
  [2] Multiple servers — this is the authority (refreshes + distributes)
  [3] Multiple servers — this is a receiver (pulls from authority)

Step 3: Provider
  "Which AI provider does this server use?"
  [1] Claude.ai (Anthropic)
  [2] ChatGPT (OpenAI)
  [3] Gemini (Google)
  [4] Perplexity

Step 4: Server Credentials
  If Perplexity:
    "Perplexity API key (pplx-...):"
    (No further auth setup needed — API key only)
  Else (for headless recovery):
    "Login email for <provider>:"
    "Password:" (ChatGPT and Gemini — for Google Sign-In)
    Note: Claude uses magic link login (no password needed, uses Gmail API)

Step 5: Distribution (authority/receiver only)
  "S3 bucket for token sharing:"
  "S3 key prefix (default: oauth/):"
  "AWS region (default: us-east-2):"

Step 6: Remote Servers (authority only)
  "Add remote servers to push tokens to."
  For each: "Server name:" / "SSH host:" / "SSH user (default: ubuntu):" /
            "SSH key path (default: ~/.ssh/id_ed25519):" /
            "EC2 instance ID (optional):" /
            "Provider for this server (default: same as authority):" /
            "Login email (for headless recovery on this server):" /
            "Add another? (y/n)"

Step 7: Headless Recovery
  "Enable headless browser recovery as a fallback? (y/n)"
  If yes:
    - Confirms Chrome path (auto-detected)
    - "Do you want to set up Gmail API for magic link login? (y/n)"
    - If yes: runs setup_gmail.py flow inline

Step 8: Notifications (optional)
  "Send Slack alerts on failure? (y/n)"
  If yes: "Slack bot token:" / "Channel or user ID:"

Step 9: Schedule
  "Set up automatic health checks? (y/n)"
  If yes:
    - Detects OS
    - macOS: generates launchd plist, offers to install
    - Linux: generates cron entry or systemd timer, offers to install
    - "Check interval in minutes (default: 15):"

Step 10: Install Dependencies
  "Install required Python packages? (y/n)"
  If yes: runs pip install for playwright, boto3, etc.
  Only installs what's needed based on config (e.g., skip boto3 if no S3)

Step 11: Validate
  - Tests SSH connectivity to remotes (if configured)
  - Tests S3 access (if configured)
  - Tests Gmail API (if configured)
  - Runs a dry health check
  - Prints summary

Step 12: Write config.json
  - Writes config to ./config.json (or user-specified path)
  - Sets file permissions to 600 (contains secrets)
  - Prints "Setup complete. Run: python3 oauth_manager.py check"
```

### Reconfigure

```bash
python3 configure.py --reconfigure <section>
```

Supported sections: `role`, `provider`, `credentials`, `distribution`, `servers`, `gmail`, `slack`, `schedule`, `all`

Re-runs only that section of the wizard, merges changes into existing config.json.

---

## Config Schema

```json
{
  "role": "standalone | authority | receiver",
  "provider": "claude | chatgpt | gemini | perplexity",
  "email": "login@example.com",
  "password": "",
  "api_key": "",
  "check_interval_minutes": 15,
  "refresh_threshold_hours": 4,
  "_comment_refresh_threshold": "Set to 0.5 for Gemini (60-min token TTL)",
  "headless_recovery_cooldown_minutes": 30,
  "headless_enabled": true,
  "chrome_path": "/auto/detected/path",
  "callback_port": 19876,
  "screenshot_dir": "~/.openclaw-oauth/screenshots",
  "browser_profile_dir": "~/.openclaw-oauth/browser-profiles",
  "servers": {
    "REMOTE_1": {
      "hostname": "ssh-alias-or-ip",
      "ssh_key": "~/.ssh/id_ed25519",
      "ssh_user": "ubuntu",
      "instance_id": "",
      "provider": "claude",
      "email": "remote-login@example.com",
      "password": ""
    }
  },
  "s3": {
    "bucket": "",
    "key": "oauth/tokens.json",
    "region": "us-east-2"
  },
  "gmail": {
    "default": {
      "client_id": "",
      "client_secret": "",
      "refresh_token": "",
      "token_uri": "https://oauth2.googleapis.com/token",
      "email": ""
    }
  },
  "slack": {
    "bot_token": "",
    "channel": ""
  }
}
```

**Notes:**
- Top-level `email`/`password` are for this server's headless recovery login
- Per-server `email`/`password` are for headless recovery on remote servers (authority pushing)
- Per-server `provider` allows mixed-provider fleets (some servers on Claude, some on ChatGPT)
- `password` is used for ChatGPT and Gemini (both use Google Sign-In). Empty string for Claude (uses magic link via Gmail API)
- `api_key` is only used for Perplexity (`pplx-...`). For Perplexity, no OAuth/headless recovery is needed — the key is written directly to the auth profile

---

## Module Design

### `oauth_manager.py` — Unified Entry Point

Commands:
- `check` — health check + layered recovery (cron target)
- `refresh` — force API token refresh
- `recover` — force headless browser recovery
- `status` — print token health summary

All commands accept `--config <path>` to specify a non-default config file.

Orchestrates the other modules. Reads config, determines role, executes appropriate layers.

### `token_refresh.py` — API Token Refresh

Provider-agnostic refresh. Takes a provider name and refresh token, returns new tokens.

```python
def refresh_token(provider: str, refresh_token: str) -> dict:
    """Call provider's OAuth endpoint. Returns {access, refresh, expires, ...}.

    Raises:
      TokenRefreshError — base class for all refresh failures
      InvalidGrantError(TokenRefreshError) — refresh token revoked/consumed (HTTP 400 with invalid_grant)
      ProviderUnavailableError(TokenRefreshError) — provider returned 5xx or timed out

    oauth_manager uses the exception type to decide next steps:
      InvalidGrantError → skip to Layer 4 (headless recovery), no point retrying API
      ProviderUnavailableError → retry once, then skip to Layer 4
    """

def find_best_token(paths: list[str], provider_profile: str) -> dict | None:
    """Scan auth-profiles.json files, return the token with longest remaining life."""

def write_tokens(paths: list[str], provider_profile: str, oauth: dict) -> int:
    """Write new token to all local auth-profiles.json files. Returns count updated.
    Also cleans up stale api_key entries and sets lastGood."""

def get_profile_key(provider: str) -> str:
    """Return the profile key for a provider. e.g., 'claude' -> 'openai-codex:codex-cli'."""

def get_auth_profile_paths() -> list[str]:
    """Glob for all auth-profiles.json files in standard OpenClaw locations."""
```

Provider constants (endpoints, client IDs, profile keys) are internal to this module, selected by `provider` config value.

**Provider-specific notes:**
- **Claude**: Supports both API refresh (~10-day token TTL) and headless recovery (magic link login via Gmail API). API refresh is preferred; headless is the fallback.
- **ChatGPT**: No API refresh flow — tokens are session-based (extracted from browser cookies/session API). Layer 1 is skipped; recovery is always via headless browser login (Google Sign-In). `refresh_token()` raises `UnsupportedProviderError`.
- **Gemini**: Supports API refresh via standard Google OAuth2 (`oauth2.googleapis.com/token`), but access tokens expire in ~60 minutes (much shorter than Claude). Known Gemini CLI bug causes refresh tokens to be wiped on save — this tool works around it by managing tokens externally. Headless recovery uses Google Sign-In (same flow as ChatGPT). The `refresh_threshold_hours` should be set lower for Gemini (recommended: `0.5` i.e. 30 minutes).
- **Perplexity**: API key only (`pplx-...`). No OAuth, no token expiration, no refresh, no headless recovery. The `check` command verifies the key is present in the auth profile and optionally validates it with a test API call. All recovery layers are skipped. Distribution (S3/SSH) still works for propagating the key to other servers.

### `token_distribute.py` — S3 + SSH Distribution

```python
def upload_to_s3(oauth: dict, provider_profile: str, config: dict) -> bool:
    """Upload token to S3 bucket in versioned envelope format."""

def download_from_s3(config: dict, provider_profile: str) -> dict | None:
    """Download token from S3. Returns oauth dict or None on failure."""

def push_to_remote(server_name: str, server_config: dict, oauth: dict, provider_profile: str) -> bool:
    """SSH into remote, write token to all auth-profiles.json files.

    Uses server_config['ssh_user'], ['ssh_key'], ['hostname'].
    If instance_id is set, pushes EC2 Instance Connect SSH key first.
    SCPs a temp file + inline Python script (same pattern as existing headless_reauth.py)."""

def probe_remote_health(server_name: str, server_config: dict, provider_profile: str) -> float:
    """SSH into remote, return hours remaining on best token. Returns -999 on connection failure."""
```

### `token_logic.py` — Pure Decision Functions (existing)

No I/O. Fully tested. Ported from `token_pull_logic.py` with provider references generalized.

```python
def should_self_refresh(local_expires, s3_expires, last_attempt, now, cooldown_ms) -> bool:
    """Whether to attempt API self-refresh. Rate-limited by cooldown_ms."""

def needs_profile_cleanup(profile: dict, provider_profile: str) -> bool:
    """Whether auth-profiles.json needs stale entries removed."""

def should_update_from_s3(s3_expires, local_expires, now) -> bool:
    """Whether local token should be replaced with S3 token (S3 is fresher and valid)."""

def token_health(expires_ms: int, now_ms: int) -> str:
    """Returns 'OK', 'LOW', 'CRITICAL', 'EXPIRED', or 'NO_TOKEN'."""

def should_headless_recover(last_attempt_ms: int, now_ms: int, cooldown_ms: int) -> bool:
    """Whether headless recovery is allowed (outside cooldown window)."""
```

### `headless_reauth.py` — Headless Browser Recovery (existing, adapted)

The existing 1114-line file stays mostly intact. Changes:
- Remove hardcoded config paths — accept config dict from oauth_manager
- Make it callable as a module (`recover_server(server_name, config)`) in addition to CLI
- Keep CLI interface (`--server`, `--all`, `--dry-run`, `--config`) for standalone use
- Add Gemini login flow (Google Sign-In + OAuth code exchange with Gemini-specific scopes and client credentials). Shares the Google Sign-In automation with the existing ChatGPT flow.
- All three providers (Claude, ChatGPT, Gemini) support headless recovery

### `configure.py` — Interactive Setup Wizard

New file. Handles the full onboarding flow described above.
- Environment detection (OS, Chrome, OpenClaw, Python packages)
- Step-by-step prompts with sensible defaults
- Dependency installation (`pip install` only what's needed)
- Connectivity validation
- Config file generation
- `--reconfigure <section>` for partial updates

### `setup_gmail.py` — Gmail OAuth Helper (existing)

No changes. Called by configure.py during the Gmail configuration step, or used standalone.

---

## Provider Constants

Baked into `token_refresh.py`, selected by config `"provider"` value:

| Provider | Profile Key | Provider Name | Client ID | Token URL | Token TTL | API Refresh? | Headless Login |
|----------|------------|---------------|-----------|-----------|-----------|--------------|----------------|
| `claude` | `openai-codex:codex-cli` | `openai-codex` | `9d1c250a-e61b-44d9-88ed-5944d1962f5e` | `https://platform.claude.com/v1/oauth/token` | ~10 days | Yes | Magic link (Gmail API) |
| `chatgpt` | `openai:oauth` | `openai` | N/A | N/A | Session-based | No | Google Sign-In |
| `gemini` | `google-gemini:oauth` | `google-gemini` | Extracted from `@google/gemini-cli` npm package | `https://oauth2.googleapis.com/token` | ~60 min | Yes | Google Sign-In |
| `perplexity` | `perplexity:api_key` | `perplexity` | N/A | N/A | Never expires | No | N/A — API key only |

Users don't need to know or configure these — just pick their provider.

**Headless login flows:**
- **Claude**: Navigate to claude.ai OAuth URL, enter email, poll Gmail for magic link, follow link, capture auth code via local callback server, exchange for tokens (PKCE flow).
- **ChatGPT**: Navigate to chatgpt.com, click "Log in" > "Continue with Google", enter Google email + password, extract session token from session API.
- **Gemini**: Navigate to Google OAuth authorize URL with Gemini scopes, enter Google email + password, capture auth code via local callback, exchange for tokens. Reuses the same Google Sign-In automation as ChatGPT.

**Gemini client credentials:** The client ID and secret are hardcoded in the `@google/gemini-cli` npm package source (`oauth2.ts`). This tool extracts them at runtime from the installed package, or falls back to well-known values. Google treats installed-app client secrets as non-confidential per their OAuth documentation.

---

## Cooldown State Persistence

Cooldown timestamps are persisted as files so they survive across cron invocations:

| File | Purpose |
|------|---------|
| `~/.openclaw-oauth/last-headless-attempt` | Unix timestamp (ms) of last headless recovery attempt |
| `~/.openclaw-oauth/last-self-refresh-attempt` | Unix timestamp (ms) of last API self-refresh attempt (receivers) |

`token_logic.py` decision functions accept these timestamps as parameters. `oauth_manager.py` reads/writes the files.

---

## Logging

All modules log to `~/.openclaw-oauth/logs/`:
- `oauth-manager.log` — main orchestration log
- `headless-recovery.log` — browser recovery details

Log rotation: each log file is capped at 500 lines. Before writing, if the file exceeds 500 lines, it is truncated to the last 200 lines (simple tail-and-replace, matching the existing bash scripts' pattern). No external rotation dependencies.

Log format: `[YYYY-MM-DDTHH:MM:SSZ] message`

---

## Testing

- `test_token_logic.py` — unit tests for all pure decision functions
- Run with: `python3 -m pytest test_token_logic.py -v`
- No integration tests in the open-source repo (would require AWS/Gmail credentials)

---

## Migration from Existing Scripts

Users of the old separate scripts (token-authority-refresh.sh, pull-fresh-tokens-from-s3.sh, token-failure-watchdog.sh) can migrate by:

1. Running `python3 configure.py` to generate config.json
2. Replacing all cron entries with a single: `*/15 * * * * python3 /path/to/oauth_manager.py check`
3. Removing the old shell scripts

The Python implementation covers all functionality of the old bash scripts with better error handling, testability, and a unified config.
