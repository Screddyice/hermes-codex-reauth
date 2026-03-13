# Headless OAuth Recovery

Automated OAuth token recovery for [OpenClaw](https://github.com/anthropics/claude-code) servers using headless browser automation. Bypasses Cloudflare Turnstile by launching real Chrome via CDP instead of Playwright's detectable Chromium.

## What It Does

When your OpenClaw server's OAuth tokens expire, this tool automatically:

1. Launches real Chrome (not Playwright's Chromium) to bypass Cloudflare bot detection
2. Navigates through the OAuth login flow (claude.ai or chatgpt.com)
3. Reads verification emails via Gmail API (for magic link login)
4. Exchanges the authorization code for fresh tokens
5. Pushes tokens to your remote server via SCP
6. Restarts the OpenClaw gateway

## Supported Providers

| Provider | Login Method | Verification |
|----------|-------------|--------------|
| **Claude.ai** (Anthropic) | Email + magic link | Gmail API polls for login link |
| **ChatGPT** (OpenAI) | Google Sign-In | Google OAuth (email + password) |

## Why Real Chrome?

Cloudflare Turnstile detects and blocks Playwright's Chromium browser because Playwright injects `--enable-automation` and other automation flags. This tool launches your system's real Chrome via `subprocess` and connects to it via Chrome DevTools Protocol (CDP). Chrome runs as a completely normal browser — no automation flags, no detection.

## Prerequisites

- **Python 3.8+**
- **Google Chrome** installed on the machine running the script
- **Playwright** (`pip install playwright && playwright install chromium`)
- **SSH access** to your OpenClaw server(s)
- **Gmail API credentials** (optional, for magic link login flow)

## Quick Start

### 1. Install dependencies

```bash
pip install playwright
playwright install chromium  # Only needed for the Playwright library, not the browser
```

### 2. Configure

```bash
cp config.example.json config.json
# Edit config.json with your server details
```

### 3. Set up Gmail API (optional, for claude.ai magic link login)

```bash
python3 setup_gmail.py \
  --client-id YOUR_CLIENT_ID.apps.googleusercontent.com \
  --client-secret GOCSPX-YOUR_SECRET \
  --email you@example.com
```

See [Gmail Setup Guide](#gmail-api-setup) below for creating the Google Cloud credentials.

### 4. Run

```bash
# Reauth a specific server
python3 headless_reauth.py --server MY_SERVER

# Dry run (test without pushing tokens)
python3 headless_reauth.py --server MY_SERVER --dry-run

# Reauth all configured servers
python3 headless_reauth.py --all
```

## Configuration

`config.json` defines your servers, Gmail credentials, and Chrome path:

```json
{
  "servers": {
    "MY_SERVER": {
      "instance_id": "i-0123456789abcdef0",
      "hostname": "my-server-ssh-alias",
      "provider": "claude",
      "email": "you@example.com",
      "password": "your-password"
    }
  },
  "gmail": {
    "default": {
      "client_id": "YOUR_ID.apps.googleusercontent.com",
      "client_secret": "GOCSPX-YOUR_SECRET",
      "refresh_token": "1//YOUR_TOKEN",
      "token_uri": "https://oauth2.googleapis.com/token",
      "email": "you@example.com"
    }
  },
  "chrome_path": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "callback_port": 19876,
  "slack": {
    "bot_token": "xoxb-...",
    "user_id": "U..."
  }
}
```

### Server fields

| Field | Required | Description |
|-------|----------|-------------|
| `hostname` | Yes | SSH alias or hostname for the server |
| `provider` | Yes | `"claude"` or `"chatgpt"` |
| `email` | Yes | Login email for the provider |
| `password` | ChatGPT only | Google account password (for Google Sign-In) |
| `instance_id` | No | AWS EC2 instance ID (for EC2 Instance Connect SSH key push) |

### Multiple servers

You can configure as many servers as you need. Each gets its own browser profile, so Cloudflare clearance cookies are cached per-server.

## Automated Recovery (launchd / cron)

### macOS (launchd)

Create `~/Library/LaunchAgents/com.headless-oauth-recovery.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.headless-oauth-recovery</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/path/to/headless_reauth.py</string>
        <string>--all</string>
    </array>
    <key>StartInterval</key>
    <integer>1800</integer>
    <key>StandardOutPath</key>
    <string>/tmp/headless-oauth-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/headless-oauth-stderr.log</string>
</dict>
</plist>
```

Load it:
```bash
launchctl load ~/Library/LaunchAgents/com.headless-oauth-recovery.plist
```

### Linux (cron)

**Important:** Cloudflare blocks headless Chrome, so on Linux you need either:
- A display (X11/Wayland session), or
- A virtual framebuffer (`Xvfb`)

```bash
# With Xvfb
*/30 * * * * xvfb-run python3 /path/to/headless_reauth.py --all >> /var/log/headless-oauth.log 2>&1
```

## Gmail API Setup

To read magic link verification emails from Gmail:

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project (or use an existing one)
3. Enable the **Gmail API**: APIs & Services > Library > Gmail API > Enable
4. Configure **OAuth consent screen**: APIs & Services > OAuth consent screen
   - User type: External
   - Add your email as a test user
5. Create **OAuth client ID**: APIs & Services > Credentials > Create Credentials > OAuth client ID
   - Application type: **Desktop app**
   - Name: anything (e.g., "Headless OAuth Recovery")
6. Run the setup script with the client ID and secret

## How It Works

### Cloudflare Bypass

The key innovation: instead of using Playwright's `launch()` or `launch_persistent_context()`, we:

1. Launch Chrome directly via `subprocess.Popen()` with `--remote-debugging-port`
2. Connect Playwright via `chromium.connect_over_cdp()`

This means Chrome runs exactly like a normal browser — no `--enable-automation`, no automation flags, no Cloudflare detection.

### Claude.ai Flow

1. **Warmup**: Visit claude.ai homepage to cache Cloudflare clearance cookies
2. **OAuth**: Navigate to the OAuth authorize URL
3. **Login** (if needed): Enter email, poll Gmail for magic link, navigate to link
4. **Consent**: Click "Authorize" on the consent page
5. **Callback**: Receive the authorization code via local callback server
6. **Exchange**: Trade the code for access + refresh tokens (PKCE flow)
7. **Push**: SCP tokens to the server, run a Python script to inject into auth profiles
8. **Restart**: Restart the OpenClaw gateway service

### ChatGPT Flow

1. Navigate to chatgpt.com/auth/login
2. Click "Log in" > "Continue with Google"
3. Enter Google email and password
4. Wait for redirect back to ChatGPT
5. Extract access token from session API
6. Push tokens and restart gateway

## Troubleshooting

### Cloudflare still blocking

- Make sure you're using **real Chrome**, not Chromium. Check `chrome_path` in config.
- Run with `--headed` first to seed the browser profile with Cloudflare clearance cookies.
- The script always runs headed (Cloudflare blocks `--headless=new` too).

### Gmail polling finds nothing

- Check that Gmail API is enabled on your Google Cloud project.
- Verify your Gmail credentials with: `python3 setup_gmail.py --test`
- Make sure the email sender matches (noreply@anthropic.com).

### SSH push fails

- Verify you can `ssh your-server-alias` manually.
- If using EC2 Instance Connect, ensure the `instance_id` is correct.

## License

MIT
