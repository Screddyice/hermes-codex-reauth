#!/usr/bin/env python3
"""
headless-oauth-recovery — Automated OAuth token recovery via headless browser.

Bypasses Cloudflare Turnstile by launching real Chrome via CDP (Chrome DevTools
Protocol) instead of Playwright's automation-flagged Chromium.

Supports:
  - Claude.ai (Anthropic) — email + magic link login
  - ChatGPT (OpenAI) — Google Sign-In login

Usage:
  python3 headless_reauth.py --server MY_SERVER          # Reauth one server
  python3 headless_reauth.py --all                        # Reauth all servers
  python3 headless_reauth.py --server MY_SERVER --dry-run # Test without pushing tokens
  python3 headless_reauth.py --server MY_SERVER --headed  # Visible browser for debugging
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import random
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

# Add this directory to path for gmail_code_reader import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# === Claude.ai OAuth Constants ===
CLAUDE_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
CLAUDE_TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
CLAUDE_AUTHORIZE_URL = "https://claude.ai/oauth/authorize"
CLAUDE_REDIRECT_URI = "http://localhost:{port}/callback"
CLAUDE_SCOPES = "user:inference user:profile"

# === Gemini OAuth Constants ===
GEMINI_TOKEN_URL = "https://oauth2.googleapis.com/token"
GEMINI_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/auth"
GEMINI_SCOPES = "https://www.googleapis.com/auth/cloud-platform openid email"
GEMINI_REDIRECT_URI = "http://localhost:{port}/callback"

MAX_ATTEMPTS = 2


def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")


def recover_server(server_name: str, config: dict, dry_run: bool = False) -> bool:
    """Module-callable entry point for headless recovery of a single server.
    Called by oauth_manager.py. Returns True on success."""
    global _config
    _config = config
    try:
        result = run_reauth_for_server(server_name, headed=False, dry_run=dry_run)
        return result.get("success", False)
    except Exception as e:
        log(f"[{server_name}] Recovery failed: {e}")
        return False


def recover_all(config: dict, dry_run: bool = False) -> bool:
    """Recover the local server. Called by oauth_manager.py."""
    global _config
    _config = config
    servers = config.get("servers", {})
    # For standalone/receiver, use "local" as the server name
    if not servers:
        # Create a synthetic "local" server entry from top-level config
        _config.setdefault("servers", {})["local"] = {
            "hostname": "localhost",
            "provider": config.get("provider", "claude"),
            "email": config.get("email", ""),
            "password": config.get("password", ""),
        }
        server_name = "local"
    else:
        server_name = list(servers.keys())[0]
    try:
        result = run_reauth_for_server(server_name, headed=False, dry_run=dry_run)
        return result.get("success", False)
    except Exception as e:
        log(f"Recovery failed: {e}")
        return False


# ============================================================
# Configuration
# ============================================================

def load_config(config_path=None):
    """Load configuration from JSON file."""
    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            return json.load(f)

    # Search common locations
    search_paths = [
        os.path.join(os.path.dirname(__file__), "config.json"),
        os.path.expanduser("~/.headless-oauth/config.json"),
        os.path.expanduser("~/.openclaw/headless-oauth-config.json"),
    ]
    for path in search_paths:
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)

    raise RuntimeError(
        "No config.json found. Copy config.example.json to config.json and fill in your values.\n"
        f"Searched: {', '.join(search_paths)}"
    )


_config = None


def get_config(config_path=None):
    global _config
    if _config is None:
        _config = load_config(config_path)
    return _config


def get_servers():
    return get_config().get("servers", {})


def get_server(name):
    servers = get_servers()
    if name not in servers:
        raise RuntimeError(f"Server '{name}' not found. Available: {list(servers.keys())}")
    return servers[name]


def get_chrome_path():
    cfg = get_config()
    path = cfg.get("chrome_path", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    if not os.path.exists(path):
        # Try common Linux paths
        for p in ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium-browser"]:
            if os.path.exists(p):
                return p
        raise RuntimeError(f"Chrome not found at {path}. Set 'chrome_path' in config.json.")
    return path


def get_callback_port():
    return get_config().get("callback_port", 19876)


def get_screenshot_dir():
    d = os.path.expanduser(get_config().get("screenshot_dir", "~/.headless-oauth/screenshots"))
    os.makedirs(d, exist_ok=True)
    return d


def get_browser_profile_dir(server_name):
    base = os.path.expanduser(get_config().get("browser_profile_dir", "~/.headless-oauth/browser-profiles"))
    d = os.path.join(base, f"chrome-{server_name.lower()}")
    os.makedirs(d, exist_ok=True)
    return d


def get_proxy_config():
    """Return the proxy config block with defaults applied.

    Shape: {enabled, mode, endpoint(host:port no scheme), host, port, username,
    password, local_forwarder_port}. The endpoint is normalized by stripping a
    leading http://|https:// and splitting host:port, because Chrome wants
    http://host:port for --proxy-server but the forwarder and curl-style
    verification want bare host:port.
    """
    cfg = get_config().get("proxy", {}) or {}
    endpoint = (cfg.get("endpoint") or "p.webshare.io:80").strip()
    for scheme in ("http://", "https://"):
        if endpoint.startswith(scheme):
            endpoint = endpoint[len(scheme):]
    endpoint = endpoint.rstrip("/")
    host, _, port = endpoint.partition(":")
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "mode": cfg.get("mode", "ip_auth"),
        "endpoint": endpoint,                  # e.g. "p.webshare.io:80"
        "host": host,                          # e.g. "p.webshare.io"
        "port": int(port) if port else 80,
        "username": cfg.get("username", ""),
        "password": cfg.get("password", ""),
        "local_forwarder_port": int(cfg.get("local_forwarder_port", 1080)),
    }


# ============================================================
# Gmail code reader (optional — for magic link login)
# ============================================================

def get_gmail_credentials(server_name=None):
    """Get Gmail OAuth credentials for reading verification emails."""
    cfg = get_config()
    gmail_cfg = cfg.get("gmail", {})
    creds = gmail_cfg.get(server_name, gmail_cfg.get("default"))
    if not creds:
        return None
    if not creds.get("refresh_token"):
        return None
    return creds


def refresh_gmail_token(creds):
    """Exchange Gmail refresh token for access token."""
    payload = urllib.parse.urlencode({
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "refresh_token": creds["refresh_token"],
        "grant_type": "refresh_token",
    }).encode()
    req = urllib.request.Request(
        creds.get("token_uri", "https://oauth2.googleapis.com/token"),
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=15)
    return json.loads(resp.read().decode())["access_token"]


def poll_gmail_for_verification(server_name, timeout=90, interval=5):
    """Poll Gmail for a magic login link from Anthropic."""
    creds = get_gmail_credentials(server_name)
    if not creds:
        log(f"[{server_name}] No Gmail credentials configured — skipping email polling")
        return None

    try:
        access_token = refresh_gmail_token(creds)
    except Exception as e:
        log(f"[{server_name}] Gmail token refresh failed: {e}")
        return None

    import re

    query = (
        "from:(noreply@anthropic.com OR no-reply@anthropic.com OR anthropic.com) "
        "newer_than:3m"
    )
    seen_ids = set()
    start = time.time()

    while (time.time() - start) < timeout:
        try:
            params = urllib.parse.urlencode({"q": query, "maxResults": 5})
            url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages?{params}"
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token}"})
            resp = json.loads(urllib.request.urlopen(req, timeout=15).read().decode())
            messages = resp.get("messages", [])

            for msg_stub in messages:
                msg_id = msg_stub["id"]
                if msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)

                msg_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=full"
                msg_req = urllib.request.Request(msg_url, headers={"Authorization": f"Bearer {access_token}"})
                message = json.loads(urllib.request.urlopen(msg_req, timeout=15).read().decode())

                # Extract body text
                body = _extract_email_body(message)

                # Look for magic login link
                urls = re.findall(
                    r'https?://(?:claude\.ai|console\.anthropic\.com|www\.anthropic\.com)/[^\s"<>]+',
                    body,
                )
                for url in urls:
                    url = url.rstrip(".,;)>]")
                    if any(kw in url.lower() for kw in ["login", "verify", "auth", "sign", "magic", "token", "code"]):
                        log(f"[{server_name}] Found login link: {url[:80]}...")
                        return {"type": "link", "value": url}
                if urls:
                    return {"type": "link", "value": urls[0].rstrip(".,;)>]")}

                # Fall back to 6-digit code
                codes = re.findall(r"\b(\d{6})\b", body)
                if codes:
                    log(f"[{server_name}] Found verification code: {codes[0]}")
                    return {"type": "code", "value": codes[0]}

            elapsed = int(time.time() - start)
            log(f"[{server_name}] No verification email yet ({elapsed}s, {len(seen_ids)} checked)...")
        except Exception as e:
            log(f"[{server_name}] Gmail poll error: {e}")
            if "401" in str(e):
                try:
                    access_token = refresh_gmail_token(creds)
                except Exception:
                    pass

        time.sleep(interval)

    return None


def _extract_email_body(message):
    """Extract plain text from a Gmail API message."""
    payload = message.get("payload", {})
    if "body" in payload and payload["body"].get("data"):
        return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors="replace")
    for mime in ["text/plain", "text/html"]:
        for part in payload.get("parts", []):
            if part.get("mimeType") == mime and part.get("body", {}).get("data"):
                return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="replace")
            for sub in part.get("parts", []):
                if sub.get("mimeType") == mime and sub.get("body", {}).get("data"):
                    return base64.urlsafe_b64decode(sub["body"]["data"]).decode("utf-8", errors="replace")
    return ""


# ============================================================
# PKCE + callback server (Claude.ai flow)
# ============================================================

def generate_pkce():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def build_claude_auth_url(verifier, challenge, port):
    params = {
        "client_id": CLAUDE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": CLAUDE_REDIRECT_URI.format(port=port),
        "scope": CLAUDE_SCOPES,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": verifier,
    }
    return f"{CLAUDE_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


def start_callback_server(port):
    result = {}
    server_ready = threading.Event()

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            code = params.get("code", [None])[0]
            if code:
                result["code"] = code
                result["state"] = params.get("state", [None])[0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body style='font-family:sans-serif;text-align:center;padding:50px'>"
                    b"<h2>Authorization successful!</h2>"
                    b"<p>Tokens are being pushed to the server. You can close this tab.</p>"
                    b"</body></html>"
                )
            else:
                self.send_response(200)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", port), CallbackHandler)

    def serve():
        server_ready.set()
        start = time.time()
        while "code" not in result and (time.time() - start) < 300:
            server.handle_request()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    server_ready.wait()
    return result, thread, server


def exchange_claude_tokens(code, state, verifier, port):
    payload = json.dumps({
        "grant_type": "authorization_code",
        "client_id": CLAUDE_CLIENT_ID,
        "code": code,
        "state": state,
        "redirect_uri": CLAUDE_REDIRECT_URI.format(port=port),
        "code_verifier": verifier,
    }).encode()
    req = urllib.request.Request(
        CLAUDE_TOKEN_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "HeadlessOAuthRecovery/1.0"},
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=15)
    result = json.loads(resp.read().decode())
    if "access_token" not in result:
        raise RuntimeError(f"Token exchange failed: {json.dumps(result)[:300]}")
    return result


# ============================================================
# Cloudflare Turnstile helpers
# ============================================================

def _is_cloudflare_page(page):
    """Detect if the current page is a Cloudflare challenge."""
    try:
        page_text = page.inner_text("body", timeout=1500)
        lower = page_text.lower()
        return any(phrase in lower for phrase in [
            "security verification",
            "performing security verification",
            "verifying",
            "verify you are human",
            "checking your browser",
            "just a moment",
        ])
    except Exception:
        return False


def _try_click_turnstile(page, server_name):
    """Attempt to click the Cloudflare Turnstile checkbox."""
    try:
        cf_iframe = page.locator(
            'iframe[src*="challenges.cloudflare.com"], '
            'iframe[title*="Cloudflare"], '
            'iframe[title*="Widget"]'
        )
        if cf_iframe.first.is_visible(timeout=500):
            box = cf_iframe.first.bounding_box()
            if box:
                click_x = box["x"] + 28 + random.uniform(-3, 3)
                click_y = box["y"] + (box["height"] / 2) + random.uniform(-3, 3)
                page.mouse.move(
                    click_x + random.uniform(50, 150),
                    click_y + random.uniform(50, 150),
                )
                time.sleep(random.uniform(0.1, 0.3))
                page.mouse.move(click_x, click_y, steps=random.randint(5, 15))
                time.sleep(random.uniform(0.1, 0.4))
                page.mouse.click(click_x, click_y)
                log(f"[{server_name}] Clicked Turnstile iframe")
                return True
    except Exception:
        pass
    return False


def _wait_for_cloudflare_clearance(page, server_name, max_wait=90):
    """Wait for Cloudflare to clear, attempting checkbox clicks periodically."""
    start = time.time()
    attempt = 0
    while (time.time() - start) < max_wait:
        if not _is_cloudflare_page(page):
            elapsed = int(time.time() - start)
            log(f"[{server_name}] Cloudflare cleared after {elapsed}s")
            return True

        if attempt == 0:
            log(f"[{server_name}] Cloudflare challenge detected — working to clear...")

        if attempt % 3 == 1:
            _try_click_turnstile(page, server_name)

        if attempt % 5 == 0:
            try:
                page.mouse.move(
                    random.randint(200, 800),
                    random.randint(200, 500),
                    steps=random.randint(3, 8),
                )
            except Exception:
                pass

        attempt += 1
        time.sleep(random.uniform(2.0, 4.0))

    log(f"[{server_name}] Cloudflare did NOT clear after {max_wait}s")
    return False


# ============================================================
# Chrome CDP launcher
# ============================================================

def launch_chrome_cdp(server_name, headed=True):
    """Launch real Chrome with remote debugging and return (process, port, forwarder).

    Uses real system Chrome instead of Playwright's Chromium to bypass
    Cloudflare Turnstile bot detection. Playwright's launch() injects
    --enable-automation which Cloudflare fingerprints.

    When the proxy config is enabled, also attaches a Webshare residential proxy:
    ip_auth mode points Chrome directly at the Webshare endpoint; userpass mode
    starts a local credential-injecting forwarder (returned as the third element)
    and points Chrome at it. ``forwarder`` is None unless userpass started one.
    """
    chrome_path = get_chrome_path()
    profile_dir = get_browser_profile_dir(server_name)
    cdp_port = 9222 + hash(server_name) % 100

    # Kill any existing session on this port
    subprocess.run(
        f"lsof -ti:{cdp_port} 2>/dev/null | xargs kill -9 2>/dev/null",
        shell=True, capture_output=True,
    )
    time.sleep(1)

    chrome_args = [
        chrome_path,
        f"--remote-debugging-port={cdp_port}",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-client-side-phishing-detection",
        "--disable-default-apps",
        "--disable-hang-monitor",
        "--disable-popup-blocking",
        "--disable-prompt-on-repost",
        "--disable-sync",
        "--metrics-recording-only",
        "--window-size=1280,720",
    ]

    forwarder = None
    pcfg = get_proxy_config()
    if pcfg["enabled"]:
        if pcfg["mode"] == "userpass":
            from proxy_forwarder import CredentialInjectingForwarder
            # Defensively clear any stale listener (e.g. a previous run's forwarder
            # that wasn't cleaned up) on the local forwarder port before binding —
            # SO_REUSEADDR does not help against an actively-listening process.
            fwd_port = pcfg["local_forwarder_port"]
            subprocess.run(
                f"lsof -ti:{fwd_port} 2>/dev/null | xargs kill -9 2>/dev/null",
                shell=True, capture_output=True,
            )
            forwarder = CredentialInjectingForwarder(
                pcfg["host"], pcfg["port"], pcfg["username"], pcfg["password"],
                local_host="127.0.0.1", local_port=fwd_port,
            )
            forwarder.start()
            proxy_server = f"http://127.0.0.1:{forwarder.port}"
        else:  # ip_auth
            proxy_server = f"http://{pcfg['endpoint']}"
        chrome_args += [
            f"--proxy-server={proxy_server}",
            # MANDATORY: keep the OAuth callback (localhost:<callback_port>) and all
            # loopback OFF the proxy, or the callback HTTP request never reaches our
            # local callback server and the whole flow fails.
            "--proxy-bypass-list=localhost;127.0.0.1;[::1];<-loopback>",
        ]
        log(f"[{server_name}] Proxy enabled (mode={pcfg['mode']}) -> {proxy_server}")

    log(f"[{server_name}] Launching Chrome (CDP port {cdp_port})...")
    proc = subprocess.Popen(chrome_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    return proc, cdp_port, forwarder


def cleanup_chrome(browser, chrome_proc, forwarder=None):
    """Clean up browser connection, Chrome process, and (if any) the local proxy forwarder."""
    if browser is not None:
        try:
            browser.close()
        except Exception:
            pass
    if forwarder is not None:
        try:
            forwarder.stop()
        except Exception:
            pass
    chrome_proc.terminate()
    try:
        chrome_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        chrome_proc.kill()


# ============================================================
# SSH push + gateway restart
# ============================================================

def push_tokens_to_server(tokens_json, server_name, dry_run=False):
    """Push OAuth tokens to a remote server via SCP."""
    server = get_server(server_name)
    if dry_run:
        log(f"  {server_name}: SKIP (dry-run)")
        return True

    hostname = server["hostname"]

    # Optional: push SSH key via EC2 Instance Connect
    instance_id = server.get("instance_id")
    if instance_id:
        try:
            subprocess.run(
                [
                    "aws", "ec2-instance-connect", "send-ssh-public-key",
                    "--instance-id", instance_id,
                    "--instance-os-user", "ubuntu",
                    "--ssh-public-key", f"file://{os.path.expanduser('~/.ssh/id_ed25519.pub')}",
                ],
                capture_output=True, timeout=15, check=True,
            )
        except Exception as e:
            log(f"  {server_name}: WARNING (SSH key push: {e})")

    # Determine auth profile key
    provider = server.get("provider", "claude")
    profile_key = "anthropic:oauth" if provider == "claude" else "openai:oauth"

    import tempfile

    # SCP tokens file
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    tmp.write(tokens_json)
    tmp.close()

    try:
        subprocess.run(
            ["scp", tmp.name, f"{hostname}:/tmp/_fresh_tokens.json"],
            capture_output=True, timeout=15, check=True,
        )
    except Exception as e:
        os.unlink(tmp.name)
        log(f"  {server_name}: FAILED (SCP: {e})")
        return False
    os.unlink(tmp.name)

    # SCP push script
    script_tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
    script_tmp.write(f"""import json, glob, os
with open('/tmp/_fresh_tokens.json') as f:
    tokens = json.load(f)
os.unlink('/tmp/_fresh_tokens.json')
profile_key = '{profile_key}'
paths = [os.path.expanduser('~/.openclaw/auth-profiles.json')] + \\
        glob.glob(os.path.expanduser('~/.openclaw/agents/*/agent/auth-profiles.json'))
updated = 0
for p in paths:
    try:
        with open(p) as f:
            d = json.load(f)
        existing = d.get('profiles', {{}}).get(profile_key, {{}})
        d.setdefault('profiles', {{}})[profile_key] = {{**existing, **tokens}}
        with open(p, 'w') as f:
            json.dump(d, f)
        updated += 1
    except: pass
print(f'OK ({{updated}} files)')
""")
    script_tmp.close()

    try:
        subprocess.run(
            ["scp", script_tmp.name, f"{hostname}:/tmp/_push_tokens.py"],
            capture_output=True, timeout=15, check=True,
        )
    except Exception as e:
        os.unlink(script_tmp.name)
        log(f"  {server_name}: FAILED (SCP script: {e})")
        return False
    os.unlink(script_tmp.name)

    try:
        result = subprocess.run(
            ["ssh", hostname, "python3 /tmp/_push_tokens.py && rm -f /tmp/_push_tokens.py"],
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout.strip()
        log(f"  {server_name}: {output or result.stderr.strip() or 'FAILED'}")
        return "OK" in output
    except Exception as e:
        log(f"  {server_name}: FAILED ({e})")
        return False


def restart_gateway(server_name, dry_run=False):
    """Restart the OpenClaw gateway on a remote server."""
    server = get_server(server_name)
    if dry_run:
        log(f"  {server_name}: SKIP (dry-run)")
        return True

    hostname = server["hostname"]
    instance_id = server.get("instance_id")

    if instance_id:
        try:
            subprocess.run(
                [
                    "aws", "ec2-instance-connect", "send-ssh-public-key",
                    "--instance-id", instance_id,
                    "--instance-os-user", "ubuntu",
                    "--ssh-public-key", f"file://{os.path.expanduser('~/.ssh/id_ed25519.pub')}",
                ],
                capture_output=True, timeout=15, check=True,
            )
        except Exception:
            pass

    try:
        result = subprocess.run(
            [
                "ssh", hostname,
                "systemctl --user restart openclaw-gateway.service 2>/dev/null && "
                "sleep 2 && "
                "systemctl --user is-active openclaw-gateway.service 2>/dev/null",
            ],
            capture_output=True, text=True, timeout=30,
        )
        status = result.stdout.strip()
        log(f"  {server_name}: {status}")
        return status == "active"
    except Exception as e:
        log(f"  {server_name}: FAILED ({e})")
        return False


# ============================================================
# Screenshot helper
# ============================================================

def save_screenshot(page, name="failure"):
    screenshot_dir = get_screenshot_dir()
    ts = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(screenshot_dir, f"{name}-{ts}.png")
    try:
        page.screenshot(path=path, full_page=True)
        log(f"Screenshot saved: {path}")
    except Exception as e:
        log(f"Screenshot save failed: {e}")
    return path


# ============================================================
# Slack notifications
# ============================================================

def notify_slack(message, is_error=False):
    cfg = get_config()
    slack_cfg = cfg.get("slack", {})
    slack_token = slack_cfg.get("bot_token")
    slack_user_id = slack_cfg.get("user_id")
    if not slack_token or not slack_user_id:
        return

    try:
        dm_payload = json.dumps({"users": slack_user_id}).encode()
        dm_req = urllib.request.Request(
            "https://slack.com/api/conversations.open",
            data=dm_payload,
            headers={"Authorization": f"Bearer {slack_token}", "Content-Type": "application/json"},
        )
        dm_resp = json.loads(urllib.request.urlopen(dm_req, timeout=10).read().decode())
        channel_id = dm_resp.get("channel", {}).get("id")
        if not channel_id:
            return

        icon = ":rotating_light:" if is_error else ":white_check_mark:"
        prefix = "HEADLESS REAUTH FAILED" if is_error else "HEADLESS REAUTH SUCCESS"
        msg_payload = json.dumps({
            "channel": channel_id,
            "text": f"{icon} *{prefix}*\n\n{message}",
        }).encode()
        msg_req = urllib.request.Request(
            "https://slack.com/api/chat.postMessage",
            data=msg_payload,
            headers={"Authorization": f"Bearer {slack_token}", "Content-Type": "application/json"},
        )
        urllib.request.urlopen(msg_req, timeout=10)
    except Exception as e:
        log(f"Slack notification failed: {e}")


# ============================================================
# Claude.ai OAuth flow
# ============================================================

def run_claude_reauth(server_name, server, headed=False, dry_run=False):
    """Complete claude.ai OAuth flow for a single server."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"success": False, "message": "Playwright not installed. Run: pip install playwright && playwright install chromium"}

    email = server["email"]
    port = get_callback_port()

    subprocess.run(f"lsof -ti:{port} 2>/dev/null | xargs kill -9 2>/dev/null", shell=True, capture_output=True)

    verifier, challenge = generate_pkce()
    auth_url = build_claude_auth_url(verifier, challenge, port)
    callback_result, callback_thread, callback_server = start_callback_server(port)

    log(f"[{server_name}] Launching browser for claude.ai OAuth ({email})...")

    try:
        chrome_proc, cdp_port, forwarder = launch_chrome_cdp(server_name, headed)
    except OSError as e:
        # Most commonly a local forwarder bind failure (port already in use).
        return {"success": False, "message": f"Failed to launch Chrome/proxy forwarder: {e}"}

    with sync_playwright() as p:
        try:
            browser = p.chromium.connect_over_cdp(f"http://127.0.0.1:{cdp_port}")
        except Exception as e:
            cleanup_chrome(None, chrome_proc, forwarder)
            return {"success": False, "message": f"Failed to connect to Chrome CDP: {e}"}

        context = browser.contexts[0] if browser.contexts else browser.new_context()
        page = context.pages[0] if context.pages else context.new_page()

        try:
            # Step 0: Warm up — visit claude.ai to cache Cloudflare clearance
            log(f"[{server_name}] Warming up profile — visiting claude.ai...")
            page.goto("https://claude.ai", wait_until="domcontentloaded", timeout=30000)
            time.sleep(2)
            cf_cleared = _wait_for_cloudflare_clearance(page, server_name, max_wait=90)
            if not cf_cleared:
                save_screenshot(page, f"{server_name}-cf-warmup-stuck")
                log(f"[{server_name}] Cloudflare did not clear on warmup — trying OAuth URL anyway...")

            # Step 1: Navigate to OAuth authorize
            log(f"[{server_name}] Navigating to OAuth authorize URL...")
            page.goto(auth_url, wait_until="domcontentloaded", timeout=30000)
            time.sleep(3)

            log(f"[{server_name}] Detecting page state...")
            page_ready = False
            for wait_idx in range(20):
                current_url = page.url
                if "code" in callback_result:
                    log(f"[{server_name}] Callback already received!")
                    page_ready = True
                    break
                if "localhost" in current_url and "code=" in current_url:
                    log(f"[{server_name}] OAuth auto-completed — callback URL in browser")
                    parsed = urllib.parse.urlparse(current_url)
                    params = urllib.parse.parse_qs(parsed.query)
                    callback_result["code"] = params.get("code", [None])[0]
                    callback_result["state"] = params.get("state", [None])[0]
                    page_ready = True
                    break

                if _is_cloudflare_page(page):
                    if wait_idx == 0:
                        log(f"[{server_name}] Cloudflare on OAuth URL — waiting...")
                    _try_click_turnstile(page, server_name)
                    time.sleep(3)
                    continue

                # Consent page (already logged in)
                authorize_btn = page.locator('button:has-text("Authorize"), button:has-text("Allow")')
                if authorize_btn.first.is_visible(timeout=1000):
                    log(f"[{server_name}] Consent page — clicking Authorize")
                    authorize_btn.first.click()
                    time.sleep(3)
                    page_ready = True
                    break

                # Login page
                if page.locator('#email, input[type="email"]').first.is_visible(timeout=1000):
                    log(f"[{server_name}] Login page detected")
                    page_ready = True
                    break

                # Verification code page
                if page.locator('input[placeholder*="verification" i], input[placeholder*="code" i]').first.is_visible(timeout=1000):
                    log(f"[{server_name}] Verification code page detected")
                    page_ready = True
                    break

                # Landed on chat page — re-navigate to OAuth
                if "claude.ai" in current_url and "/oauth" not in current_url:
                    log(f"[{server_name}] On chat page — re-navigating to OAuth...")
                    page.goto(auth_url, wait_until="domcontentloaded", timeout=30000)
                    time.sleep(3)
                    continue

                log(f"[{server_name}] Waiting... ({wait_idx * 3}s) URL: {current_url[:80]}")

            if not page_ready:
                save_screenshot(page, f"{server_name}-unknown-page")
                return {"success": False, "message": f"Unknown page state. URL: {page.url[:100]}"}

            # Handle login if needed
            if "code" not in callback_result:
                authorize_btn = page.locator('button:has-text("Authorize"), button:has-text("Allow")')
                if authorize_btn.first.is_visible(timeout=500):
                    authorize_btn.first.click()
                    log(f"[{server_name}] Clicked Authorize")
                    time.sleep(3)
                elif page.locator('#email, input[type="email"]').first.is_visible(timeout=500):
                    log(f"[{server_name}] Entering email: {email}")
                    page.fill('#email', email)
                    time.sleep(0.5)
                    page.click('button[type="submit"]')
                    log(f"[{server_name}] Clicked Continue")
                    time.sleep(5)

                    # Wait for verification page, then poll Gmail
                    code_input = page.locator('input[placeholder*="verification" i], input[placeholder*="code" i]')
                    try:
                        code_input.first.wait_for(state="visible", timeout=10000)
                    except Exception:
                        pass

                    if code_input.first.is_visible(timeout=2000):
                        log(f"[{server_name}] Polling Gmail for magic link...")
                        verification = poll_gmail_for_verification(server_name, timeout=90, interval=5)

                        if not verification:
                            save_screenshot(page, f"{server_name}-no-verification")
                            return {"success": False, "message": "No verification email found"}

                        if verification["type"] == "link":
                            log(f"[{server_name}] Navigating to magic login link...")
                            page.goto(verification["value"], wait_until="domcontentloaded", timeout=30000)
                            time.sleep(3)
                        elif verification["type"] == "code":
                            log(f"[{server_name}] Entering code: {verification['value']}")
                            code_input.first.fill(verification["value"])
                            time.sleep(0.5)
                            page.locator('button:has-text("Verify"), button[type="submit"]').first.click()
                            time.sleep(3)

                    # Check for consent page after login
                    authorize_btn = page.locator('button:has-text("Authorize"), button:has-text("Allow")')
                    if authorize_btn.first.is_visible(timeout=5000):
                        authorize_btn.first.click()
                        log(f"[{server_name}] Clicked Authorize")
                        time.sleep(3)

            # Wait for callback
            log(f"[{server_name}] Waiting for OAuth callback...")
            start_wait = time.time()
            while "code" not in callback_result and (time.time() - start_wait) < 30:
                try:
                    current_url = page.url
                    if "localhost" in current_url and "code=" in current_url:
                        parsed = urllib.parse.urlparse(current_url)
                        params = urllib.parse.parse_qs(parsed.query)
                        callback_result["code"] = params.get("code", [None])[0]
                        callback_result["state"] = params.get("state", [None])[0]
                        break
                except Exception:
                    pass
                try:
                    allow_btn = page.locator('button:has-text("Allow"), button:has-text("Authorize")').first
                    if allow_btn.is_visible(timeout=1000):
                        allow_btn.click()
                        time.sleep(3)
                except Exception:
                    pass
                time.sleep(1)

            if "code" not in callback_result:
                save_screenshot(page, f"{server_name}-no-callback")
                return {"success": False, "message": f"No OAuth callback. Page: {page.url[:100]}"}

        except Exception as e:
            save_screenshot(page, f"{server_name}-exception")
            return {"success": False, "message": f"Browser error: {e}"}
        finally:
            cleanup_chrome(browser, chrome_proc, forwarder)

    # Exchange code for tokens
    log(f"[{server_name}] Exchanging authorization code for tokens...")
    try:
        token_result = exchange_claude_tokens(
            callback_result["code"], callback_result.get("state", ""), verifier, port
        )
    except Exception as e:
        return {"success": False, "message": f"Token exchange failed: {e}"}

    hours = round(token_result["expires_in"] / 3600, 1)
    log(f"[{server_name}] Token obtained: valid for {hours}h")

    tokens = {
        "type": "oauth",
        "provider": "anthropic",
        "access": token_result["access_token"],
        "refresh": token_result["refresh_token"],
        "expires": int(time.time() * 1000) + token_result["expires_in"] * 1000 - 5 * 60 * 1000,
        "scopes": ["user:inference", "user:profile"],
    }
    tokens_json = json.dumps(tokens)

    # Push and restart
    log(f"[{server_name}] Pushing tokens...")
    pushed = push_tokens_to_server(tokens_json, server_name, dry_run)
    log(f"[{server_name}] Restarting gateway...")
    restarted = restart_gateway(server_name, dry_run)

    success = pushed and restarted
    message = f"[{server_name}] OAuth recovered. Token valid for {hours}h. Push={'OK' if pushed else 'FAILED'}, Restart={'OK' if restarted else 'FAILED'}"
    return {"success": success, "message": message}


# ============================================================
# ChatGPT OAuth flow via Google Sign-In
# ============================================================

def run_chatgpt_reauth(server_name, server, headed=False, dry_run=False):
    """Complete chatgpt.com OAuth flow via Google Sign-In."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"success": False, "message": "Playwright not installed"}

    email = server["email"]
    password = server["password"]

    log(f"[{server_name}] Launching browser for chatgpt.com via Google ({email})...")

    try:
        chrome_proc, cdp_port, forwarder = launch_chrome_cdp(server_name, headed)
    except OSError as e:
        # Most commonly a local forwarder bind failure (port already in use).
        return {"success": False, "message": f"Failed to launch Chrome/proxy forwarder: {e}"}

    with sync_playwright() as p:
        try:
            browser = p.chromium.connect_over_cdp(f"http://127.0.0.1:{cdp_port}")
        except Exception as e:
            cleanup_chrome(None, chrome_proc, forwarder)
            return {"success": False, "message": f"Failed to connect to Chrome CDP: {e}"}

        context = browser.contexts[0] if browser.contexts else browser.new_context()
        page = context.pages[0] if context.pages else context.new_page()

        try:
            page.goto("https://chatgpt.com/auth/login", wait_until="domcontentloaded", timeout=30000)
            time.sleep(3)
            _wait_for_cloudflare_clearance(page, server_name, max_wait=60)

            login_btn = page.locator('button:has-text("Log in"), a:has-text("Log in")').first
            if login_btn.is_visible(timeout=5000):
                login_btn.click()
                log(f"[{server_name}] Clicked Log in")
                time.sleep(3)
                _wait_for_cloudflare_clearance(page, server_name, max_wait=30)

            log(f"[{server_name}] Looking for Continue with Google...")
            google_btn = page.locator('button:has-text("Continue with Google"), a:has-text("Continue with Google"), [data-provider="google"]').first
            if not google_btn.is_visible(timeout=10000):
                save_screenshot(page, f"{server_name}-no-google-btn")
                return {"success": False, "message": "Google login button not found"}

            google_btn.click()
            log(f"[{server_name}] Clicked Continue with Google")
            time.sleep(3)
            _wait_for_cloudflare_clearance(page, server_name, max_wait=30)

            # Google email
            google_email = page.locator('input[type="email"]').first
            if not google_email.is_visible(timeout=10000):
                account_option = page.locator(f'[data-email="{email}"], :has-text("{email}")').first
                if account_option.is_visible(timeout=5000):
                    account_option.click()
                    time.sleep(3)
                else:
                    save_screenshot(page, f"{server_name}-no-google-email")
                    return {"success": False, "message": "Google email input not found"}
            else:
                google_email.fill(email)
                time.sleep(0.5)
                page.locator('#identifierNext, button:has-text("Next")').first.click()
                time.sleep(3)

            # Google password
            google_pw = page.locator('input[type="password"]').first
            try:
                google_pw.wait_for(state="visible", timeout=10000)
            except Exception:
                pass
            if google_pw.is_visible():
                google_pw.fill(password)
                time.sleep(0.5)
                page.locator('#passwordNext, button:has-text("Next")').first.click()
                time.sleep(5)

            log(f"[{server_name}] Waiting for ChatGPT redirect...")
            time.sleep(5)

            current_url = page.url
            if "chatgpt.com" not in current_url and "chat.openai.com" not in current_url:
                save_screenshot(page, f"{server_name}-google-verification")
                log(f"[{server_name}] Not on ChatGPT yet: {current_url[:80]}")
                time.sleep(10)
                current_url = page.url

            if "chatgpt.com" in current_url or "chat.openai.com" in current_url:
                log(f"[{server_name}] Logged into ChatGPT")

                cookies = context.cookies()
                session_token = None
                for cookie in cookies:
                    if cookie["name"] == "__Secure-next-auth.session-token":
                        session_token = cookie["value"]

                access_token = None
                try:
                    page.goto("https://chatgpt.com/api/auth/session", wait_until="domcontentloaded", timeout=15000)
                    session_data = json.loads(page.locator("body").inner_text())
                    access_token = session_data.get("accessToken")
                except Exception:
                    pass

                if not access_token:
                    save_screenshot(page, f"{server_name}-no-token")
                    return {"success": False, "message": "Logged in but couldn't extract token"}

                tokens = {
                    "type": "oauth",
                    "provider": "openai",
                    "access": access_token,
                    "refresh": session_token or "",
                    "expires": int(time.time() * 1000) + 7 * 24 * 3600 * 1000,
                    "scopes": ["chat"],
                }
                tokens_json = json.dumps(tokens)

                log(f"[{server_name}] Pushing tokens...")
                pushed = push_tokens_to_server(tokens_json, server_name, dry_run)
                log(f"[{server_name}] Restarting gateway...")
                restarted = restart_gateway(server_name, dry_run)

                success = pushed and restarted
                message = f"[{server_name}] ChatGPT OAuth recovered. Push={'OK' if pushed else 'FAILED'}, Restart={'OK' if restarted else 'FAILED'}"
                return {"success": success, "message": message}
            else:
                save_screenshot(page, f"{server_name}-not-on-chatgpt")
                return {"success": False, "message": f"Failed to reach ChatGPT: {current_url[:100]}"}

        except Exception as e:
            save_screenshot(page, f"{server_name}-exception")
            return {"success": False, "message": f"Browser error: {e}"}
        finally:
            cleanup_chrome(browser, chrome_proc, forwarder)


# ============================================================
# Main orchestrator
# ============================================================

def run_gemini_reauth(server_name, server, headed=False, dry_run=False):
    """Gemini OAuth via Google Sign-In — reuses Google login automation."""
    try:
        from token_refresh import _get_gemini_credentials
        client_id, client_secret = _get_gemini_credentials({"client_id": None, "client_secret": None})
    except ImportError:
        return {"success": False, "message": "token_refresh.py not found — needed for Gemini credentials"}

    port = get_callback_port()
    verifier, challenge = generate_pkce()

    auth_url = (
        f"{GEMINI_AUTHORIZE_URL}?"
        f"client_id={client_id}&"
        f"redirect_uri={GEMINI_REDIRECT_URI.format(port=port)}&"
        f"response_type=code&"
        f"scope={urllib.parse.quote(GEMINI_SCOPES)}&"
        f"access_type=offline&"
        f"prompt=consent&"
        f"code_challenge={challenge}&"
        f"code_challenge_method=S256"
    )

    chrome_proc = None
    browser = None
    forwarder = None
    try:
        chrome_proc, cdp_port, forwarder = launch_chrome_cdp(server_name, headed=headed)
        from playwright.sync_api import sync_playwright
        pw = sync_playwright().start()
        browser = pw.chromium.connect_over_cdp(f"http://localhost:{cdp_port}")
        page = browser.contexts[0].pages[0] if browser.contexts and browser.contexts[0].pages else browser.contexts[0].new_page() if browser.contexts else browser.new_context().new_page()

        # Start callback server
        callback_result, thread, callback_server = start_callback_server(port)

        # Navigate to Google OAuth
        log(f"[{server_name}] Navigating to Google OAuth for Gemini...")
        page.goto(auth_url, wait_until="networkidle", timeout=30000)

        # Enter email
        email = server.get("email", "")
        if email:
            try:
                email_input = page.locator('input[type="email"]')
                email_input.fill(email, timeout=10000)
                page.locator('#identifierNext, button:has-text("Next")').click(timeout=5000)
                time.sleep(2)
            except Exception as e:
                log(f"[{server_name}] Email entry: {e}")

        # Enter password
        password = server.get("password", "")
        if password:
            try:
                pw_input = page.locator('input[type="password"]')
                pw_input.fill(password, timeout=10000)
                page.locator('#passwordNext, button:has-text("Next")').click(timeout=5000)
                time.sleep(3)
            except Exception as e:
                log(f"[{server_name}] Password entry: {e}")

        # Wait for callback
        thread.join(timeout=120)
        if "code" not in callback_result:
            save_screenshot(page, f"{server_name}-gemini-no-code")
            return {"success": False, "message": "No auth code received from Gemini OAuth"}

        # Exchange code for tokens
        payload = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": callback_result["code"],
            "redirect_uri": GEMINI_REDIRECT_URI.format(port=port),
            "code_verifier": verifier,
        }).encode()
        req = urllib.request.Request(
            GEMINI_TOKEN_URL, data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=15)
        tokens = json.loads(resp.read().decode())

        if "access_token" not in tokens:
            return {"success": False, "message": f"Gemini token exchange failed: {json.dumps(tokens)[:300]}"}

        # Build OAuth object
        oauth = {
            "type": "oauth",
            "provider": "google-gemini",
            "access": tokens["access_token"],
            "refresh": tokens.get("refresh_token", ""),
            "expires": int(time.time() * 1000) + tokens.get("expires_in", 3600) * 1000 - 60000,
            "scopes": ["cloud-platform", "userinfo.email"],
        }
        tokens_json = json.dumps(oauth)

        if not dry_run:
            push_tokens_to_server(tokens_json, server_name, dry_run=False)

        hrs = round(tokens.get("expires_in", 3600) / 3600, 1)
        return {"success": True, "message": f"Gemini tokens refreshed ({hrs}h)"}

    except Exception as e:
        return {"success": False, "message": f"Gemini reauth error: {e}"}
    finally:
        if chrome_proc is not None:
            try:
                cleanup_chrome(browser, chrome_proc, forwarder)
            except Exception:
                pass
        elif forwarder is not None:
            try:
                forwarder.stop()
            except Exception:
                pass


def run_reauth_for_server(server_name, headed=False, dry_run=False):
    server = get_server(server_name)
    provider = server.get("provider", "claude")
    if provider == "claude":
        return run_claude_reauth(server_name, server, headed, dry_run)
    elif provider == "chatgpt":
        return run_chatgpt_reauth(server_name, server, headed, dry_run)
    elif provider == "gemini":
        return run_gemini_reauth(server_name, server, headed, dry_run)
    else:
        return {"success": False, "message": f"Unknown provider: {provider}"}


def main():
    parser = argparse.ArgumentParser(description="Headless OAuth recovery for OpenClaw servers")
    parser.add_argument("--server", help="Server name from config.json")
    parser.add_argument("--all", action="store_true", help="Reauth all servers")
    parser.add_argument("--dry-run", action="store_true", help="Complete flow but don't push tokens")
    parser.add_argument("--headed", action="store_true", help="Run browser visibly (for debugging)")
    parser.add_argument("--config", default=None, help="Path to config.json")
    parser.add_argument("--max-attempts", type=int, default=MAX_ATTEMPTS, help="Max retries per server")
    args = parser.parse_args()

    # Load config
    get_config(args.config)

    servers = get_servers()
    if args.all:
        target_servers = list(servers.keys())
    elif args.server:
        target_servers = [args.server]
    else:
        if len(servers) == 1:
            target_servers = list(servers.keys())
        else:
            print(f"Specify --server NAME or --all. Available: {list(servers.keys())}")
            sys.exit(1)

    log(f"=== Headless OAuth Recovery — Servers: {', '.join(target_servers)} ===")

    overall_success = True
    for server_name in target_servers:
        server = get_server(server_name)
        provider = server.get("provider", "claude")
        log(f"\n--- {server_name} ({provider}) ---")

        for attempt in range(1, args.max_attempts + 1):
            log(f"[{server_name}] Attempt {attempt}/{args.max_attempts}")
            try:
                result = run_reauth_for_server(server_name, args.headed, args.dry_run)
            except Exception as e:
                # An unhandled exception (e.g. a forwarder bind failure) must fail
                # only this server's attempt, not abort the entire --all run.
                log(f"[{server_name}] Unhandled error: {e}")
                result = {"success": False, "message": f"Unhandled error: {e}"}

            if result["success"]:
                log(f"SUCCESS: {result['message']}")
                notify_slack(result["message"])
                break
            else:
                log(f"FAILED: {result['message']}")
                if attempt < args.max_attempts:
                    log("Retrying in 10 seconds...")
                    time.sleep(10)
        else:
            overall_success = False
            log(f"[{server_name}] All {args.max_attempts} attempts failed.")
            notify_slack(
                f"[{server_name}] All attempts failed.\nLast error: {result['message']}",
                is_error=True,
            )

    sys.exit(0 if overall_success else 1)


if __name__ == "__main__":
    main()
