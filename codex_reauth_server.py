#!/usr/bin/env python3
"""Server-side OpenAI Codex re-auth, Gmail-driven.

Purpose
-------
Non-interactively restore the openai-codex:codex-cli OAuth token on this
server. The whole design assumes that when we submit the Codex auth form
with a new-device IP, OpenAI sends you@example.com an email with
either a magic link or a numeric verification code, and we can catch that
email via the Gmail API and finish the login without human interaction.

Prereqs (one-time setup, documented in README.md):
  - google-chrome-stable installed at /usr/bin/google-chrome-stable
  - xvfb-run installed if no display is available
  - A persistent Chrome profile at <chrome_profile_dir> that has already
    been seeded via a tunneled browser session so Cloudflare Turnstile
    trust cookies (cf_clearance) exist
  - ~/.openclaw/gmail-oauth-credentials.json points at
    you@example.com with a valid refresh token
  - Playwright Python installed in venv: pip install playwright

Usage:
  ./venv/bin/python codex_reauth_server.py
  ./venv/bin/python codex_reauth_server.py --config ./config.server.json
  ./venv/bin/python codex_reauth_server.py --dry-run

Exit codes:
  0  success (tokens written, gateway restarted)
  10 config error
  11 chrome launch failed
  12 navigation blocked (Turnstile or other)
  13 Gmail returned nothing actionable within timeout
  14 OAuth token exchange failed
  15 gateway restart failed
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re as _re
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

from auth_profiles import (
    discover_paths,
    write_codex_cli_native,
    write_token_cache,
    write_tokens,
)
from codex_oauth import build_authorize_url, exchange_code
from gmail_reader import GmailReader, extract_first_code, extract_links

# Global callback state (single-shot per run, so a module global is fine)
_callback_state: dict = {"code": None, "state": None, "hit": False}


# ---------------------------------------------------------------- config
DEFAULT_CONFIG = {
    "gmail": {
        "credentials_path": "~/.openclaw/gmail-oauth-credentials.json",
        "sender_query": "from:openai.com OR from:auth.openai.com OR from:tm.openai.com OR from:email.openai.com",
        "wait_timeout_s": 120,
        "poll_interval_s": 4.0,
        "link_host_allowlist": ["openai.com", "auth.openai.com", "chatgpt.com"],
    },
    "codex": {
        "openai_email": "you@example.com",
        "openai_password": "",  # set in config.server.json (mode 600). Empty = SSO-only flow.
        "chrome_path": "/usr/bin/google-chrome-stable",
        "chrome_profile_dir": "~/.hermes-oauth/chrome-profile",
        "cdp_port": 9333,
        "callback_host": "127.0.0.1",
        "callback_port": 1455,
        "callback_path": "/auth/callback",
        "use_xvfb": True,
        "xvfb_screen": "1280x900x24",
        "socks_proxy_port": 1080,
        "socks_proxy_auto": True,
    },
    "auth_profiles": {
        "globs": [
            "~/.openclaw/auth-profiles.json",
            "~/.openclaw/agents/*/agent/auth-profiles.json",
        ],
        "oauth_token_cache": "~/.openclaw/oauth-token-cache.json",
    },
    "gateway": {
        "systemd_user_units": ["hermes-gateway"],
    },
    "logging": {
        "log_file": "~/.hermes-oauth/codex-reauth.log",
        "level": "INFO",
    },
}


def load_config(path: str | None) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep-copy defaults
    if path and os.path.exists(os.path.expanduser(path)):
        with open(os.path.expanduser(path)) as f:
            user = json.load(f)
        _deep_merge(cfg, user)
    return cfg


def _deep_merge(dst: dict, src: dict) -> None:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v


# ------------------------------------------------------------------ logging
def setup_logging(cfg: dict) -> logging.Logger:
    log_file = os.path.expanduser(cfg["logging"]["log_file"])
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    log = logging.getLogger("codex-reauth")
    log.setLevel(getattr(logging, cfg["logging"]["level"].upper(), logging.INFO))
    log.handlers.clear()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = logging.FileHandler(log_file)
    fh.setFormatter(fmt)
    log.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    return log


# ----------------------------------------------------------- callback server
def start_callback_server(cfg: dict, expected_state: str) -> HTTPServer:
    host = cfg["codex"]["callback_host"]
    port = int(cfg["codex"]["callback_port"])
    path = cfg["codex"]["callback_path"]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != path:
                self.send_response(404); self.end_headers(); return
            params = urllib.parse.parse_qs(parsed.query)
            state = (params.get("state") or [None])[0]
            code = (params.get("code") or [None])[0]
            if state != expected_state:
                self.send_response(400); self.end_headers()
                self.wfile.write(b"state mismatch"); return
            _callback_state["code"] = code
            _callback_state["state"] = state
            _callback_state["hit"] = True
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Done</h1>")

        def log_message(self, *_):  # silence
            pass

    # Kill anything already on the port (stale callback server, etc.)
    subprocess.run(
        f"lsof -ti:{port} 2>/dev/null | xargs -r kill -9",
        shell=True, check=False,
    )
    time.sleep(0.3)
    server = HTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# --------------------------------------------------------------- chrome CDP
def launch_chrome(cfg: dict, log: logging.Logger) -> subprocess.Popen:
    chrome = cfg["codex"]["chrome_path"]
    profile_dir = os.path.expanduser(cfg["codex"]["chrome_profile_dir"])
    cdp_port = int(cfg["codex"]["cdp_port"])
    os.makedirs(profile_dir, exist_ok=True)

    # Clear any prior Chrome holding this CDP port
    subprocess.run(
        f"lsof -ti:{cdp_port} 2>/dev/null | xargs -r kill -9",
        shell=True, check=False,
    )
    time.sleep(0.3)

    chrome_args = [
        chrome,
        f"--remote-debugging-port={cdp_port}",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--no-sandbox",
        "--disable-background-networking",
        "--disable-client-side-phishing-detection",
        "--disable-default-apps",
        "--disable-popup-blocking",
        "--disable-prompt-on-repost",
        "--disable-sync",
        "--metrics-recording-only",
        "--window-size=1280,900",
    ]

    # Use residential SOCKS proxy if the reverse SSH tunnel is up
    socks_port = int(cfg["codex"].get("socks_proxy_port", 1080))
    if cfg["codex"].get("socks_proxy_auto", True):
        import socket as _sock
        try:
            s = _sock.create_connection(("127.0.0.1", socks_port), timeout=2)
            s.close()
            chrome_args.append(f"--proxy-server=socks5://127.0.0.1:{socks_port}")
            log.info("SOCKS proxy detected on :%d — routing Chrome through residential IP", socks_port)
        except Exception:
            log.warning(
                "expected residential proxy on :%d not reachable — "
                "re-auth will likely fail from datacenter IP. Check residential-proxy.service.",
                socks_port,
            )

    if cfg["codex"].get("use_xvfb") and not os.environ.get("DISPLAY"):
        chrome_args = [
            "xvfb-run", "-a",
            "--server-args", f"-screen 0 {cfg['codex']['xvfb_screen']}",
        ] + chrome_args
        log.info("launching chrome under xvfb-run")
    else:
        log.info("launching chrome (headful, DISPLAY=%s)", os.environ.get("DISPLAY", ""))

    proc = subprocess.Popen(
        chrome_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(4)
    if proc.poll() is not None:
        raise RuntimeError("chrome exited immediately — check xvfb / display")
    return proc


# ---------------------------------------------------------------- main flow
def run(cfg: dict, dry_run: bool, log: logging.Logger) -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.error("playwright not installed in this venv")
        return 10

    auth_url, verifier, state = build_authorize_url()
    log.info("built authorize url (state=%s)", state)

    callback_server = start_callback_server(cfg, state)

    try:
        chrome_proc = launch_chrome(cfg, log)
    except Exception as e:
        callback_server.shutdown()
        log.error("chrome launch failed: %s", e)
        return 11

    gmail = GmailReader(cfg["gmail"]["credentials_path"])
    start_ts_ms = int(time.time() * 1000)

    try:
        with sync_playwright() as p:
            cdp_url = f"http://127.0.0.1:{cfg['codex']['cdp_port']}"
            browser = p.chromium.connect_over_cdp(cdp_url)
            ctx = browser.contexts[0] if browser.contexts else browser.new_context()
            page = ctx.pages[0] if ctx.pages else ctx.new_page()

            # Apply playwright-stealth: spoof navigator.webdriver, fix plugins,
            # normalize UA hints. Best-effort — OpenAI does behavioral
            # fingerprinting too, so this is necessary but not sufficient.
            try:
                from playwright_stealth import Stealth
                Stealth().apply_stealth_sync(page)
                log.info("stealth applied to page")
            except Exception as e:
                log.warning("stealth not applied (%s); continuing without", e)

            # STEP 1: navigate to Codex authorize URL
            log.info("navigating to authorize url")
            try:
                page.goto(auth_url, wait_until="domcontentloaded", timeout=45000)
            except Exception as e:
                log.warning("initial goto timeout: %s", e)

            # Give Cloudflare Turnstile a chance to auto-clear (if the profile
            # is already trusted, this resolves in a few seconds)
            _wait_for_turnstile(page, log, max_wait=60)

            if "log-in" not in page.url and "authorize" not in page.url:
                log.error("blocked before login form: %s", page.url[:120])
                _dump_debug(page, log, "blocked-before-form")
                return 12

            # STEP 2: enter email + click Continue (human-paced).
            # OpenAI does behavioral fingerprinting, so we hover, jitter, type
            # with per-keystroke delay, mouse-move along a curve, then click.
            email = cfg["codex"]["openai_email"]
            log.info("submitting email %s", email)
            try:
                email_loc = page.locator('input[type="email"]').first
                email_loc.wait_for(state="visible", timeout=15000)
                email_loc.hover()
                page.wait_for_timeout(_jitter(150, 350))
                email_loc.click()
                page.wait_for_timeout(_jitter(120, 280))
                email_loc.type(email, delay=_jitter(60, 140))
                page.wait_for_timeout(_jitter(300, 600))

                btn = page.locator('button:has-text("Continue")').first
                btn.wait_for(state="visible", timeout=10000)
                box = btn.bounding_box()
                if box:
                    page.mouse.move(
                        box["x"] + box["width"] / 2,
                        box["y"] + box["height"] / 2,
                        steps=_jitter(8, 16),
                    )
                    page.wait_for_timeout(_jitter(80, 200))
                btn.click(timeout=10000)

                # Wait for the URL to actually change away from /log-in.
                # OpenAI may go to /log-in/password (account has password),
                # /log-in/code (passwordless), or /email-verification.
                # 10s is generous — usually <1s.
                try:
                    page.wait_for_url(
                        _re.compile(r"/log-in/(password|code|verify|otp)|/email-verification|/sign-in-with-chatgpt"),
                        timeout=10000,
                    )
                except Exception:
                    pass  # URL didn't change in 10s — log it and continue
                log.info("post-submit url: %s", page.url[:140])
            except Exception as e:
                log.error("email/continue failed: %s", e)
                _dump_debug(page, log, "email-continue-failed")
                return 12

            # STEP 2b: password handling. If `openai_password` is configured,
            # fill it. Empty password = SSO-only or OTC-only flow.
            password = cfg["codex"].get("openai_password", "")
            if password and "/log-in/password" in page.url:
                try:
                    page.wait_for_selector('input[type="password"]', timeout=5000)
                    pw_loc = page.locator('input[type="password"]').first
                    pw_loc.click()
                    page.wait_for_timeout(_jitter(120, 280))
                    pw_loc.type(password, delay=_jitter(60, 140))
                    page.wait_for_timeout(_jitter(200, 400))
                    page.locator('button:has-text("Continue")').first.click(timeout=10000)
                    log.info("password submitted")
                    page.wait_for_timeout(_jitter(800, 1500))
                except Exception as e:
                    log.info("password fill issue: %s", str(e)[:120])

            # STEP 2c: if still on /log-in/password (no password configured or
            # password fill failed), fall back to "Log in with one-time code".
            # The OTC path uses the email magic-code flow that gmail_reader handles.
            if "/log-in/password" in page.url:
                log.info("password page detected, switching to one-time code")
                try:
                    otc_btn = page.locator(
                        'button:has-text("one-time code"), a:has-text("one-time code")'
                    ).first
                    otc_btn.wait_for(state="visible", timeout=5000)
                    box = otc_btn.bounding_box()
                    if box:
                        page.mouse.move(
                            box["x"] + box["width"] / 2,
                            box["y"] + box["height"] / 2,
                            steps=_jitter(8, 16),
                        )
                        page.wait_for_timeout(_jitter(80, 200))
                    otc_btn.click(timeout=5000)
                    page.wait_for_timeout(_jitter(800, 1500))
                    log.info("post-OTC-click url: %s", page.url[:140])
                except Exception as e:
                    log.error("could not click one-time-code button: %s", e)
                    _dump_debug(page, log, "otc-button-not-found")
                    return 12

            # STEP 3: wait for either (a) /auth/callback to fire on its own
            # (rare, happens if the persistent profile is fully logged in),
            # (b) an email from OpenAI we can act on, or (c) a code-input field
            # that we'll fill from a Gmail-fetched code.
            deadline = time.time() + int(cfg["gmail"]["wait_timeout_s"])
            acted_on_email = False

            while time.time() < deadline:
                if _callback_state["hit"]:
                    log.info("callback already fired (trusted profile path)")
                    break

                # Once we've submitted a code or followed a link, stop polling
                # Gmail and just wait for the OAuth callback to fire.
                if acted_on_email:
                    time.sleep(2)
                    continue

                msg = gmail.wait_for_matching(
                    query=cfg["gmail"]["sender_query"],
                    since_ts_ms=start_ts_ms,
                    timeout_s=8,
                    poll_interval_s=cfg["gmail"]["poll_interval_s"],
                )
                if msg:
                    log.info("gmail hit: %s | %s", msg.from_addr[:40], msg.subject[:60])
                    body = msg.text_or_html()
                    # Prefer numeric code over magic link — OTC emails contain
                    # both a code AND asset URLs (fonts, tracking pixels) that
                    # incorrectly match the host allowlist. The code is the
                    # authoritative path.
                    code = extract_first_code(body)
                    if code:
                        log.info("extracted verification code %s, filling", code)
                        try:
                            code_loc = page.locator(
                                'input[inputmode="numeric"], input[autocomplete="one-time-code"], input[type="tel"]'
                            ).first
                            code_loc.wait_for(state="visible", timeout=5000)
                            code_loc.click()
                            page.wait_for_timeout(_jitter(120, 280))
                            code_loc.type(code, delay=_jitter(60, 140))
                            page.wait_for_timeout(_jitter(200, 400))
                            page.keyboard.press("Enter")
                            acted_on_email = True

                            # STEP 3b: after successful code entry, OpenAI shows
                            # a Codex OAuth consent page ("Sign in to Codex with
                            # ChatGPT"). Click Continue → /auth/callback fires.
                            try:
                                page.wait_for_url(
                                    _re.compile(r"sign-in-with-chatgpt|/consent"),
                                    timeout=15000,
                                )
                                log.info("consent page: %s", page.url[:140])
                                consent_btn = page.locator(
                                    'button:has-text("Continue")'
                                ).first
                                consent_btn.wait_for(state="visible", timeout=5000)
                                box = consent_btn.bounding_box()
                                if box:
                                    page.mouse.move(
                                        box["x"] + box["width"] / 2,
                                        box["y"] + box["height"] / 2,
                                        steps=_jitter(8, 16),
                                    )
                                    page.wait_for_timeout(_jitter(80, 200))
                                consent_btn.click(timeout=5000)
                                log.info("consent granted")
                            except Exception as e:
                                log.warning("consent step issue (callback may still fire): %s", e)
                        except Exception as e:
                            log.warning("code entry failed: %s", e)
                    else:
                        links = extract_links(body, cfg["gmail"]["link_host_allowlist"])
                        if links:
                            link = links[0]
                            log.info("navigating to magic link: %s", link[:80])
                            try:
                                page.goto(link, wait_until="domcontentloaded", timeout=30000)
                                acted_on_email = True
                            except Exception as e:
                                log.warning("magic link goto failed: %s", e)
                # Loop back — give the callback server a chance to fire
                time.sleep(2)

            # STEP 4: wait for /auth/callback to actually fire
            while not _callback_state["hit"] and time.time() < deadline + 30:
                time.sleep(0.5)

            if not _callback_state["hit"]:
                log.error("no /auth/callback received within timeout (acted_on_email=%s)", acted_on_email)
                _dump_debug(page, log, f"timeout-acted-{acted_on_email}")
                return 13

            code = _callback_state["code"]
            log.info("got authorization code, exchanging for tokens")
            try:
                tokens = exchange_code(code, verifier)
            except Exception as e:
                log.error("token exchange failed: %s", e)
                return 14

            log.info(
                "tokens acquired, expires in %.1fh",
                (tokens.expires_ms - int(time.time() * 1000)) / 3_600_000,
            )

            if dry_run:
                log.info("dry-run: skipping writes and gateway restart")
                return 0

            paths = discover_paths(cfg["auth_profiles"]["globs"])
            updated = write_tokens(paths, tokens)
            write_token_cache(cfg["auth_profiles"]["oauth_token_cache"], tokens)
            cli_native_ok = write_codex_cli_native(tokens, create_if_missing=True)
            log.info(
                "wrote %d auth-profiles.json files + oauth-token-cache.json + codex-cli-native=%s",
                updated, "yes" if cli_native_ok else "no",
            )

            for unit in cfg["gateway"]["systemd_user_units"]:
                r = subprocess.run(
                    ["systemctl", "--user", "restart", unit],
                    capture_output=True, text=True,
                )
                if r.returncode != 0:
                    log.warning("failed to restart %s: %s", unit, r.stderr.strip())
                    return 15
                log.info("restarted %s", unit)

            return 0
    finally:
        try:
            callback_server.shutdown()
        except Exception:
            pass
        try:
            chrome_proc.terminate()
            chrome_proc.wait(timeout=5)
        except Exception:
            try:
                chrome_proc.kill()
            except Exception:
                pass


def _jitter(low: int, high: int) -> int:
    """Random int in [low, high] for human-like timing on clicks/keystrokes."""
    return random.randint(low, high)


def _dump_debug(page, log: logging.Logger, label: str) -> None:
    """Save screenshot + page HTML + url/title to ~/.hermes-oauth/debug/.

    Forensic only — we want to know exactly what page Chrome was on when the
    flow timed out. Cheap insurance: each dump is a few hundred KB.
    """
    try:
        debug_dir = os.path.expanduser("~/.hermes-oauth/debug")
        os.makedirs(debug_dir, exist_ok=True)
        ts = time.strftime("%Y%m%dT%H%M%S")
        prefix = os.path.join(debug_dir, f"{ts}-{label}")
        try:
            page.screenshot(path=f"{prefix}.png", full_page=True)
        except Exception as e:
            log.warning("screenshot failed: %s", e)
        try:
            with open(f"{prefix}.html", "w") as f:
                f.write(page.content())
        except Exception as e:
            log.warning("html dump failed: %s", e)
        try:
            with open(f"{prefix}.txt", "w") as f:
                f.write(f"url: {page.url}\ntitle: {page.title()}\n")
        except Exception as e:
            log.warning("meta dump failed: %s", e)
        log.info("debug artifacts saved to %s.{png,html,txt}", prefix)
    except Exception as e:
        log.warning("debug dump failed entirely: %s", e)


def _wait_for_turnstile(page, log: logging.Logger, max_wait: int = 60) -> None:
    """Block until the 'Just a moment...' Cloudflare challenge clears.

    If the profile is already trusted, this returns in ~1s. If it never
    clears, we fall through and let the subsequent selector fail, which the
    caller turns into exit code 12.
    """
    deadline = time.time() + max_wait
    while time.time() < deadline:
        title = (page.title() or "").lower()
        if "just a moment" not in title and "checking your browser" not in title:
            return
        time.sleep(1)
    log.warning("turnstile still present after %ds", max_wait)


# ---------------------------------------------------------------------- CLI
def _autodiscover_config() -> str | None:
    """Return path to config.server.json sitting alongside this script, if any."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(here, "config.server.json")
    return candidate if os.path.exists(candidate) else None


def main() -> int:
    parser = argparse.ArgumentParser(description="OpenAI Codex re-auth (server, Gmail-driven)")
    parser.add_argument("--config", default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    # Zero-arg invocation (e.g., from codex_watchdog._escalate) must still pick up
    # the operator's config.server.json. Auto-discover alongside the script.
    # Without this, DEFAULT_CONFIG's placeholder email (`you@example.com`) would
    # be used and the reauth would silently fail at email submission.
    if args.config is None:
        args.config = _autodiscover_config()

    cfg = load_config(args.config)
    log = setup_logging(cfg)
    log.info("codex-reauth-server starting")
    return run(cfg, args.dry_run, log)


if __name__ == "__main__":
    sys.exit(main())
