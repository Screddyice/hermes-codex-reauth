#!/usr/bin/env python3
"""Mac-side OpenAI Codex re-auth — backup flow.

Purpose
-------
When the server-side headless flow fails (codex_reauth_server.py returns
non-zero on both servers), run this on the Mac instead. It does the same
Codex OAuth dance using the Mac's real Chrome (no Turnstile problem, real
display, existing Google session), catches the auth code on localhost:1455,
exchanges it for tokens, and pushes the fresh token pair to both servers
via scp. Finally it restarts hermes-gateway on each server over SSH.

This is the escape hatch. Gmail involvement is still wired in — if OpenAI
throws up an email-verification challenge during the Mac run, the same
gmail_reader is used to pull the code or link automatically.

Usage:
  python3 codex_reauth_mac.py
  python3 codex_reauth_mac.py --config ./config.mac.json

The Mac config tells this script which servers to push to:

  {
    "servers": [
      { "ssh_alias": "server-a",
        "remote_paths": [
          "~/.openclaw/auth-profiles.json",
          "~/.openclaw/agents/*/agent/auth-profiles.json"
        ],
        "oauth_token_cache": "~/.openclaw/oauth-token-cache.json",
        "restart_units": ["hermes-gateway", "n8n-openclaw-bridge", "webhook-receiver"]
      },
      { "ssh_alias": "server-b", ... }
    ]
  }
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

from auth_profiles import (
    write_codex_cli_native as _write_local_codex_cli,
    write_tokens as _write_local,
)
from codex_oauth import build_authorize_url, exchange_code
from gmail_reader import GmailReader, extract_first_code, extract_links


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
        "callback_host": "127.0.0.1",
        "callback_port": 1455,
        "callback_path": "/auth/callback",
    },
    "servers": [
        {
            "ssh_alias": "server-a",
            "remote_paths": [
                "~/.openclaw/auth-profiles.json",
                "~/.openclaw/agents/*/agent/auth-profiles.json",
            ],
            "oauth_token_cache": "~/.openclaw/oauth-token-cache.json",
            "restart_units": ["hermes-gateway", "n8n-openclaw-bridge", "webhook-receiver"],
        },
        {
            "ssh_alias": "server-b",
            "remote_paths": [
                "~/.openclaw/auth-profiles.json",
                "~/.openclaw/agents/*/agent/auth-profiles.json",
            ],
            "oauth_token_cache": "~/.openclaw/oauth-token-cache.json",
            "restart_units": ["hermes-gateway", "webhook-receiver"],
        },
    ],
    "logging": {
        "log_file": "~/.hermes-oauth/codex-reauth-mac.log",
        "level": "INFO",
    },
}

_callback_state: dict = {"code": None, "hit": False}


# --------------------------------------------------------------- helpers
def _deep_merge(dst: dict, src: dict) -> None:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v


def load_config(path: str | None) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path and os.path.exists(os.path.expanduser(path)):
        with open(os.path.expanduser(path)) as f:
            _deep_merge(cfg, json.load(f))
    return cfg


def setup_logging(cfg: dict) -> logging.Logger:
    log_file = os.path.expanduser(cfg["logging"]["log_file"])
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    log = logging.getLogger("codex-reauth-mac")
    log.setLevel(getattr(logging, cfg["logging"]["level"].upper(), logging.INFO))
    log.handlers.clear()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = logging.FileHandler(log_file); fh.setFormatter(fmt); log.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout); sh.setFormatter(fmt); log.addHandler(sh)
    return log


# -------------------------------------------------------- callback server
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
            if (params.get("state") or [None])[0] != expected_state:
                self.send_response(400); self.end_headers(); return
            _callback_state["code"] = (params.get("code") or [None])[0]
            _callback_state["hit"] = True
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Done. Return to your terminal.</h1>")
        def log_message(self, *_): pass

    subprocess.run(f"lsof -ti:{port} 2>/dev/null | xargs -r kill -9", shell=True, check=False)
    time.sleep(0.3)
    server = HTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# --------------------------------------------------- optional Gmail assist
def _maybe_assist_via_gmail(cfg: dict, log: logging.Logger, start_ts_ms: int) -> None:
    """If OpenAI emails a magic link while we're waiting for the callback,
    auto-open it in the default browser so the user doesn't have to check
    their inbox. Runs in a background thread."""
    def worker():
        try:
            gmail = GmailReader(cfg["gmail"]["credentials_path"])
        except Exception as e:
            log.warning("gmail reader init failed: %s", e)
            return
        deadline = time.time() + int(cfg["gmail"]["wait_timeout_s"])
        while time.time() < deadline and not _callback_state["hit"]:
            msg = gmail.wait_for_matching(
                query=cfg["gmail"]["sender_query"],
                since_ts_ms=start_ts_ms,
                timeout_s=6,
                poll_interval_s=cfg["gmail"]["poll_interval_s"],
            )
            if not msg:
                continue
            body = msg.text_or_html()
            links = extract_links(body, cfg["gmail"]["link_host_allowlist"])
            if links:
                log.info("gmail assist: opening magic link from %s", msg.from_addr[:40])
                webbrowser.open(links[0])
                return
            code = extract_first_code(body)
            if code:
                log.info("gmail assist: OpenAI sent verification code %s — paste it into the browser", code)
    threading.Thread(target=worker, daemon=True).start()


# ------------------------------------------------------ remote deployment
def _ssh(alias: str, cmd: str, log: logging.Logger) -> tuple[int, str]:
    result = subprocess.run(
        ["ssh", alias, cmd],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        log.warning("ssh %s: rc=%d stderr=%s", alias, result.returncode, result.stderr.strip()[:200])
    return result.returncode, result.stdout.strip()


def push_to_server(
    server: dict,
    profile_json: str,
    cli_tokens_json: str,
    log: logging.Logger,
) -> bool:
    """Push fresh tokens to a remote server. Updates BOTH:
      - openclaw's auth-profiles.json files (under remote_paths)
      - oauth-token-cache.json (legacy cache)
      - Codex CLI native ~/.codex/auth.json (so `codex` CLI itself works)

    The Codex CLI write merges into the existing auth.json if present;
    creates it (mode 0600) otherwise.
    """
    alias = server["ssh_alias"]
    log.info("pushing tokens to %s", alias)

    # Copy a tmp file with the new openclaw profile + Codex CLI tokens block
    tmp_local = "/tmp/codex-tokens-push.json"
    with open(tmp_local, "w") as f:
        json.dump({"profile": json.loads(profile_json), "cli_tokens": json.loads(cli_tokens_json)}, f)
    r = subprocess.run(
        ["scp", tmp_local, f"{alias}:/tmp/codex-tokens-push.json"],
        capture_output=True, text=True, timeout=60,
    )
    if r.returncode != 0:
        log.error("scp to %s failed: %s", alias, r.stderr.strip()[:200])
        return False

    # Remote merge script — writes to every auth-profiles.json path AND to the
    # Codex CLI native auth.json. Kept inline so the server doesn't need this
    # repo deployed for the Mac fallback flow to work.
    remote_paths = server["remote_paths"]
    cache = server.get("oauth_token_cache", "~/.openclaw/oauth-token-cache.json")
    cli_native = server.get("codex_cli_auth_path", "~/.codex/auth.json")
    merge_script = f'''
import glob, json, os, time
payload = json.load(open("/tmp/codex-tokens-push.json"))
profile = payload["profile"]
cli_tokens = payload["cli_tokens"]
paths = []
for g in {json.dumps(remote_paths)}:
    paths.extend(glob.glob(os.path.expanduser(g)))
updated = 0
for p in paths:
    try:
        with open(p) as f: d = json.load(f)
    except Exception: continue
    d.setdefault("profiles", {{}})["openai-codex:codex-cli"] = profile
    d.get("profiles", {{}}).pop("openai-codex:api_key", None)
    d.setdefault("lastGood", {{}})["openai-codex"] = "openai-codex:codex-cli"
    with open(p, "w") as f: json.dump(d, f)
    updated += 1
cache = os.path.expanduser("{cache}")
try:
    with open(cache) as f: c = json.load(f)
except Exception: c = {{}}
c["access"] = profile.get("access")
c["refresh"] = profile.get("refresh")
c["expires"] = profile.get("expires")
with open(cache, "w") as f: json.dump(c, f)
cli_path = os.path.expanduser("{cli_native}")
try:
    with open(cli_path) as f: cd = json.load(f)
except Exception:
    cd = {{"OPENAI_API_KEY": None, "auth_mode": "chatgpt", "tokens": {{}}}}
cd_tokens = cd.get("tokens") or {{}}
cd_tokens.update(cli_tokens)
cd["tokens"] = cd_tokens
cd["last_refresh"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
os.makedirs(os.path.dirname(cli_path), exist_ok=True)
with open(cli_path, "w") as f: json.dump(cd, f)
os.chmod(cli_path, 0o600)
print(f"merged into {{updated}} openclaw files + codex-cli-native")
'''
    rc, out = _ssh(alias, f"python3 -c {shlex.quote(merge_script)} && rm -f /tmp/codex-tokens-push.json", log)
    if rc != 0:
        return False
    log.info("  %s: %s", alias, out)

    # Restart requested systemd --user units
    for unit in server.get("restart_units", []):
        rc, _ = _ssh(alias, f"systemctl --user restart {unit}", log)
        if rc != 0:
            log.warning("  %s: restart %s failed", alias, unit)
        else:
            log.info("  %s: restarted %s", alias, unit)
    return True


# ------------------------------------------------------------------- main
def run(cfg: dict, dry_run: bool, log: logging.Logger) -> int:
    auth_url, verifier, state = build_authorize_url()
    log.info("authorize url state=%s", state)

    server = start_callback_server(cfg, state)
    start_ts_ms = int(time.time() * 1000)
    _maybe_assist_via_gmail(cfg, log, start_ts_ms)

    print("\n" + "=" * 70)
    print("Opening OpenAI Codex login in your default browser.")
    print("Complete the login as", cfg["codex"]["openai_email"])
    print("(If Gmail receives a magic link from OpenAI, it will open automatically.)")
    print("=" * 70 + "\n")
    webbrowser.open(auth_url)

    deadline = time.time() + int(cfg["gmail"]["wait_timeout_s"]) + 180  # extra time for human
    while not _callback_state["hit"] and time.time() < deadline:
        time.sleep(0.5)
    server.shutdown()

    if not _callback_state["hit"]:
        log.error("no /auth/callback received within %ds", int(deadline - start_ts_ms / 1000))
        return 13

    code = _callback_state["code"]
    log.info("received authorization code, exchanging")
    try:
        tokens = exchange_code(code, verifier)
    except Exception as e:
        log.error("token exchange failed: %s", e)
        return 14

    log.info(
        "fresh tokens acquired, expires in %.1fh",
        (tokens.expires_ms - int(time.time() * 1000)) / 3_600_000,
    )

    if dry_run:
        log.info("dry-run: skipping server push")
        return 0

    # Always write locally too (so Mac has a copy for future refreshes)
    local_paths = []
    for g in ["~/.openclaw/auth-profiles.json"]:
        expanded = os.path.expanduser(g)
        if os.path.exists(expanded):
            local_paths.append(expanded)
    if local_paths:
        _write_local(local_paths, tokens)
        log.info("wrote local Mac auth-profiles.json (%d files)", len(local_paths))
    if _write_local_codex_cli(tokens, create_if_missing=True):
        log.info("wrote local Mac ~/.codex/auth.json")

    profile_json = json.dumps(tokens.to_hermes_profile())
    cli_tokens_json = json.dumps(tokens.to_codex_cli_tokens())
    all_ok = True
    for server_cfg in cfg["servers"]:
        if not push_to_server(server_cfg, profile_json, cli_tokens_json, log):
            all_ok = False

    return 0 if all_ok else 15


def _autodiscover_config() -> str | None:
    """Return path to config.mac.json sitting alongside this script, if any."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(here, "config.mac.json")
    return candidate if os.path.exists(candidate) else None


def main() -> int:
    parser = argparse.ArgumentParser(description="OpenAI Codex re-auth (Mac backup flow)")
    parser.add_argument("--config", default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.config is None:
        args.config = _autodiscover_config()
    cfg = load_config(args.config)
    log = setup_logging(cfg)
    log.info("codex-reauth-mac starting")
    return run(cfg, args.dry_run, log)


if __name__ == "__main__":
    sys.exit(main())
