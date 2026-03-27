#!/usr/bin/env python3
"""
oauth_manager.py — Unified CLI entry point for OpenClaw OAuth management.

Commands:
  check    — Run full layered health check and recovery loop
  refresh  — Force API token refresh
  recover  — Trigger headless browser recovery
  status   — Print token health summary

Usage:
  python3 oauth_manager.py check   [--config PATH]
  python3 oauth_manager.py refresh [--config PATH]
  python3 oauth_manager.py recover [--config PATH]
  python3 oauth_manager.py status  [--config PATH]
"""
from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import sys
import time
import urllib.request  # imported at top level per spec

# ── Local module imports ────────────────────────────────────────────────

from token_logic import (
    token_health,
    should_self_refresh,
    should_update_from_s3,
    should_headless_recover,
)
from token_refresh import (
    PROVIDERS,
    InvalidGrantError,
    ProviderUnavailableError,
    UnsupportedProviderError,
    get_profile_key,
    supports_api_refresh,
    get_auth_profile_paths,
    find_best_token,
    write_tokens,
    refresh_token,
)
from token_distribute import (
    upload_to_s3,
    download_from_s3,
    push_to_remote,
    probe_remote_health,
)


# ── Constants ───────────────────────────────────────────────────────────

OPENCLAW_DIR = os.path.expanduser("~/.openclaw-oauth")
LOG_DIR = os.path.join(OPENCLAW_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "oauth-manager.log")
LAST_HEADLESS_FILE = os.path.join(OPENCLAW_DIR, "last-headless-attempt")
LAST_SELF_REFRESH_FILE = os.path.join(OPENCLAW_DIR, "last-self-refresh-attempt")

CONFIG_SEARCH_PATHS = [
    "./config.json",
    os.path.join(OPENCLAW_DIR, "config.json"),
]

LOG_MAX_LINES = 500
LOG_TRUNCATE_TO = 200

# Cooldown defaults (ms)
HEADLESS_COOLDOWN_MS = 30 * 60 * 1000   # 30 minutes
SELF_REFRESH_COOLDOWN_MS = 5 * 60 * 1000  # 5 minutes


# ── Logging setup ───────────────────────────────────────────────────────

def _rotate_log_if_needed(log_path: str) -> None:
    """Truncate log file to LOG_TRUNCATE_TO lines if it exceeds LOG_MAX_LINES."""
    try:
        if not os.path.exists(log_path):
            return
        with open(log_path, "r") as f:
            lines = f.readlines()
        if len(lines) > LOG_MAX_LINES:
            with open(log_path, "w") as f:
                f.writelines(lines[-LOG_TRUNCATE_TO:])
    except Exception:
        pass


def setup_logging() -> logging.Logger:
    """Configure file + stderr logging with line-count-based rotation."""
    os.makedirs(LOG_DIR, exist_ok=True)
    _rotate_log_if_needed(LOG_FILE)

    logger = logging.getLogger("oauth_manager")
    logger.setLevel(logging.DEBUG)

    if not logger.handlers:
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                datefmt="%Y-%m-%d %H:%M:%S")

        fh = logging.FileHandler(LOG_FILE)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(logging.INFO)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

    return logger


log = setup_logging()


# ── Config loading ──────────────────────────────────────────────────────

def load_config(config_path: str | None = None) -> dict:
    """Load config.json from explicit path or search defaults."""
    paths = [config_path] if config_path else CONFIG_SEARCH_PATHS
    for p in paths:
        if p and os.path.exists(p):
            try:
                with open(p) as f:
                    data = json.load(f)
                log.debug("Loaded config from %s", p)
                return data
            except Exception as e:
                log.warning("Failed to parse config %s: %s", p, e)
    log.debug("No config found; using empty config")
    return {}


# ── Cooldown timestamp helpers ──────────────────────────────────────────

def _read_ts(path: str) -> int:
    """Read a Unix ms timestamp from a file. Returns 0 on any error."""
    try:
        with open(path) as f:
            return int(f.read().strip())
    except Exception:
        return 0


def _write_ts(path: str, ts_ms: int) -> None:
    """Write a Unix ms timestamp to a file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "w") as f:
            f.write(str(ts_ms))
    except Exception as e:
        log.warning("Could not write timestamp to %s: %s", path, e)


# ── Slack notification ──────────────────────────────────────────────────

def _notify_slack(config: dict, message: str) -> None:
    """Send an optional Slack DM on failure. Silently skips if not configured."""
    slack = config.get("slack", {})
    bot_token = slack.get("bot_token", "")
    user_id = slack.get("user_id", "")
    if not bot_token or not user_id:
        return
    try:
        payload = json.dumps({"channel": user_id, "text": message}).encode()
        req = urllib.request.Request(
            "https://slack.com/api/chat.postMessage",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {bot_token}",
            },
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
        log.debug("Slack notification sent")
    except Exception as e:
        log.debug("Slack notification failed (non-fatal): %s", e)


# ── Distribution helpers ────────────────────────────────────────────────

def _distribute(oauth: dict, provider_profile: str, config: dict) -> None:
    """Push token to S3 + all remote servers defined in config."""
    # S3 push
    s3_ok = upload_to_s3(oauth, provider_profile, config)
    log.info("S3 upload: %s", "OK" if s3_ok else "skipped/failed")

    # Remote servers push
    servers = config.get("servers", {})
    for name, srv in servers.items():
        ok = push_to_remote(name, srv, oauth, provider_profile)
        log.info("Push to remote %s: %s", name, "OK" if ok else "FAILED")


def _authority_check_remotes(provider_profile: str, local_hours: float,
                              config: dict, oauth: dict) -> None:
    """Probe all remotes; push to any that are stale vs local."""
    servers = config.get("servers", {})
    if not servers:
        return
    for name, srv in servers.items():
        remote_hrs = probe_remote_health(name, srv, provider_profile)
        log.info("Remote %s health: %.1fh", name, remote_hrs)
        if remote_hrs < local_hours - 0.25:  # remote is >15 min behind
            log.info("Remote %s is stale — pushing token", name)
            ok = push_to_remote(name, srv, oauth, provider_profile)
            log.info("Push to %s: %s", name, "OK" if ok else "FAILED")


# ── Command implementations ─────────────────────────────────────────────

def cmd_status(args: argparse.Namespace) -> int:
    """Print a one-line summary: provider, profile key, health, hours remaining."""
    config = load_config(args.config)
    provider = config.get("provider", "claude")

    profile_key = get_profile_key(provider)
    paths = get_auth_profile_paths()
    token = find_best_token(paths, profile_key)

    now_ms = int(time.time() * 1000)
    expires_ms = token.get("expires", 0) if token else 0
    health = token_health(expires_ms, now_ms)
    hours = max(0.0, (expires_ms - now_ms) / 3_600_000) if expires_ms > 0 else 0.0

    print(f"provider      : {provider}")
    print(f"profile_key   : {profile_key}")
    print(f"health        : {health}")
    print(f"hours_remaining: {hours:.1f}")
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    """Force an API refresh for the configured provider."""
    config = load_config(args.config)
    provider = config.get("provider", "claude")

    if not supports_api_refresh(provider):
        log.error("Provider '%s' does not support API refresh", provider)
        return 1

    profile_key = get_profile_key(provider)
    paths = get_auth_profile_paths()
    token = find_best_token(paths, profile_key)
    if not token:
        log.error("No token found locally for %s", profile_key)
        return 1

    refresh_tok = token.get("refresh")
    if not refresh_tok:
        log.error("No refresh_token present in local token")
        return 1

    log.info("Forcing API refresh for provider=%s", provider)
    try:
        new_oauth = refresh_token(provider, refresh_tok)
        write_tokens(paths, profile_key, new_oauth)
        _distribute(new_oauth, profile_key, config)
        _write_ts(LAST_SELF_REFRESH_FILE, int(time.time() * 1000))
        log.info("Refresh successful — token expires in %.1fh",
                 (new_oauth.get("expires", 0) - time.time() * 1000) / 3_600_000)
        return 0
    except InvalidGrantError as e:
        log.error("Refresh token revoked — headless recovery required: %s", e)
        _notify_slack(config, f"[oauth-manager] InvalidGrant for {provider}: {e}")
        return 2
    except ProviderUnavailableError as e:
        log.error("Provider unavailable: %s", e)
        return 3
    except UnsupportedProviderError as e:
        log.error("Unsupported provider: %s", e)
        return 1


def cmd_recover(args: argparse.Namespace) -> int:
    """Trigger headless browser recovery via headless_reauth.recover_all()."""
    config = load_config(args.config)
    try:
        import headless_reauth  # noqa: F401
        if not hasattr(headless_reauth, "recover_all"):
            log.error(
                "headless_reauth.recover_all() not yet implemented — "
                "module exists but function is missing (expected, Task 5 precondition)"
            )
            return 1
        log.info("Calling headless_reauth.recover_all()")
        _write_ts(LAST_HEADLESS_FILE, int(time.time() * 1000))
        headless_reauth.recover_all(config)
        log.info("headless_reauth.recover_all() completed")
        return 0
    except ImportError as e:
        log.warning(
            "headless_reauth not importable (not yet adapted) — skipping: %s", e
        )
        return 1


def cmd_check(args: argparse.Namespace) -> int:
    """
    Main health loop with layered recovery:

    1. Read auth-profiles, find best token
    2. Perplexity: just check key presence
    3. Authority role: probe remotes, push if stale
    4. If healthy and not authority: exit
    5. Layer 1: API Refresh (Claude/Gemini only)
    6. Layer 2: S3 Pull (multi-server only)
    7. Layer 4: Headless Recovery (with cooldown check)
    Layer 3 (S3 Push) runs inside Layer 1 success path via _distribute().
    """
    config = load_config(args.config)
    provider = config.get("provider", "claude")
    is_authority = config.get("authority", False)
    multi_server = bool(config.get("servers"))

    profile_key = get_profile_key(provider)
    log.info("cmd_check: provider=%s profile=%s authority=%s",
             provider, profile_key, is_authority)

    # ── Step 1: Find best local token ──
    paths = get_auth_profile_paths()
    token = find_best_token(paths, profile_key)
    now_ms = int(time.time() * 1000)
    local_expires = token.get("expires", 0) if token else 0
    health = token_health(local_expires, now_ms)
    local_hours = max(0.0, (local_expires - now_ms) / 3_600_000)
    log.info("Local token health=%s hours_remaining=%.1f", health, local_hours)

    # ── Step 2: Perplexity — API key check only ──
    if provider == "perplexity":
        api_key = token.get("key", "") if token else ""
        if api_key:
            log.info("Perplexity API key present — OK")
            return 0
        else:
            log.error("Perplexity API key missing — manual intervention required")
            _notify_slack(config, "[oauth-manager] Perplexity API key missing")
            return 1

    # ── Step 3: Authority role — probe and sync remotes ──
    if is_authority and token:
        _authority_check_remotes(profile_key, local_hours, config, token)

    # ── Step 4: Exit early if healthy and not authority ──
    if health == "OK" and not is_authority:
        log.info("Token is healthy and this node is not authority — nothing to do")
        return 0

    if health == "OK" and is_authority:
        log.info("Token is healthy; authority sync done")
        return 0

    log.info("Token needs recovery (health=%s) — entering layered recovery", health)

    # ── Layer 1: API Refresh (Claude / Gemini only) ──
    if supports_api_refresh(provider):
        last_refresh_ts = _read_ts(LAST_SELF_REFRESH_FILE)
        s3_token = download_from_s3(config, profile_key)
        s3_expires = s3_token.get("expires", 0) if s3_token else None

        if should_self_refresh(local_expires or None, s3_expires, last_refresh_ts,
                               now_ms, SELF_REFRESH_COOLDOWN_MS):
            refresh_tok = (token.get("refresh") if token else None)
            if refresh_tok:
                log.info("Layer 1: attempting API refresh")
                try:
                    new_oauth = refresh_token(provider, refresh_tok)
                    write_tokens(paths, profile_key, new_oauth)
                    # Layer 3 (S3 push) + remote push bundled here
                    _distribute(new_oauth, profile_key, config)
                    _write_ts(LAST_SELF_REFRESH_FILE, now_ms)
                    log.info("Layer 1: API refresh succeeded")
                    return 0
                except InvalidGrantError as e:
                    log.warning("Layer 1: InvalidGrant — %s; escalating", e)
                    _notify_slack(config,
                                  f"[oauth-manager] InvalidGrant for {provider}: {e}")
                except ProviderUnavailableError as e:
                    log.warning("Layer 1: provider unavailable — %s; escalating", e)
                except Exception as e:
                    log.warning("Layer 1: unexpected error — %s; escalating", e)
            else:
                log.warning("Layer 1: no refresh_token present — skipping API refresh")
        else:
            log.info("Layer 1: skipped (cooldown or S3/local token still valid)")
    else:
        log.info("Layer 1: provider %s does not support API refresh — skipping", provider)

    # ── Layer 2: S3 Pull (multi-server setups) ──
    if multi_server:
        log.info("Layer 2: attempting S3 pull")
        s3_token = download_from_s3(config, profile_key)
        s3_expires = s3_token.get("expires", 0) if s3_token else 0
        if s3_token and should_update_from_s3(s3_expires, local_expires, now_ms):
            write_tokens(paths, profile_key, s3_token)
            new_health = token_health(s3_expires, now_ms)
            log.info("Layer 2: updated from S3, new health=%s", new_health)
            if new_health in ("OK", "LOW"):
                return 0
            log.info("Layer 2: S3 token also not healthy — escalating to headless")
        else:
            log.info("Layer 2: S3 token not better than local — skipping update")
    else:
        log.info("Layer 2: single-server — skipping S3 pull")

    # ── Layer 4: Headless Recovery ──
    last_headless_ts = _read_ts(LAST_HEADLESS_FILE)
    if not should_headless_recover(last_headless_ts, now_ms, HEADLESS_COOLDOWN_MS):
        remaining_min = (HEADLESS_COOLDOWN_MS - (now_ms - last_headless_ts)) / 60_000
        log.warning(
            "Layer 4: headless recovery on cooldown (%.1f min remaining) — giving up",
            remaining_min,
        )
        _notify_slack(
            config,
            f"[oauth-manager] Token {health} for {provider} and headless on cooldown",
        )
        return 1

    log.info("Layer 4: triggering headless recovery")
    _write_ts(LAST_HEADLESS_FILE, now_ms)

    try:
        import headless_reauth  # noqa: F401
        if not hasattr(headless_reauth, "recover_all"):
            log.error(
                "Layer 4: headless_reauth.recover_all() not yet available — "
                "module needs adaptation (Task 6+)"
            )
            _notify_slack(
                config,
                f"[oauth-manager] Token {health} for {provider}; "
                "headless_reauth.recover_all() not yet implemented",
            )
            return 1
        headless_reauth.recover_all(config)
        log.info("Layer 4: headless_reauth.recover_all() completed")
        return 0
    except ImportError as e:
        log.error("Layer 4: headless_reauth not importable: %s", e)
        _notify_slack(
            config,
            f"[oauth-manager] Token {health} for {provider}; "
            f"headless_reauth import failed: {e}",
        )
        return 1
    except Exception as e:
        log.error("Layer 4: headless recovery failed: %s", e)
        _notify_slack(
            config,
            f"[oauth-manager] Headless recovery failed for {provider}: {e}",
        )
        return 1


# ── CLI entry point ─────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oauth_manager",
        description="OpenClaw OAuth Manager — layered token health and recovery",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for cmd_name, help_text in [
        ("check",   "Run full health check and layered recovery loop"),
        ("refresh", "Force an API token refresh"),
        ("recover", "Trigger headless browser re-authentication"),
        ("status",  "Print token health summary"),
    ]:
        sp = sub.add_parser(cmd_name, help=help_text)
        sp.add_argument(
            "--config",
            metavar="PATH",
            default=None,
            help="Path to config.json (default: search ./config.json then ~/.openclaw-oauth/config.json)",
        )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "check":   cmd_check,
        "refresh": cmd_refresh,
        "recover": cmd_recover,
        "status":  cmd_status,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
