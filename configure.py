#!/usr/bin/env python3
"""
configure.py — Interactive setup wizard for OpenClaw OAuth Manager.

Usage:
  python3 configure.py                          # Full setup
  python3 configure.py --reconfigure provider   # Reconfigure one section
  python3 configure.py --reconfigure all        # Redo everything
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
VALID_SECTIONS = ["role", "provider", "credentials", "distribution", "servers",
                  "gmail", "slack", "proxy", "schedule", "all"]


def ask_choice(prompt, options):
    """Ask user to pick from numbered options. Returns the value."""
    print(f"\n{prompt}")
    for i, (label, value) in enumerate(options, 1):
        print(f"  [{i}] {label}")
    while True:
        try:
            choice = int(input("\nChoice: ").strip())
            if 1 <= choice <= len(options):
                return options[choice - 1][1]
        except (ValueError, EOFError):
            pass
        print(f"Please enter a number 1-{len(options)}")


def ask_text(prompt, default=""):
    """Ask for text input with optional default."""
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def ask_yn(prompt, default=True):
    """Ask yes/no question."""
    suffix = " [Y/n]" if default else " [y/N]"
    value = input(f"{prompt}{suffix}: ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes")


# ── Environment Detection ──────────────────────────────────────────────

def detect_environment():
    """Auto-detect OS, Chrome, OpenClaw install, Python packages."""
    env = {"os": platform.system(), "chrome_path": None, "openclaw_installed": False,
           "installed_packages": []}

    # Chrome paths
    chrome_paths = {
        "Darwin": ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"],
        "Linux": ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
                  "/usr/bin/chromium-browser", "/snap/bin/chromium"],
    }
    for p in chrome_paths.get(env["os"], []):
        if os.path.exists(p):
            env["chrome_path"] = p
            break

    # OpenClaw install
    env["openclaw_installed"] = os.path.exists(os.path.expanduser("~/.openclaw"))

    # Installed packages
    for pkg in ["boto3", "playwright", "pytest"]:
        try:
            __import__(pkg)
            env["installed_packages"].append(pkg)
        except ImportError:
            pass

    return env


# ── Wizard Sections ────────────────────────────────────────────────────

def ask_role(config):
    role = ask_choice("How are you using this?", [
        ("Single server (standalone)", "standalone"),
        ("Multiple servers — this is the authority (refreshes + distributes)", "authority"),
        ("Multiple servers — this is a receiver (pulls from authority)", "receiver"),
    ])
    config["role"] = role
    return config


def ask_provider(config):
    provider = ask_choice("Which AI provider does this server use?", [
        ("Claude.ai (Anthropic)", "claude"),
        ("ChatGPT (OpenAI)", "chatgpt"),
        ("Gemini (Google)", "gemini"),
        ("Perplexity", "perplexity"),
    ])
    config["provider"] = provider
    if provider == "gemini":
        print("\n  Note: Gemini access tokens expire in ~60 minutes.")
        print("  Setting refresh_threshold_hours to 0.5 (30 min).")
        config["refresh_threshold_hours"] = 0.5
    return config


def ask_credentials(config):
    provider = config.get("provider", "claude")
    if provider == "perplexity":
        config["api_key"] = ask_text("Perplexity API key (pplx-...)")
        config["email"] = ""
        config["password"] = ""
    else:
        config["email"] = ask_text(f"Login email for {provider}")
        if provider in ("chatgpt", "gemini"):
            config["password"] = ask_text("Google account password (for Google Sign-In)")
        else:
            config["password"] = ""
            print("  Claude uses magic link login — no password needed.")
        config["api_key"] = ""
    return config


def ask_distribution(config):
    if config.get("role") not in ("authority", "receiver"):
        return config
    print("\n--- S3 Distribution ---")
    bucket = ask_text("S3 bucket for token sharing")
    config["s3"] = {
        "bucket": bucket,
        "key": ask_text("S3 key", default="oauth/tokens.json"),
        "region": ask_text("AWS region", default="us-east-2"),
    }
    return config


def ask_remote_servers(config):
    if config.get("role") != "authority":
        return config
    print("\n--- Remote Servers ---")
    print("Add servers to push tokens to.\n")
    servers = {}
    while True:
        name = ask_text("Server name (e.g., PROD, STAGING)")
        if not name:
            break
        srv = {
            "hostname": ask_text("SSH host (alias or IP)"),
            "ssh_user": ask_text("SSH user", default="ubuntu"),
            "ssh_key": ask_text("SSH key path", default="~/.ssh/id_ed25519"),
            "instance_id": ask_text("EC2 instance ID (optional, press Enter to skip)"),
            "provider": ask_text("Provider for this server", default=config.get("provider", "claude")),
            "email": ask_text("Login email for headless recovery on this server"),
            "password": "",
        }
        if srv["provider"] in ("chatgpt", "gemini"):
            srv["password"] = ask_text("Google password for this server")
        servers[name] = srv
        if not ask_yn("Add another server?", default=False):
            break
    config["servers"] = servers
    return config


def ask_headless(config, env):
    if config.get("provider") == "perplexity":
        config["headless_enabled"] = False
        return config
    enabled = ask_yn("Enable headless browser recovery as a fallback?")
    config["headless_enabled"] = enabled
    if not enabled:
        return config
    chrome = ask_text("Chrome path", default=env.get("chrome_path", ""))
    config["chrome_path"] = chrome
    if config.get("provider") == "claude":
        if ask_yn("Set up Gmail API for magic link login?"):
            print("\n  Run: python3 setup_gmail.py --client-id YOUR_ID --client-secret YOUR_SECRET --email YOUR_EMAIL")
            print("  Then add the credentials to config.json under 'gmail'.\n")
    return config


def ask_proxy(config):
    print("\n--- Residential Proxy (Webshare) ---")
    print("Datacenter server IPs get provider sign-in blocked / verification emails suppressed.")
    if not ask_yn("Route headless logins through a Webshare residential proxy?", default=False):
        config["proxy"] = {"enabled": False, "mode": "ip_auth",
                           "endpoint": "p.webshare.io:80", "username": "",
                           "password": "", "local_forwarder_port": 1080}
        return config
    mode = ask_choice("Webshare auth mode?", [
        ("IP whitelist (server IP authorized in Webshare dashboard) — recommended", "ip_auth"),
        ("Username/password (local credential forwarder)", "userpass"),
    ])
    proxy = {
        "enabled": True,
        "mode": mode,
        "endpoint": ask_text("Webshare endpoint host:port", default="p.webshare.io:80"),
        "username": "",
        "password": "",
        "local_forwarder_port": 1080,
    }
    if mode == "userpass":
        proxy["username"] = ask_text("Webshare proxy username")
        proxy["password"] = ask_text("Webshare proxy password")
        proxy["local_forwarder_port"] = int(ask_text("Local forwarder port", default="1080"))
    else:
        print("\n  IP-auth mode: whitelist this server's egress IP in the Webshare dashboard")
        print("  (Proxy > IP Authorization). See docs/DEPLOY-webshare-proxy.md.")
    config["proxy"] = proxy
    return config


def ask_notifications(config):
    if not ask_yn("Send Slack alerts on failure?", default=False):
        config["slack"] = {"bot_token": "", "channel": ""}
        return config
    config["slack"] = {
        "bot_token": ask_text("Slack bot token (xoxb-...)"),
        "channel": ask_text("Slack channel or user ID"),
    }
    return config


def ask_schedule(config, env):
    if not ask_yn("Set up automatic health checks?"):
        return config
    interval = int(ask_text("Check interval in minutes", default="15"))
    config["check_interval_minutes"] = interval
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "oauth_manager.py"))

    if env["os"] == "Darwin":
        plist_name = "com.openclaw-oauth.check"
        plist_path = os.path.expanduser(f"~/Library/LaunchAgents/{plist_name}.plist")
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{plist_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{script_path}</string>
        <string>check</string>
    </array>
    <key>StartInterval</key><integer>{interval * 60}</integer>
    <key>StandardOutPath</key><string>/tmp/openclaw-oauth-stdout.log</string>
    <key>StandardErrorPath</key><string>/tmp/openclaw-oauth-stderr.log</string>
</dict>
</plist>"""
        print(f"\n  launchd plist:\n{plist}\n")
        if ask_yn(f"Install to {plist_path}?"):
            with open(plist_path, "w") as f:
                f.write(plist)
            subprocess.run(["launchctl", "load", plist_path], capture_output=True)
            print(f"  Installed and loaded: {plist_path}")
    else:
        cron_line = f"*/{interval} * * * * {sys.executable} {script_path} check >> /var/log/openclaw-oauth.log 2>&1"
        print(f"\n  Cron entry:\n  {cron_line}\n")
        if ask_yn("Add to crontab?"):
            existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
            if cron_line not in existing:
                new_crontab = existing.rstrip() + "\n" + cron_line + "\n"
                subprocess.run(["crontab", "-"], input=new_crontab, text=True, capture_output=True)
                print("  Added to crontab.")
    return config


def install_dependencies(config, env):
    if not ask_yn("Install required Python packages?"):
        return
    deps = ["pytest"]
    if config.get("s3", {}).get("bucket"):
        deps.append("boto3")
    if config.get("headless_enabled"):
        deps.append("playwright")
    missing = [d for d in deps if d not in env.get("installed_packages", [])]
    if not missing:
        print("  All dependencies already installed.")
        return
    print(f"  Installing: {', '.join(missing)}")
    subprocess.run([sys.executable, "-m", "pip", "install"] + missing)
    if "playwright" in missing:
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"])


def validate_config(config):
    print("\n--- Validation ---")
    ok = True
    # SSH
    for name, srv in config.get("servers", {}).items():
        hostname = srv.get("hostname")
        ssh_key = os.path.expanduser(srv.get("ssh_key", "~/.ssh/id_ed25519"))
        ssh_user = srv.get("ssh_user", "ubuntu")
        try:
            result = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-o", "BatchMode=yes", "-i", ssh_key,
                 f"{ssh_user}@{hostname}", "echo ok"],
                capture_output=True, text=True, timeout=10,
            )
            status = "OK" if result.returncode == 0 else "FAIL"
        except Exception:
            status = "FAIL"
        print(f"  SSH {name} ({hostname}): {status}")
        if status == "FAIL":
            ok = False
    # S3
    bucket = config.get("s3", {}).get("bucket")
    if bucket:
        try:
            import boto3
            s3 = boto3.client("s3", region_name=config["s3"].get("region", "us-east-2"))
            s3.head_bucket(Bucket=bucket)
            print(f"  S3 {bucket}: OK")
        except Exception as e:
            print(f"  S3 {bucket}: FAIL ({e})")
            ok = False
    if ok:
        print("\n  All validations passed!")
    else:
        print("\n  Some validations failed. You can fix these later and re-run configure.py --reconfigure <section>")


def write_config(config, path=None):
    path = path or CONFIG_PATH
    # Set defaults for fields not covered by wizard
    config.setdefault("check_interval_minutes", 15)
    config.setdefault("refresh_threshold_hours", 4)
    config.setdefault("headless_recovery_cooldown_minutes", 30)
    config.setdefault("headless_enabled", True)
    config.setdefault("callback_port", 19876)
    config.setdefault("screenshot_dir", "~/.openclaw-oauth/screenshots")
    config.setdefault("browser_profile_dir", "~/.openclaw-oauth/browser-profiles")
    config.setdefault("servers", {})
    config.setdefault("s3", {"bucket": "", "key": "oauth/tokens.json", "region": "us-east-2"})
    config.setdefault("gmail", {"default": {"client_id": "", "client_secret": "",
                                            "refresh_token": "", "token_uri": "https://oauth2.googleapis.com/token",
                                            "email": ""}})
    config.setdefault("slack", {"bot_token": "", "channel": ""})
    config.setdefault("proxy", {"enabled": False, "mode": "ip_auth",
                                "endpoint": "p.webshare.io:80", "username": "",
                                "password": "", "local_forwarder_port": 1080})

    with open(path, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(path, 0o600)
    print(f"\n  Config written to: {path}")
    print(f"  Run: python3 oauth_manager.py check")


# ── Main ───────────────────────────────────────────────────────────────

SECTION_MAP = {
    "role": ask_role,
    "provider": ask_provider,
    "credentials": ask_credentials,
    "distribution": ask_distribution,
    "servers": ask_remote_servers,
    "notifications": ask_notifications,
    "slack": ask_notifications,
    "proxy": ask_proxy,
}


def main():
    parser = argparse.ArgumentParser(description="OpenClaw OAuth Manager — Setup Wizard")
    parser.add_argument("--reconfigure", metavar="SECTION",
                        help=f"Reconfigure one section: {', '.join(VALID_SECTIONS)}")
    parser.add_argument("--output", default=None, help="Output path for config.json")
    args = parser.parse_args()

    env = detect_environment()

    if args.reconfigure:
        section = args.reconfigure
        if section not in VALID_SECTIONS:
            print(f"Unknown section: {section}. Valid: {', '.join(VALID_SECTIONS)}")
            sys.exit(1)
        # Load existing config
        if not os.path.exists(CONFIG_PATH):
            print("No existing config.json found. Run without --reconfigure first.")
            sys.exit(1)
        with open(CONFIG_PATH) as f:
            config = json.load(f)
        if section == "all":
            # Re-run everything
            pass
        elif section in SECTION_MAP:
            config = SECTION_MAP[section](config)
            write_config(config, args.output)
            return
        elif section == "gmail":
            print("Run: python3 setup_gmail.py --client-id YOUR_ID --client-secret YOUR_SECRET --email YOUR_EMAIL")
            print("Then update config.json gmail section manually.")
            return
        elif section == "schedule":
            config = ask_schedule(config, env)
            write_config(config, args.output)
            return

    # Full wizard
    print("=" * 50)
    print("  OpenClaw OAuth Manager — Setup")
    print("=" * 50)

    # Environment detection
    print(f"\n  OS: {env['os']}")
    print(f"  Chrome: {env['chrome_path'] or 'not found'}")
    print(f"  OpenClaw: {'installed' if env['openclaw_installed'] else 'not found'}")
    print(f"  Packages: {', '.join(env['installed_packages']) or 'none'}")

    config = {}
    config = ask_role(config)
    config = ask_provider(config)
    config = ask_credentials(config)
    config = ask_distribution(config)
    config = ask_remote_servers(config)
    config = ask_headless(config, env)
    config = ask_proxy(config)
    config = ask_notifications(config)
    config = ask_schedule(config, env)
    install_dependencies(config, env)
    validate_config(config)
    write_config(config, args.output)


if __name__ == "__main__":
    main()
