#!/usr/bin/env bash
# token-refresh-cron.sh — Lightweight, provider-agnostic OAuth token refresh.
# Reads provider config from server-config.env, checks oauth-token-cache.json,
# refreshes if < 2h remaining, and propagates to all auth-profiles.
# Designed as a cron backup for the systemd health timer.
# Runs every 15 min via cron.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/server-config.env"
LOGDIR="$HOME/.openclaw/logs"
LOG="$LOGDIR/token-refresh-cron.log"
CACHE="$HOME/.openclaw/oauth-token-cache.json"
REFRESH_LOCK="/tmp/openclaw-token-refresh.lock"

mkdir -p "$LOGDIR"

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" >> "$LOG"; }

# Rotate log
if [ -f "$LOG" ] && [ "$(wc -l < "$LOG" 2>/dev/null || echo 0)" -gt 300 ]; then
  tail -n 100 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

# Load config
if [ ! -f "$CONFIG" ]; then
  log "ERROR: No server-config.env at $CONFIG"
  exit 1
fi
set -a; source "$CONFIG"; set +a

# Check token health
TOKEN_MINS=$(python3 -c "
import json, time, os
try:
    with open(os.path.expanduser('$CACHE')) as f:
        d = json.load(f)
    print(int((d.get('expires', 0)/1000 - time.time()) / 60))
except:
    print('-9999')
" 2>/dev/null || echo "-9999")

if [ "$TOKEN_MINS" -gt 120 ]; then
  log "OK: Token healthy (${TOKEN_MINS}m remaining)"
  exit 0
fi

log "Token needs refresh (${TOKEN_MINS}m remaining). Attempting..."

# Acquire lock (prevent races with health script)
exec 200>"$REFRESH_LOCK"
if ! flock -n 200; then
  log "SKIP: Another refresh holds the lock"
  exit 0
fi

# Clear stale lock
if [ -f "$REFRESH_LOCK" ]; then
  lock_age=$(( $(date +%s) - $(stat -c %Y "$REFRESH_LOCK" 2>/dev/null || date +%s) ))
  if [ "$lock_age" -gt 600 ]; then
    log "Clearing stale lock (${lock_age}s old)"
  fi
fi

# Refresh token (provider-agnostic)
export CACHE_PATH="$CACHE"
RESULT=$(python3 << 'PYREFRESH'
import json, time, urllib.request, os, sys, glob

cache_path = os.environ.get("CACHE_PATH", "")
client_id = os.environ.get("OAUTH_CLIENT_ID", "")
token_url = os.environ.get("OAUTH_TOKEN_URL", "")
provider = os.environ.get("OAUTH_PROVIDER", "")

try:
    with open(cache_path) as f:
        cache = json.load(f)
except:
    print("FAIL:no cache")
    sys.exit(1)

refresh = cache.get("refresh", "")
if not refresh:
    print("FAIL:no refresh token")
    sys.exit(1)

# Build payload based on provider
if provider == "openai":
    import urllib.parse
    payload = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh,
    }).encode()
    content_type = "application/x-www-form-urlencoded"
else:
    payload = json.dumps({
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh,
    }).encode()
    content_type = "application/json"

req = urllib.request.Request(
    token_url,
    data=payload,
    headers={"Content-Type": content_type, "User-Agent": "OpenClaw/1.0"},
    method="POST"
)

try:
    resp = urllib.request.urlopen(req, timeout=15)
    result = json.loads(resp.read().decode())

    if "access_token" not in result:
        print(f"FAIL:{result.get('error', 'no access_token')}")
        sys.exit(1)

    new_cache = {**cache}
    new_cache["access"] = result["access_token"]
    new_cache["expires"] = int(time.time()*1000) + result["expires_in"]*1000 - 5*60*1000
    if "refresh_token" in result:
        new_cache["refresh"] = result["refresh_token"]

    # Atomic write to cache
    tmp = cache_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(new_cache, f)
    os.replace(tmp, cache_path)

    # Propagate to all auth-profiles
    profile_key = "anthropic:oauth" if "claude" in token_url else "openai-codex:codex-cli"
    paths = glob.glob(os.path.expanduser("~/.openclaw/auth-profiles.json")) + \
            glob.glob(os.path.expanduser("~/.openclaw/agents/*/agent/auth-profiles.json"))
    updated = 0
    for p in paths:
        try:
            with open(p) as f:
                d = json.load(f)
            d.setdefault("profiles", {})[profile_key] = new_cache
            t = p + ".tmp"
            with open(t, "w") as f:
                json.dump(d, f)
            os.replace(t, p)
            updated += 1
        except:
            pass

    hours = round(result["expires_in"] / 3600, 1)
    print(f"OK:{hours}h,{updated}files")

except urllib.error.HTTPError as e:
    body = ""
    try: body = e.read().decode()[:200]
    except: pass
    print(f"FAIL:HTTP {e.code} {body}")
    sys.exit(1)
except Exception as e:
    print(f"FAIL:{e}")
    sys.exit(1)
PYREFRESH
)

log "Refresh result: $RESULT"

# ── S3 upload after successful refresh ───────────────────────────────────
# Workers (Cliqk, etc.) pull from S3 every 5 min. Uploading here closes the
# distribution loop so refresh tokens stay synchronized across the fleet.
if echo "$RESULT" | grep -q "^OK:"; then
  UPLOAD_RESULT=$(python3 << 'PYUPLOAD'
import json, os
try:
    import boto3
    with open(os.path.expanduser("~/.openclaw/oauth-token-cache.json")) as f:
        cache = json.load(f)
    envelope = {"version": 1, "profiles": {"openai-codex:codex-cli": cache}}
    tmp = "/tmp/oauth-s3-upload.json"
    with open(tmp, "w") as f:
        json.dump(envelope, f)
    s3 = boto3.client("s3", region_name="us-east-2")
    s3.upload_file(tmp, "openclaw-secrets-429835537523", "oauth/openai-auth-profiles.json")
    os.remove(tmp)
    print("S3_OK")
except Exception as e:
    print(f"S3_FAIL:{e}")
PYUPLOAD
)
  log "S3 upload: $UPLOAD_RESULT"
fi
