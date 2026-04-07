#!/usr/bin/env bash
# pull-fresh-tokens-from-s3.sh — Worker-only token pull.
#
# Downloads fresh OpenAI Codex tokens from S3 and writes them to the local
# oauth-token-cache.json plus every auth-profiles.json on disk.
#
# Workers never refresh. All refreshes happen on the token authority (NEB),
# which uploads the new token to S3 after each successful refresh. Workers
# poll S3 every 5 min via cron and update local state if S3 is fresher.
#
# Runs on worker nodes (Cliqk, etc.) every 5 minutes via cron.
# Logs to: ~/.openclaw/logs/s3-token-pull.log

set -uo pipefail

LOGDIR="$HOME/.openclaw/logs"
LOG="$LOGDIR/s3-token-pull.log"
CACHE="$HOME/.openclaw/oauth-token-cache.json"
SCRIPTS="$HOME/.openclaw/scripts"
mkdir -p "$LOGDIR"

log() { echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*" >> "$LOG"; }

# Rotate log
if [ -f "$LOG" ] && [ "$(wc -l < "$LOG" 2>/dev/null || echo 0)" -gt 300 ]; then
  tail -n 100 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
fi

# Load provider config (not strictly needed here, but kept for parity with NEB)
if [ -f "$SCRIPTS/server-config.env" ]; then
  set -a; source "$SCRIPTS/server-config.env"; set +a
fi

RESULT=$(CACHE_PATH="$CACHE" python3 << 'PYPULL'
import json, os, glob, time, sys

S3_BUCKET    = "openclaw-secrets-429835537523"
S3_KEY       = "oauth/openai-auth-profiles.json"
TMP          = "/tmp/s3-oauth-pull.json"
CACHE        = os.environ["CACHE_PATH"]
PROFILE_KEY  = "openai-codex:codex-cli"
PROFILE_SLOT = "openai-codex"

now = int(time.time() * 1000)

# Find local best expiry across all auth-profiles.json files
paths = glob.glob(os.path.expanduser("~/.openclaw/auth-profiles.json")) + \
        glob.glob(os.path.expanduser("~/.openclaw/agents/*/agent/auth-profiles.json"))

local_best = 0
for p in paths:
    try:
        with open(p) as f:
            d = json.load(f)
        exp = d.get("profiles", {}).get(PROFILE_KEY, {}).get("expires", 0)
        if exp > local_best:
            local_best = exp
    except Exception:
        pass

# Download from S3
try:
    import boto3
    s3 = boto3.client("s3", region_name="us-east-2")
    s3.download_file(S3_BUCKET, S3_KEY, TMP)
except Exception as e:
    hrs = round((local_best - now) / 3600000, 1) if local_best > now else 0
    print(f"S3_FAIL:{e} (local {hrs}h)")
    sys.exit(0)

# Parse S3 envelope
try:
    with open(TMP) as f:
        s3_data = json.load(f)
    s3_oauth = s3_data.get("profiles", {}).get(PROFILE_KEY, {})
    s3_exp = s3_oauth.get("expires", 0)
except Exception as e:
    print(f"PARSE_FAIL:{e}")
    sys.exit(0)

# Decide
if s3_exp <= now:
    hrs_ago = round((now - s3_exp) / 3600000, 1)
    local_hrs = round((local_best - now) / 3600000, 1) if local_best > now else 0
    print(f"S3_STALE:{hrs_ago}h ago (local {local_hrs}h)")
    sys.exit(0)

if s3_exp <= local_best:
    hrs = round((local_best - now) / 3600000, 1)
    print(f"LOCAL_OK:{hrs}h remaining")
    sys.exit(0)

# S3 is fresher — write to cache and all auth-profiles atomically
try:
    tmp = CACHE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s3_oauth, f)
    os.replace(tmp, CACHE)
except Exception as e:
    print(f"CACHE_FAIL:{e}")
    sys.exit(1)

updated = 0
for p in paths:
    try:
        with open(p) as f:
            d = json.load(f)
        d.setdefault("profiles", {})[PROFILE_KEY] = s3_oauth
        d.get("profiles", {}).pop(f"{PROFILE_SLOT}:api_key", None)
        d.setdefault("lastGood", {})[PROFILE_SLOT] = PROFILE_KEY
        t = p + ".tmp"
        with open(t, "w") as f:
            json.dump(d, f)
        os.replace(t, p)
        updated += 1
    except Exception:
        pass

hrs = round((s3_exp - now) / 3600000, 1)
print(f"UPDATED:{updated}files, {hrs}h remaining")
PYPULL
)

log "$RESULT"
