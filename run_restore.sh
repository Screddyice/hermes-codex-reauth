#!/bin/bash
# Headless server-side Hermes codex reauth launcher (Xvfb + Chrome via CDP).
# Called synchronously by the self-healing keepalive, or standalone for a manual reauth.
HERE="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")" && pwd)"
cd "$HERE" || exit 1
PY="$HERE/.venv/bin/python"; [ -x "$PY" ] || PY="python3"
echo "launcher start $(date -u +%H:%M:%S)" > /tmp/restore_reauth.out
exec xvfb-run -a -s "-screen 0 1280x720x24" "$PY" restore_reauth.py >> /tmp/restore_reauth.out 2>&1
