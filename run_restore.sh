#!/bin/bash
# Headless server-side Hermes codex reauth launcher (Xvfb + Chrome via CDP).
# Called synchronously by the self-healing keepalive, or standalone for a manual reauth.
cd /home/ubuntu/headless-oauth-recovery || exit 1
echo "launcher start $(date -u +%H:%M:%S)" > /tmp/restore_reauth.out
exec xvfb-run -a -s "-screen 0 1280x720x24" /home/ubuntu/headless-oauth-recovery/.venv/bin/python restore_reauth.py >> /tmp/restore_reauth.out 2>&1
