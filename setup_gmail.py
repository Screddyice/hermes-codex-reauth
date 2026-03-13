#!/usr/bin/env python3
"""
setup_gmail.py — One-time Gmail API OAuth setup for reading verification emails.

Creates OAuth credentials for the Gmail readonly scope, which allows the
headless reauth script to poll for magic login links from Anthropic.

Prerequisites:
  1. Create a Google Cloud project at https://console.cloud.google.com
  2. Enable the Gmail API
  3. Create an OAuth consent screen (External, test mode)
  4. Add your email as a test user
  5. Create a Desktop app OAuth client ID
  6. Run this script with the client ID and secret

Usage:
  python3 setup_gmail.py --client-id YOUR_ID --client-secret YOUR_SECRET --email you@example.com
"""

import argparse
import http.server
import json
import os
import sys
import threading
import time
import urllib.parse
import urllib.request

REDIRECT_PORT = 19877
REDIRECT_URI = f"http://localhost:{REDIRECT_PORT}/callback"
SCOPES = "https://www.googleapis.com/auth/gmail.readonly"


def main():
    parser = argparse.ArgumentParser(description="Set up Gmail API OAuth for reading verification emails")
    parser.add_argument("--client-id", required=True, help="Google OAuth client ID")
    parser.add_argument("--client-secret", required=True, help="Google OAuth client secret")
    parser.add_argument("--email", required=True, help="Gmail address to authorize")
    parser.add_argument("--output", default=None, help="Output path for credentials JSON")
    args = parser.parse_args()

    output_path = args.output or os.path.expanduser("~/.headless-oauth/gmail-credentials.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print(f"Setting up Gmail API for {args.email}")
    print(f"Credentials will be saved to: {output_path}")
    print()

    # Start local callback server
    callback_result = {}
    server_ready = threading.Event()

    import subprocess
    subprocess.run(f"lsof -ti:{REDIRECT_PORT} 2>/dev/null | xargs kill -9 2>/dev/null", shell=True, capture_output=True)

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            code = params.get("code", [None])[0]
            if code:
                callback_result["code"] = code
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body style='font-family:sans-serif;text-align:center;padding:50px'><h2>Gmail API authorized!</h2><p>You can close this tab.</p></body></html>")
            else:
                self.send_response(200)
                self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", REDIRECT_PORT), CallbackHandler)

    def serve():
        server_ready.set()
        start = time.time()
        while "code" not in callback_result and (time.time() - start) < 300:
            server.handle_request()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    server_ready.wait()

    # Build auth URL
    auth_params = {
        "client_id": args.client_id,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPES,
        "access_type": "offline",
        "prompt": "consent",
        "login_hint": args.email,
    }
    auth_url = f"https://accounts.google.com/o/oauth2/auth?{urllib.parse.urlencode(auth_params)}"

    print("Opening browser for authorization...")
    try:
        import subprocess
        subprocess.run(["open", auth_url], capture_output=True)
    except Exception:
        print(f"\nOpen this URL in your browser:\n{auth_url}\n")

    print("Waiting for authorization (5 min timeout)...")
    t.join(timeout=300)

    if "code" not in callback_result:
        print("ERROR: No authorization code received.")
        sys.exit(1)

    print("Got authorization code. Exchanging for tokens...")

    # Exchange code for tokens
    exchange_payload = urllib.parse.urlencode({
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "code": callback_result["code"],
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
    }).encode()

    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        data=exchange_payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        resp = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if hasattr(e, "read") else ""
        print(f"ERROR: Token exchange failed: HTTP {e.code} — {body[:300]}")
        sys.exit(1)

    if "refresh_token" not in result:
        print(f"ERROR: No refresh_token in response: {json.dumps(result)[:500]}")
        sys.exit(1)

    print(f"Token obtained. Expires in {result.get('expires_in', '?')}s")

    # Save credentials
    creds = {
        "client_id": args.client_id,
        "client_secret": args.client_secret,
        "refresh_token": result["refresh_token"],
        "token_uri": "https://oauth2.googleapis.com/token",
        "email": args.email,
    }

    with open(output_path, "w") as f:
        json.dump(creds, f, indent=2)
    os.chmod(output_path, 0o600)

    print(f"\nSaved to: {output_path}")
    print()
    print("Add these values to your config.json under 'gmail':")
    print(json.dumps({"gmail": {"default": creds}}, indent=2))
    print()
    print("Done! Gmail API is ready.")


if __name__ == "__main__":
    main()
