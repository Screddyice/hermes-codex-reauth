"""Observed restore reauth for Hermes codex.

Fix vs auto_reauth_hermes.py (Jun 20 stall): drive the browser to *type*
hermes' user_code into the auth.openai.com/codex/device code field (NOT a URL
param) so the approval binds to hermes' device_auth_id and the auto-poll completes.

Flow:
1. `hermes auth add openai-codex --type oauth --no-browser` via PTY; answer the
   "Import these credentials? [y/N]" prompt with 'n' (fresh independent session),
   capture the printed user_code.
2. Launch logged-in Chrome (chrome-auto profile, proxy as configured). If the
   session is logged out, do email + Gmail-OTP login.
3. Go to /codex/device, TYPE the user_code, submit, approve consent.
4. hermes' poll returns 200, saves tokens, exits 0. Stream until exit + verify.
"""
import sys, os, pty, subprocess, select, re, time, json, urllib.parse, urllib.request, urllib.error
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from headless_reauth import launch_chrome_cdp, cleanup_chrome, save_screenshot
from playwright.sync_api import sync_playwright

EMAIL = "shawn.reddy1@gmail.com"
GMAIL_CRED = "/home/ubuntu/.openclaw/gmail-oauth-credentials.json"
PWFILE = "/home/ubuntu/.openclaw/oai-password"
HERMES_PY = "/home/ubuntu/.hermes/hermes-agent/venv/bin/python"

def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

def wait_cdp(port, t=30):
    d = time.time() + t
    while time.time() < d:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=2).read(); return True
        except Exception: time.sleep(1)
    return False

def gmail_token():
    c = json.load(open(GMAIL_CRED))
    body = urllib.parse.urlencode({"client_id": c["client_id"], "client_secret": c["client_secret"],
        "refresh_token": c["refresh_token"], "grant_type": "refresh_token"}).encode()
    return json.loads(urllib.request.urlopen(urllib.request.Request("https://oauth2.googleapis.com/token",
        data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"), timeout=20).read())["access_token"]

def poll_otp(after_ms, timeout=120, interval=5):
    h = {"Authorization": "Bearer " + gmail_token()}
    q = urllib.parse.quote('from:openai.com (code OR "login code" OR verification)')
    end = time.time() + timeout
    while time.time() < end:
        r = json.loads(urllib.request.urlopen(urllib.request.Request(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=5&q=" + q, headers=h), timeout=20).read())
        for m in r.get("messages", []):
            full = json.loads(urllib.request.urlopen(urllib.request.Request(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{m['id']}?format=full", headers=h), timeout=20).read())
            if int(full.get("internalDate", "0")) < after_ms: continue
            txt = ({x["name"]: x["value"] for x in full["payload"].get("headers", [])}).get("Subject", "") + " " + full.get("snippet", "")
            codes = re.findall(r'\b(\d{6})\b', txt)
            if codes: return codes[0]
        time.sleep(interval)
    return None

def start_hermes_device():
    """Start `hermes auth add openai-codex`; answer import prompt 'n'; return (proc, master_fd, user_code)."""
    master, slave = os.openpty()
    proc = subprocess.Popen(
        [HERMES_PY, "-m", "hermes_cli.main", "auth", "add", "openai-codex", "--type", "oauth", "--no-browser"],
        stdout=slave, stderr=slave, stdin=slave, close_fds=True)
    os.close(slave)
    buf = b""; code = None; answered = False; end = time.time() + 120
    while time.time() < end and code is None:
        r, _, _ = select.select([master], [], [], 2)
        if master in r:
            try: data = os.read(master, 4096)
            except OSError: break
            if not data: break
            buf += data
            try: sys.stdout.write("HERMES> " + data.decode(errors="replace")); sys.stdout.flush()
            except Exception: pass
            if (not answered) and re.search(rb'[Ii]mport these credentials', buf):
                os.write(master, b"n\n"); answered = True; log(">>> answered import prompt: n")
            # capture the device user_code (printed after 'Enter this code:')
            m = re.search(rb'Enter this code:[^\n]*\n[^\n]*?([A-Z0-9]{4}-[A-Z0-9]{4,6})', buf)
            if not m:
                m = re.search(rb'\x1b\[94m([A-Z0-9]{4}-[A-Z0-9]{4,6})\x1b', buf)
            if not m:
                m = re.search(rb'\b([A-Z0-9]{4}-[A-Z0-9]{4,6})\b', buf)
            if m: code = m.group(1).decode()
    return proc, master, code

def _logged_in(pg):
    return "chatgpt.com" in pg.url and "/auth" not in pg.url and "login" not in pg.url

def dismiss_cookie(pg):
    for t in ["Reject non-essential", "Accept all", "Accept"]:
        try:
            cb = pg.locator(f'button:has-text("{t}")').first
            if cb.is_visible(timeout=1500): cb.click(); time.sleep(1); return
        except Exception: pass

def ensure_login(pg):
    """If the device page bounced us to login, do email + Gmail-OTP (password fallback)."""
    if "/codex/device" in pg.url and "login" not in pg.url and "/auth" not in pg.url:
        return True  # already on the device page, logged in
    em = pg.locator('input[type=email], input[name=email], input[autocomplete=username]').first
    try: em.wait_for(state="visible", timeout=6000)
    except Exception:
        log(f"no email field; assuming logged in (url={pg.url})"); return True
    em.fill(EMAIL); pg.locator('button[type=submit]').first.click(); log("email submitted"); time.sleep(6)
    # prefer one-time-code path
    otc = pg.locator('button:has-text("one-time code"), a:has-text("one-time code")').first
    try:
        otc.wait_for(state="visible", timeout=8000)
        req_ms = int(time.time() * 1000); otc.click(); log("requested one-time code"); time.sleep(6)
        code = poll_otp(req_ms, timeout=120); log(f"OTP={code}")
        if code:
            f = pg.locator('input[autocomplete="one-time-code"], input[inputmode=numeric], input[name*=code]')
            if f.count() >= 6:
                for i, ch in enumerate(code): f.nth(i).fill(ch)
            else: f.first.fill(code)
            time.sleep(1)
            try: pg.locator('button[type=submit], button:has-text("Continue"), button:has-text("Verify")').first.click(timeout=4000)
            except Exception: f.last.press("Enter")
            time.sleep(6); return True
    except Exception:
        pass
    # password fallback
    try:
        pw = open(PWFILE).read().strip()
        pf = pg.locator('input[type=password]').first
        pf.wait_for(state="visible", timeout=10000); pf.fill(pw)
        pg.locator('button[type=submit]').first.click(); log("password submitted"); time.sleep(8); return True
    except Exception as e:
        log(f"login fallback failed: {e!r}"); return False

def _boxes_value(pg):
    """Concatenate the segmented box values to verify what actually got entered."""
    try:
        return pg.eval_on_selector_all(
            'input[autocomplete="one-time-code"]',
            "els => els.map(e => (e.value||'').trim()).join('')")
    except Exception:
        return ""

def fill_device_code(pg, code9):
    """Type the dash-stripped code into the auto-advancing segmented input.

    Per-box fill() drops chars (the OTP component moves focus on each input),
    so focus the first box and let keyboard auto-advance place every char.
    Retries with a clear if the concatenated value doesn't match.
    """
    box1 = pg.locator('input[autocomplete="one-time-code"]').first
    if not (box1.count() and box1.is_visible()):
        f = pg.locator('input[type=text]:visible, input:not([type=hidden])').first
        if not (f.count() and f.is_visible()): return False
        box1 = f
    for attempt in range(3):
        try:
            box1.click()
            for _ in range(14): pg.keyboard.press("Backspace")
            box1.click()
        except Exception: pass
        box1.type(code9, delay=90)
        time.sleep(0.8)
        got = _boxes_value(pg)
        log(f"typed code attempt {attempt}: got='{got}' want='{code9}'")
        if got.upper() == code9.upper():
            return True
    return True  # proceed anyway; Continue enablement is the real gate

def click_primary(pg, labels):
    for lbl in labels:
        try:
            b = pg.locator(f'button:has-text("{lbl}")').first
            if b.is_visible(timeout=1000) and b.is_enabled():
                b.click(); log(f"clicked {lbl}"); return True
        except Exception: pass
    return False

def approve(pg, user_code, proc):
    """Drive device approval. Success signal is hermes completion (proc exit), NOT the browser URL."""
    code9 = user_code.replace("-", "").strip()
    pg.goto("https://auth.openai.com/codex/device", wait_until="domcontentloaded", timeout=45000); time.sleep(4)
    dismiss_cookie(pg)
    if ("login" in pg.url or "/auth/login" in pg.url) and "choose-an-account" not in pg.url:
        log(f"not logged in (url={pg.url}) — running login"); ensure_login(pg)
        pg.goto("https://auth.openai.com/codex/device", wait_until="domcontentloaded", timeout=45000); time.sleep(3)
    submitted = False
    stuck = 0
    for step in range(18):
        if proc.poll() is not None:
            log("hermes exited during approval loop"); return True
        u = pg.url; save_screenshot(pg, f"restore-{step}"); log(f"step {step}: url={u} submitted={submitted}")
        # transient ChatGPT route error ("Oops, an error occurred" / Try again)
        try:
            body_txt = (pg.inner_text("body") or "")
        except Exception:
            body_txt = ""
        if "an error occurred" in body_txt or "Route Error" in body_txt or "Try again" in body_txt:
            log("transient error page — re-navigating to /codex/device")
            pg.goto("https://auth.openai.com/codex/device", wait_until="domcontentloaded", timeout=45000)
            time.sleep(4); stuck += 1
            if stuck >= 4: log("too many error retries"); return submitted
            continue
        # account chooser
        if "choose-an-account" in u or "choose_account" in u:
            try:
                tile = pg.locator(f'button:has-text("{EMAIL}"), [role=button]:has-text("{EMAIL}"), li:has-text("{EMAIL}"), a:has-text("{EMAIL}")').first
                if not (tile.count() and tile.is_visible(timeout=1000)):
                    tile = pg.locator(f'text={EMAIL}').first
                if tile.is_visible(timeout=1500):
                    tile.click(); log("clicked account tile")
                    try: pg.wait_for_load_state("networkidle", timeout=8000)
                    except Exception: pass
                    time.sleep(2); continue
            except Exception as e: log(f"acct tile err {e!r}")
        boxes = pg.locator('input[autocomplete="one-time-code"]')
        has_boxes = False
        try: has_boxes = boxes.count() >= 1 and boxes.first.is_visible(timeout=1000)
        except Exception: has_boxes = False
        if has_boxes and not submitted:
            try: empty = not (boxes.first.input_value() or "").strip()
            except Exception: empty = True
            if empty: fill_device_code(pg, code9)
            time.sleep(1)
            # explicitly submit the device grant
            if click_primary(pg, ["Continue", "Authorize", "Grant access", "Allow", "Confirm", "Approve"]):
                submitted = True
            time.sleep(3); continue
        # post-submit consent screens
        if click_primary(pg, ["Continue", "Authorize", "Allow", "Confirm", "Approve"]):
            time.sleep(3); continue
        if "deviceauth/callback" in u and submitted:
            log("callback after submit — waiting for hermes poll"); time.sleep(3); continue
        log("nothing actionable this step"); time.sleep(3)
    log(f"approve loop done (submitted={submitted}, url={pg.url})")
    return submitted

def main():
    log("=== restore reauth start ===")
    proc, master, user_code = start_hermes_device()
    log(f"device user_code={user_code}")
    if not user_code:
        log("FAILED: no device code from hermes");
        try: proc.kill()
        except Exception: pass
        return 1
    cproc = cdp_port = fwd = None
    try:
        cproc, cdp_port, fwd = launch_chrome_cdp("auto", False); wait_cdp(cdp_port, 30)
        with sync_playwright() as p:
            b = p.chromium.connect_over_cdp(f"http://127.0.0.1:{cdp_port}")
            ctx = b.contexts[0] if b.contexts else b.new_context()
            pg = ctx.pages[0] if ctx.pages else ctx.new_page()
            approve(pg, user_code, proc)
    except Exception as e:
        log(f"browser error: {e!r}")
    finally:
        try: cleanup_chrome(None, cproc, fwd)
        except Exception: pass

    # Stream hermes until it polls 200 + saves + exits (device poll window is 15 min).
    log("--- waiting for hermes device poll to complete ---")
    end = time.time() + 240
    while time.time() < end:
        rc = proc.poll()
        try:
            r, _, _ = select.select([master], [], [], 1)
            if master in r:
                c = os.read(master, 4096)
                if c: sys.stdout.write("HERMES> " + c.decode(errors="replace")); sys.stdout.flush()
        except OSError: pass
        if rc is not None:
            log(f"hermes auth add exit={rc}")
            return 0 if rc == 0 else 2
    log("TIMEOUT waiting for hermes poll")
    try: proc.kill()
    except Exception: pass
    return 3

if __name__ == "__main__":
    sys.exit(main())
