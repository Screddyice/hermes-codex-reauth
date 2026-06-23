# Fully server-side, self-healing Hermes codex reauth

Keeps the Hermes ChatGPT-plan codex OAuth credential alive on `neb-brain-hostinger`
with **zero human / Mac / browser-on-laptop involvement**. Replaces the old reactive
Mac LaunchAgent re-auth (which needed Shawn to click a browser on the Mac).

## The problem it solves

OpenAI's codex refresh token is **single-use and rotates on every refresh**. Two
processes refreshing the same token (the Hermes gateway + a separate keepalive warmup)
race and trip `refresh_token_reused`, which invalidates the whole token family
(access **and** refresh) — `401 token_invalidated` on every model call until a full
re-login. The old keepalive ran an *unconditional* refreshing `hermes -z` every 30 min,
so it was itself a frequent racer.

## Components

| File | Role |
|------|------|
| `codex_auth_probe.py` | Read-only auth check. Uses the **current** access token (no refresh, no rotation) against `chatgpt.com/backend-api/codex/responses`. Exit `0`=OK, `1`=BROKEN (definitive 401/invalidated), `2`=UNKNOWN (transient/5xx — never reauth on this). account_id is read from the JWT `https://api.openai.com/auth.chatgpt_account_id` claim. |
| `restore_reauth.py` | Headless device-code reauth. Runs `hermes auth add openai-codex` via a PTY, drives logged-in Chrome (Xvfb + Webshare proxy) to **type the user_code into the segmented 9-char field on `auth.openai.com/codex/device` and click Continue**, then lets hermes' device poll complete. |
| `run_restore.sh` | Xvfb launcher for `restore_reauth.py`. Synchronous (`exec`), returns the reauth exit code. |
| `deploy/codex-keepalive.sh` | The self-healing loop (runs on the `codex-keepalive.timer`). |

## Self-heal flow (`codex-keepalive.sh`)

1. **flock** — only one scheduled refresh/reauth at a time (kills keepalive-vs-keepalive
   and keepalive-vs-reauth races).
2. **Probe** (read-only). OK → exit, **no refresh, no race**. This is the common path and
   is why the new keepalive is no longer a refresh-racer.
3. Probe UNKNOWN (transient) → do nothing, don't flip state.
4. Probe BROKEN → try **one** `hermes -z` refresh, re-probe. Recovers the
   "access token merely expired, refresh token still good" case.
5. Still broken → refresh token is dead → run the **headless device-code reauth**
   (`run_restore.sh`), re-probe. On success, clear the stale `last_auth_error`.
6. Still broken after reauth (e.g. the OpenAI browser session itself expired) →
   **edge-triggered Slack alert** (ok→fail only) asking for a manual re-login.

## The device-code binding bug (why earlier attempts stalled)

The browser must **type hermes' `user_code` into the segmented input and click
Continue**. Earlier attempts failed two ways: (a) passing `?user_code=` in the URL and
never typing it (the grant never bound to hermes' `device_auth_id`, so its poll hung
15 min); (b) per-box `fill()` dropped a char on the auto-advancing OTP input, leaving
Continue disabled. The fix: focus the first box, `type()` the dash-stripped 9 chars
(component auto-advances), verify the concatenated value equals the code, then click
Continue explicitly. Success signal is **hermes completion** (`auth.json` rewritten),
not the browser URL (a stale `deviceauth/callback` from the sign-in consent is a red
herring).

## Also done (root-cause hardening)

- `~/.codex/auth.json` (Codex CLI's tokens, same OpenAI account) moved aside — it was the
  "another client" named in the `refresh_token_reused` error. Hermes keeps its own
  independent device-code session, so the CLI token is dead weight + a latent racer.
- Stale `last_auth_error` / `relogin_required` cleared from `~/.hermes/auth.json`.

## Notes / limits

- The headless reauth needs the box's Chrome profile (`chrome-auto`) to still hold a valid
  OpenAI **web session** (cookies, profile-based — independent of the codex OAuth token).
  When that eventually expires, `restore_reauth.py` falls back to email + Gmail-OTP login;
  if OTP is suppressed from the datacenter IP, it edge-alerts for a manual login.
- The gateway's own internal refreshes are not flock-guarded (can't modify the gateway),
  so a rare gateway-vs-keepalive collision can still happen — but step 5 now **auto-heals**
  it instead of paging a human.
