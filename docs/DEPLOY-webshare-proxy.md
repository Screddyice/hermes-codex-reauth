# Deploy runbook — Webshare residential proxy for headless reauth

> ## ⚠️ DO NOT run a live OpenAI/ChatGPT reauth as part of testing this.
>
> A live OpenAI reauth **rotates a SHARED single-use refresh token** and can break the
> live **Hermes gateway on Hostinger** (`neb-brain-hostinger`, `2.25.149.69`). Coordinate
> before running any live OpenAI sign-in.
>
> **Scope of this change is build + unit test + PR only.** Claude and Gemini `--dry-run`
> are fine for verifying the proxy attaches and the callback still resolves. **Live
> OpenAI/ChatGPT sign-in is NOT** — do not trigger it while validating the proxy.

---

## What this does

Headless provider sign-in (Claude, ChatGPT, Gemini, Perplexity) is launched through a
**Webshare residential proxy** so it looks like a home connection. Datacenter/server IPs
get sign-in blocked and the verification email suppressed; the residential egress fixes
that. This replaces the retired IPRoyal `gost` SOCKS5 proxy (decommissioned 2026-05-26).

The proxy injects at one point — `launch_chrome_cdp` in `headless_reauth.py` — so it
applies to every provider flow. Two modes:

- **`ip_auth`** (default, recommended): Chrome points straight at `http://p.webshare.io:80`;
  no credentials on disk. The server's egress IP is whitelisted in the Webshare dashboard.
- **`userpass`** (fallback): a localhost-only stdlib forwarder (`proxy_forwarder.py`) injects
  `Proxy-Authorization` toward Webshare; Chrome points at `127.0.0.1:<local_forwarder_port>`.

---

## 1. Webshare IP-whitelist setup (`ip_auth` mode — recommended)

For the Hostinger box, the egress IP is `2.25.149.69`.

1. Log in to the Webshare dashboard → **Proxy → IP Authorization**.
2. Add Authorized IP `2.25.149.69` (the Hostinger egress IP).
3. Confirm the endpoint is `p.webshare.io:80` (Webshare's rotating residential gateway)
   and that the subscription is **residential**, not datacenter.
4. Set the `config.json` `proxy` block:
   ```json
   "proxy": {
     "enabled": true,
     "mode": "ip_auth",
     "endpoint": "p.webshare.io:80"
   }
   ```
   (or run `python3 configure.py --reconfigure proxy` and pick "IP whitelist").
5. Verify the egress IP from the box — it should be a residential IP, **not** `2.25.149.69`:
   ```bash
   curl -s --proxy http://p.webshare.io:80 https://api.ipify.org
   ```

---

## 2. Username/password fallback (`userpass` mode)

Use this when you can't whitelist a static egress IP.

1. In Webshare → **Proxy → Proxy List / Credentials**, copy the proxy username and password.
2. Put them in `config.json` (gitignored, written `0o600`) and set the mode:
   ```json
   "proxy": {
     "enabled": true,
     "mode": "userpass",
     "endpoint": "p.webshare.io:80",
     "username": "YOUR_WEBSHARE_USER",
     "password": "YOUR_WEBSHARE_PASS",
     "local_forwarder_port": 1080
   }
   ```
   (or `python3 configure.py --reconfigure proxy` → "Username/password").
3. Pick a `local_forwarder_port` (default `1080`) and restart.

The forwarder **binds `127.0.0.1` only** — it relays plaintext Basic credentials, so it is
never reachable off-box. Chrome's `--proxy-server` cannot carry `user:pass@` inline, which is
the entire reason this forwarder exists. It supports HTTPS via CONNECT tunneling (all provider
sign-in is https): it injects the auth header into the `CONNECT host:443` request to Webshare,
then blind-relays the established TLS tunnel.

---

## 3. Loopback callback note

The OAuth callback is served on `localhost:<callback_port>` (default `19876`). Whenever the
proxy is enabled, Chrome is launched with:

```
--proxy-bypass-list=localhost;127.0.0.1;[::1];<-loopback>
```

This is set **automatically** — you do not configure it. The `<-loopback>` token bypasses all
loopback/link-local, so if you ever change `callback_port`, no extra action is needed. Without
this bypass, Chrome would route the localhost callback through the residential proxy and the
OAuth callback would never arrive (every flow silently fails with "No OAuth callback").

---

## 4. Verification (without live OpenAI)

1. Run the offline unit tests:
   ```bash
   pytest test_proxy.py -v
   ```
2. Optionally, a **Claude** or **Gemini** dry-run to confirm Chrome launches with the proxy
   and the callback still resolves:
   ```bash
   python3 headless_reauth.py --server MY_SERVER --dry-run
   ```
3. **Do NOT** run a ChatGPT/OpenAI live sign-in — see the warning box at the top of this file.
