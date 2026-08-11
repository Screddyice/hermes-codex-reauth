# hermes-codex-reauth

Monitoring for OpenAI Codex (ChatGPT-plan) OAuth on the Hermes hosts.

> **2026-08-11 — this repo no longer re-authenticates anything.**
> OpenAI now mandates 2FA on sign-in, which makes unattended device-code reauth
> impossible by construction: completing a login requires a person at a browser.
> The headless self-heal that gave this repo its name has been removed. What
> remains is a **watchdog** — it detects a broken credential quickly and tells a
> human clearly, and it never mutates anything.
>
> The repo name is now a slight misnomer, kept for URL stability.

## Why a watchdog and not a fixer

The codex refresh token is single-use and rotates on every refresh, so two
processes refreshing the same credential trip `refresh_token_reused` and
invalidate the whole token family. That is what took both boxes down in July.
The old design answered this with automation: probe, refresh, and — if the
refresh chain was dead — drive a headless Chrome through the device-code flow.

2FA ended that. A login now needs a human, so the only useful thing software can
do is notice fast and say so. Everything mutating was removed on 2026-08-11:

| Removed | Why |
|---|---|
| Headless device-code reauth (Chrome/Xvfb/Gmail-OTP/residential proxy) | 2FA makes it impossible; it could only fail slowly |
| The `hermes -z` refresh rung | Mutating. Pure-watchdog by decision — all recovery is manual |
| `codex-keepalive` (30-min loop) | With both rungs gone, its remainder duplicated the watchdog |

**Consequence, stated plainly:** nothing refreshes these tokens on a schedule any
more. A running gateway refreshes on use, so a *live* bot stays healthy. A bot
that is down long enough for its access token to age out will not recover on its
own — it will page you instead. That is the intended trade, and it is exactly the
2026-08-05 scenario, which previously ran six days unnoticed.

## What runs

One watchdog per host, on a 3-hourly timer, silent unless something is wrong.

| Host | User | Auth store it watches | Alerts to |
|---|---|---|---|
| `neb-brain-hostinger` (`@Screddy_bot`) | `ubuntu` | `~/.hermes/auth.json` | email + Linear |
| `hermes-tmn` (GCP, `@Teamnebula_bot`) | `screddy` | `~/.hermes/profiles/tmn/auth.json` | Slack `#tmn-ops` + email |

The two timers are offset 80 minutes so the boxes never alert in the same minute.

```
watchdog/
  codex_health_check.py   canonical, shared by both hosts
  codex_auth_probe.py     live probe — OPERATOR TOOL, not on any timer
  hosts/{hostinger,tmn}.json   everything host-specific
  systemd/                4 units, byte-identical to what is deployed
  install.sh              --host {hostinger|tmn}
```

**Everything host-specific lives in `hosts/*.json`** — auth store, gateway unit,
channels, and the runbook prose. The script carries no host defaults.

### `hermes_home` has no default, on purpose

The two scripts this replaced disagreed: `~/.hermes` on one host,
`~/.hermes/profiles/tmn` on the other. TMN's gateway runs with
`HERMES_HOME=~/.hermes/profiles/tmn` and its root `~/.hermes/auth.json` is stale
and unused — so a shared default would silently watch a credential nothing runs
on and report a confident, wrong `ok`. That was a real defect, fixed 2026-07-29.

A missing `hermes_home` is therefore a hard failure, not a guess, and a test
asserts each shipped config resolves to the intended store.

## Detection

Local signals only, read straight from `auth.json`. It deliberately does **not**
trust `hermes auth status`, which on 2026-07-29 reported `logged in` for a
credential with no refresh token at all.

Reported `down` when: there is no credential; `last_auth_error` is newer than
`last_refresh` with `relogin_required` or `refresh_token_reused`; there is no
refresh token; the access token has expired; **or the gateway unit is not
active** — codex auth can be perfect while the bot is dead, and nothing used to
notice.

Every alert carries a short `lineage=` fingerprint of the refresh token, so two
hosts sharing one OAuth lineage — the July failure — is visible by inspection
instead of requiring an incident. The credential `label` field is cosmetic and
reads the same on both boxes; compare fingerprints.

## Alerting

```
ok   -> down   alert once on every configured channel
down -> down   quiet for renotify_s (24h), then one reminder, no second ticket
down -> ok     silent re-arm, no "recovered" message
unknown        never pages, never changes state
```

## Failing loudly

A monitor that fails silently is worse than no monitor, because it also removes
the suspicion that you are unmonitored. Six paths used to exit 0 with systemd
green; all are now hard failures (exit 1): unreadable config, unreadable
`auth.json`, unresolvable secret, Slack `ok:false`, Composio false-success, and
corrupt state. Most importantly, **"we decided to alert and every channel
failed" is a failure** — it previously printed the error and exited 0.

### The deadman

No in-process check can detect its own absence. On 2026-08-05 this host's timer
was disabled and nothing noticed for six days. So each successful run pings an
external deadman (healthchecks.io), which pages if pings stop.

A failed *delivery* deliberately **withholds** the ping. That makes the deadman
cover both "the watchdog stopped running" and "it ran but could not tell
anyone", escalating over a channel that cannot be broken by the same rotated
secret that just swallowed the alert. An `OnFailure=` unit would only retry the
channels already known to be dead.

> Set `deadman.ping_url` in each host config and flip `enabled` to `true`.
> Until then this protection is off, and `install.sh` says so.

## Install

```bash
./watchdog/install.sh --host hostinger    # or --host tmn
```

Idempotent. Never touches `state.json` — a reinstall must not reset an
in-progress outage and re-arm the edge detector. It **ends in assertions** and
refuses to report success unless the timer is enabled, actually scheduled,
lingering is on, and the installed script runs clean.

## Verify

```bash
python3 check.py --dry-run                          # detection, no side effects
python3 check.py --force-down --dry-run             # alert rendering
python3 check.py --force-down --state-file /tmp/d.json   # real delivery drill
```

Always pass `--state-file` for drills. Without it a `--force-down` writes `down`
into production state, leaving the host inside a 24h quiet window where a
genuine outage pages nobody.

Note `--force-down` bypasses `detect()` entirely, so it proves *delivery* only.
To prove *detection*, point `hermes_home` at a scratch directory holding a
crafted `auth.json` and a copied `config.yaml` — without the latter the
applicability guard exits quietly and you get a false pass.

## The probe

`codex_auth_probe.py` makes a real call to OpenAI. It is an **operator tool for
triage**, run by hand, and is deliberately on no timer.

It used to run every 30 minutes as part of the self-heal, and the keepalive log
shows the cost: over ~7 weeks, **3 genuine `BROKEN` results against 209
`UNKNOWN`s — 209 of which were HTTP 429 `usage_limit_reached`**, including a
continuous 4.6-hour blind window. It was consuming the plan quota it existed to
protect and classifying its own exhaustion as "transient". All three real
breakages were caught by local signals for free.

```
0 OK   1 BROKEN (a human must re-login)   2 UNKNOWN (transient)   3 QUOTA (429)
```

`QUOTA` is separate from `UNKNOWN` because collapsing them made "we were blind
for five hours" indistinguishable from health. Any 401/403 is `BROKEN`: the old
allowlist of error substrings let a reworded OpenAI message fall through to
`UNKNOWN`. That bias was right when `BROKEN` triggered a destructive reauth; now
a false page costs nothing and a swallowed 401 costs an outage.

## Tests

```bash
pytest
```

## History

The reauth machinery is **deleted from the working tree**, not merely unused —
17 modules plus the whole `deploy/` directory, and the 6 tests that covered them.
That includes the Chrome/CDP driver, the Xvfb launcher, the Webshare proxy
forwarder, the Gmail-OTP reader, and the legacy Mac-trigger flow. Playwright is
gone from `requirements.txt`; the watchdog is stdlib-only.

Recovering any of it:

| Want | Where |
|---|---|
| The self-heal design | `docs/SELF-HEAL-codex-reauth.md` (kept) |
| The scripts as they ran on each VM | `watchdog/hosts-deployed/` (kept — they had never been in git) |
| The deleted reauth code | tag `pre-watchdog-consolidation` |

Two on-box cleanups are deliberately **not** done by this repo and must be done
by hand, because both hold live credentials: the plaintext OpenAI password at
`~/.openclaw/oai-password`, and the `chrome-auto` browser profile under
`~/.hermes-oauth/browser-profiles/`, which still contains a logged-in OpenAI web
session. Wipe those deliberately rather than leaving them to rot.

⚠️ `~/headless-oauth-recovery` on hostinger is **not a git repo** and is where the
still-running `codex-keepalive` loads its probe from. Deleting it makes `python3`
exit 2, which that script maps to UNKNOWN → "no action" → **systemd green
forever**. Archive it; never `rm` it, and only after the keepalive is retired.
