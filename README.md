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

One watchdog per host, 4 runs a day, silent unless something is wrong.

| Target | Credential watched | Runs on | Alerts to |
|---|---|---|---|
| `@Screddy_bot` codex | `~/.hermes/auth.json` | hostinger (`ubuntu`) | email |
| `@Teamnebula_bot` codex | `~/.hermes/profiles/tmn/auth.json` | hermes-tmn (`screddy`) | Slack `#tmn-ops` + email |
| **NEBOS v2 Claude** | `CLAUDE_CODE_OAUTH_TOKEN` in `nebos-dev` Secret Manager | hermes-tmn (`screddy`) | Slack `#tmn-ops` + email |
| **both watchdogs** | the two heartbeats, over the tailnet | neb-ops-gcp (observer) | Telegram DM |

The two hosts are **interleaved on the half-cycle** — TMN on 00/06/12/18:35, hostinger on
03/09/15/21:35 — so each box is checked every 6h while the fleet as a whole is
checked every 3h, and the two can never alert in the same minute.

```
watchdog/
  codex_health_check.py   canonical, shared by both hosts
  notify_failure.py       last-resort escalator, fired by OnFailure=
  heartbeat_server.py     serves this box's heartbeat to its peer, tailnet only
  codex_auth_probe.py     live probe — OPERATOR TOOL, not on any timer
  hosts/{hostinger,tmn,neb-ops}.json   everything host-specific
  systemd/                12 units, byte-identical to what is deployed
  install.sh              --host {hostinger|tmn|nebos-claude|neb-ops}
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

## The Claude watchdog is a different script, on purpose

`claude_health_check.py` watches NEBOS v2's Anthropic credential. It is a
sibling of the codex watchdog rather than another host config, because
detection is not the same problem:

* codex keeps structured local state — an `auth.json` with `last_auth_error`
  and a decodable JWT — so it can be judged without touching the network;
* a Claude Code OAuth token is an opaque `sk-ant-oat01…` string with **no local
  metadata at all**. There is nothing to inspect. The only way to know whether
  it still works is to ask Anthropic.

So it makes one real authenticated call per run. That is affordable here for
precisely the reason the codex probe was not: it is a 1-token request to the
cheapest model, four times a day, against an account whose quota is not the
thing being protected.

Only `401`/`403` counts as down. `429` and `5xx` say nothing about the
credential, and paging on them trains you to ignore the alert.

**Why it matters:** `nebos-v2`'s deploy wires `CLAUDE_CODE_OAUTH_TOKEN` as its
only Anthropic credential — `ANTHROPIC_API_KEY` appears in `.env.example` but
is not in the deploy secrets — so when that token stops authenticating, every
Claude-backed NEBOS feature stops with it.

It runs on hermes-tmn rather than in `nebos-dev`, because that box already has
systemd timers and both alert channels, while `nebos-dev` does not even have
the Cloud Scheduler API enabled. Reading the secret needs
`roles/secretmanager.secretAccessor` for the hermes-tmn compute service account,
granted **on that one secret**, not project-wide.

Scope note: this watches the **credential**, not the service. NEBOS can be down
for reasons unrelated to Claude auth and this check stays quiet through all of
them.

## Detection (codex)

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

The `ok` line also prints `plan=` from the access-token claims. That is context,
never a trigger: the claim is baked at token issuance, so it lags a plan change.
On 2026-08-17 it still read `free` for minutes after the account was upgraded and
the API was already serving traffic. Paging on it would have paged through a
working bot.

## Quota is a second verdict, not a kind of `down`

Added 2026-08-17, after `@Teamnebula_bot` spent three days answering every message
with the canned "model provider is rate-limiting" reply while this check printed
`status=ok healthy` four times a day. The credential refreshed on schedule, the
gateway unit stayed active, and every signal the check knew how to read was
genuinely fine. The plan behind the credential had dropped to the free tier and
returned `HTTP 429 usage_limit_reached` on every call.

`quota` is deliberately not folded into `down`, because the two need opposite
responses. A `down` alert tells you to complete a device-code login. During that
outage two logins were completed against the exhausted plan before anyone read the
429 body, and both landed on the same account the browser was already signed into.
So the quota alert omits `reauth_url` and says outright that a re-login will change
nothing. A test asserts the device URL never appears in quota prose.

**How it detects, without spending the thing it protects.** Passively, from the
`credential_pool` entries Hermes already writes: `last_status: exhausted`,
`last_error_code: 429`, and the 429 body carrying `resets_at`. No network call and
no quota. The live probe stays off every timer for the reason recorded below (it
ran every 30 minutes and burned the quota it existed to watch), and satisfying this
gap with a scheduled probe would repeat that mistake.

Three rules keep it honest:

| Situation | Verdict | Why |
|---|---|---|
| Every pooled credential blocked | `quota` | The pool is a failover set. One usable entry and the bot still answers. |
| `resets_at` in the past | `ok` | The window rolled. A spent record stops paging by itself. |
| Blocked, no `resets_at`, last error older than `QUOTA_STALE_S` (6h) | `ok` | A live exhaustion re-stamps `last_status_at` on every attempt, so this cannot swallow a real outage. |

A broken sign-in outranks quota: with both wrong you get `down`, because quota is
moot until the credential can call at all.

## A watchdog watching the watchdog next door

A box can run more than one check. hermes-tmn runs the codex check and the NEBOS
v2 Claude check. If the **codex** timer stops, its heartbeat goes stale and the
peer reports it — but the **Claude** timer has no such shadow, so switching it off
was invisible while the box stayed healthy. That is the 2026-08-04 failure mode (a
timer disabled, six days unnoticed) surviving in a corner.

So each host config may name `sibling_timers`, and the codex check asserts them
locally through systemd: enabled, scheduled, and triggered within
`sibling_stale_s` (26h — 4x/day plus slack). No network, no heartbeat, nothing new
to rot. A never-triggered timer reads as a fresh install rather than a fault, and
a systemctl error reads as uncheckable rather than broken.

Only hermes-tmn carries one (`nebos-claude-health.timer`). hostinger runs a single
watchdog, so it has no sibling to pair with.

The `sibling` verdict is its own kind, with prose that says plainly that the box's
own credential is fine and points at the timer. It outranks the peer watch, being
local and certain where the peer watch is remote and inferential.

## Alerting

Routing differs per box, set on 2026-08-17. `@Screddy_bot` on hostinger is Shawn's
own assistant, so it emails him and stays out of the team channel. `@Teamnebula_bot`
on hermes-tmn is company infrastructure with no fallback provider, so it posts to
Slack `#tmn-ops` **and** emails. hostinger's Linear ticketing was dropped in the
same pass.

The personal box carries two channels since 2026-08-24: Telegram, then email.
Telegram reuses `TELEGRAM_BOT_TOKEN`, the same secret `notify_failure.py`
escalates with, so the primary path no longer shares a failure mode with
Composio. That closed the single-channel risk this paragraph used to document,
and the risk was not hypothetical: on 2026-08-24 a `TMN_COMPOSIO_API_KEY`
rotation reached the box's fleet store but not `~/.hermes/.env`, every email
returned HTTP 401, and for a day the only delivery was the OnFailure backstop.
tmn survives losing either channel, which is the reason it keeps two: on
2026-08-17 a Slack app reinstall dropped the bot from `#tmn-ops` and
`chat.postMessage` would have returned `not_in_channel`.

Composio email is entity-scoped since the 2026-08-21 single-account migration.
An email channel must pin BOTH `composio_user_id` (per-mailbox: `src` for the
personal box, `tmn-shawn` for TMN hosts) and `connected_account_id` (the `ca_*`
id from `~/projects/docs/reference/composio-tmn-connected-accounts.md`). The
retired shared entity `user_uwgmr` fails even with a live key. And after any key
rotation, update `~/.hermes/.env` on each box, not only the fleet store:
`env_val` resolves `TMN_COMPOSIO_API_KEY` from there, and a stale copy is
exactly the 401 above.

```
ok    -> down/quota   alert once on every configured channel
same  -> same         quiet for renotify_s (24h), then one reminder, no second ticket
down  -> quota        alerts again, even inside the quiet window
fail  -> ok           silent re-arm, no "recovered" message
unknown               never pages, never changes state
```

A change of failure kind breaks the quiet window on purpose. Inheriting the earlier
alert's silence would leave "go re-login" standing as the last instruction given,
for a problem no login fixes. That transition also files its own Linear ticket
rather than reusing the one whose body says to sign in again.

Every alert leads with what broke, then the **sign-in link** (`reauth_url` in each
host config), then that host's own runbook. The link sits near the top because
buried in step 3 of the prose it was unreadable at the moment it mattered — but
it is always paired with the caveat that the device page needs the code the CLI
prints first. An unqualified link is worse than none: it invites opening a page
you cannot finish, precisely when you are least inclined to read on.

## Failing loudly

A monitor that fails silently is worse than no monitor, because it also removes
the suspicion that you are unmonitored. Six paths used to exit 0 with systemd
green; all are now hard failures (exit 1): unreadable config, unreadable
`auth.json`, unresolvable secret, Slack `ok:false`, Composio false-success, and
corrupt state. Most importantly, **"we decided to alert and every channel
failed" is a failure** — it previously printed the error and exited 0.

## When the watchdog cannot report

Every check unit carries `OnFailure=`, which fires `notify_failure.py` and sends
you a Telegram DM. It covers every non-zero exit: DISARMED, "alerted but nothing
was delivered", a crash, a timeout. Those are the cases where the check knows
something is wrong and cannot say so through its own channels.

This existed only as a claim until 2026-08-17. The check's docstring said exit 1
was "paired with `OnFailure=` in the systemd unit"; no unit had ever carried the
directive. A failed delivery wrote to stderr, marked the unit failed, and stopped
there — findable by running `systemctl --user status`, which nobody runs while
everything looks fine. `install.sh` now reads back `OnFailure` from the installed
unit and refuses to report success without it.

**Why Telegram.** The escalation has to use a transport that cannot fail for the
same reason the primary did. A second email address would not qualify: both
authenticate with `TMN_COMPOSIO_API_KEY`, so one rotation takes out both. The
Hermes Telegram bot token is a different secret from a different vendor, it is
already on both boxes, and it fails visibly — if that token dies, the bot stops
answering and you know within minutes.

It matters most on hostinger, which alerts through email alone. If that Composio
key rotates away, `env_val` returns empty and the run exits 1 having told nobody.
Now it exits 1 *and* DMs you.

`notify_failure.py` imports nothing from the health checks, on purpose. A last
resort that depends on the component which just failed is not a last resort, so it
carries its own config read, its own env resolution, and degrades to generic
wording rather than staying silent when `config.json` is unreadable. `install.sh`
dry-runs it on every deploy, so a notifier that could never fire fails the install
instead of waiting to disappoint you.

## The two boxes watch each other

`OnFailure=` needs a run to hook, so it cannot fire for a check that never runs.
That gap is covered by a mutual peer watch, added 2026-08-17: each check writes a
heartbeat, serves it on the tailnet, and reads its peer's. A box that stops
reporting gets called out by the other one, through channels that already work.

```
hostinger  ──reads──▶ http://100.126.215.66:8299/heartbeat  (hermes-tmn)
hermes-tmn ──reads──▶ http://100.98.215.63:8299/heartbeat   (hostinger)
```

Two failure shapes, handled differently on purpose:

| What the peer looks like | Verdict | Why |
|---|---|---|
| Heartbeat readable, older than 13h | `peer`, alerts at once | The box is up and its check stopped. Unambiguous. |
| Heartbeat unreachable | `unknown`, then `peer` on the second miss | These two boxes route over a DERP relay, so one miss is not evidence |

13h is two 6h cycles plus grace. A local failure outranks the peer watch: a broken
credential here beats a dark box over there, and burying the former under the
latter would be a regression.

The peer alert deliberately shares no prose with the sign-in alert. It says which
box went quiet, that the reporting box is fine, and where to look — pointing an
operator at a re-login on the wrong machine is worse than saying nothing.

**Why not healthchecks.io.** A deadman was built and removed on 2026-08-12, and it
had never actually run: both host configs shipped `enabled: false` with an empty
`ping_url`. The objection then was that a service which pages when pings stop is a
different and unwanted signal. The peer watch answers that: it adds no vendor, no
account, and no new signal type, because a dark peer is reported through the same
"something is broken" channels as everything else.

### The backstop: neb-ops-gcp

Mutual watching leaves one hole — both boxes dark at once, with no one left to
report it. `neb-ops-gcp` closes it. It is a third always-on host already on the
tailnet, it holds no Hermes credential and checks none, and it reads both
heartbeats four times a day on `01,07,13,19:35`, offset from both Hermes hosts so
a fleet-wide outage surfaces within about 90 minutes.

**It alerts only when EVERY watched box is dark.** While one box is up, that box
already reports its dark partner, and a second alert for the same event is the
noise this repo keeps refusing to add. A test pins that behaviour, and the drill
below confirmed it live.

It alerts by Telegram DM, and that is a deliberate choice of secret: the observer
needed some credential, and a bot token can only speak as a bot Shawn owns, where
`TMN_COMPOSIO_API_KEY` could send mail as him. Telegram also keeps working when
both boxes are off, being a cloud API that does not care whether either gateway
runs. The token lives in `~/.watchdog-observer/.env`, mode 600.

Observer mode is not a loophole in the `hermes_home` rule. A config with no
`mode: observer` still hard-fails without an auth store; the observer is exempt
only because it inspects no credential. Both halves have tests.

**The observer is watched too.** It serves a heartbeat like the others, and
hermes-tmn reads it. Only that one box does: if both Hermes boxes watched the
observer, a single dead observer would page twice for one event. So the ring has
no unwatched node — hostinger ↔ hermes-tmn → neb-ops-gcp → back.

**What remains uncovered:** all three hosts dark at once, which now requires three
independent failures across two providers and two regions.

The heartbeat server binds the tailnet address from `tailscale ip -4` and refuses
to start without one. It never falls back to `0.0.0.0`: hostinger has a public IP,
and a monitoring tool that quietly opens a public port is the failure this repo
exists to prevent. The payload carries no secrets — host label, unit, timestamp,
last verdict.

### Known limitation: nothing watches the watcher, alone

**By explicit decision (2026-08-12), there is no external deadman.** The only
notifications this system produces are "something is actually broken". Nothing
pings you to say it is still alive; the peer box is what notices silence now.

The cost is real and worth stating plainly, because it has already happened
once: no in-process check can detect its own absence, so if a timer gets
disabled — as `hermes-codex-health.timer` was on 2026-08-04 — the silence is
indistinguishable from health. That outage ran six days. A deadman was built,
tested, and then removed rather than left switched off, because disabled code
rots and an installer that nags about an unwanted feature is noise.

`OnFailure=` was ruled out here on the same reasoning, on the grounds that it
would only retry the channels already known to be dead. **That was reversed on
2026-08-17**, because the objection holds only for a retry. Escalating over a
transport with a different secret and a different vendor is not a retry: when the
Composio key is what broke, a Telegram DM is unaffected. See "When the watchdog
cannot report" above.

What remains true is the part this does not solve. `OnFailure=` needs a run to
hook, so it cannot fire for a check that never runs. The 2026-08-04 disabled-timer
case would still go six days unnoticed, and only a deadman closes that.

If that trade is ever revisited, the mechanism is small — a single HTTP GET at
the end of a successful run — and `git log` has the removed implementation.
Note the check would need a **6h** period to match the per-host cadence; 3h
would page every interval.

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

The probe knowing about `QUOTA` while the timer could not see it is what left the
three-day gap: the one component that recognised exhaustion ran only when someone
typed it. The scheduled check now reads the same condition from `auth.json`, so the
probe keeps its triage role and stays off the timer.

One thing the probe still gives you that `auth.json` cannot: **live headroom.** A
successful call returns the window and how much of it is spent, which is a warning
before exhaustion rather than a page after it.

```
x-codex-active-limit: premium
x-codex-primary-window-minutes: 10080          # 7-day rolling window
x-codex-primary-over-secondary-limit-percent: 0   # spent so far
x-codex-primary-reset-at: 1787587961
x-codex-credits-unlimited: False
```

Reading those on a timer would mean a scheduled probe, so they stay a triage tool.
Run the probe by hand when you want to know how much room is left.

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
