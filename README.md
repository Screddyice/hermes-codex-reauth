# hermes-codex-reauth

Monitoring and bounded repair for OpenAI Codex OAuth on the Hermes hosts.

The watchdog reads local Hermes state without spending Codex quota. A separate
healer runs every 15 minutes and repairs a fixed set of faults: disabled or
unscheduled health timers, inactive gateways with recoverable auth, renewable
credential-pool failures, reset quota windows, and allowlisted peer units.
OpenAI device-code login and 2FA remain human work.

## Repair boundary

The codex refresh token is single-use and rotates on every refresh, so two
processes refreshing the same credential trip `refresh_token_reused` and
invalidate the whole token family. That is what took both boxes down in July.
The retired design drove a browser through device-code login. OpenAI added 2FA,
so the repository removed Chrome, Xvfb, Gmail OTP handling, residential proxy
support, and scheduled live probes on 2026-08-11.

The current healer uses a stdlib-only refresh helper that imports no Hermes
agent, plugin, MCP, memory, rule, skill, or tool code. It never calls
`hermes auth reset`. Before one eligible credential repair, it copies
`auth.json` into the role directory's `backups/` directory, sets the snapshot to
mode `0600`, and retains the newest five snapshots. The helper holds Hermes'
`auth.lock` across one refresh request and one atomic write, verifies the saved
lineage, then lets the healer restart the gateway and run one pool-aware live
probe. Operators keep the backup as evidence. The healer never restores it
because a failed refresh may have consumed a single-use refresh token.

Terminal OAuth failures stop at the device-code runbook in the alert. A person
must run `hermes auth add openai-codex --type oauth --no-browser`, enter the code
in a browser, finish 2FA, restart the gateway, and verify a real turn. The healer
does not redeem usage-reset credits or automate any part of that login.

## What runs

Each role runs its scheduled check four times a day. The three Codex roles also
run a healer every 15 minutes.

| Target | Credential watched | Runs on | Alerts to |
|---|---|---|---|
| `@Screddy_bot` codex | `~/.hermes/auth.json` | src (`hermes`) | Telegram + email |
| `@Teamnebula_bot` codex | `~/.hermes/auth.json` | neb-ops-gcp (`shawn_teamnebula_ai`) | Slack `#tmn-ops` + email |
| **NEBOS v2 Claude** | `CLAUDE_CODE_OAUTH_TOKEN` in `nebos-dev` Secret Manager | hermes-tmn (`screddy`) | Slack `#tmn-ops` + email |
| **uncovered Codex watchdog outage** | the two heartbeats, over the tailnet | hermes-tmn (observer) | Telegram DM |

The two hosts use an interleaved half-cycle: TMN runs at 00/06/12/18:35, and src
runs at 03/09/15/21:35. Each box gets a passive check every six hours. The
15-minute healer uses `OnBootSec=2m`, `OnActiveSec=2m`,
`OnUnitActiveSec=15m`, and `Persistent=true`.

```
watchdog/
  codex_health_check.py   canonical, shared by both hosts
  auth_state.py           shared passive credential and quota classification
  self_heal.py            bounded local and peer repair
  notify_failure.py       last-resort escalator, fired by OnFailure=
  heartbeat_server.py     serves this box's heartbeat to its peer, tailnet only
  codex_auth_probe.py     pool-aware probe used by operators and eligible repairs
  hosts/{src,tmn,hermes-tmn-observer}.json   everything host-specific
  systemd/                role-specific check, heartbeat, notifier, and healer units
  install.sh              --host {src|tmn|nebos-claude|observer}
```

**Everything host-specific lives in `hosts/*.json`** — auth store, gateway unit,
channels, and the runbook prose. The script carries no host defaults.

### `hermes_home` has no default, on purpose

Both live gateways now use `~/.hermes`, but each host config still names that
path. A default would hide the next host or profile migration and could report
against an unused credential. A missing `hermes_home` remains a hard failure.

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

Hermes routes through `credential_pool` whenever that list is populated, so the
watchdog uses the same source of truth. It ignores the legacy `providers` block in
that case. That block can retain `refresh_token_reused` after a manual pool entry
has taken over, which made the watchdog report a working gateway as signed out on
2026-08-27. The singleton still governs hosts without a pool.

Three rules keep it honest:

| Situation | Verdict | Why |
|---|---|---|
| Healthy pooled credential, broken legacy singleton | `ok` | Hermes serves through the pool; the singleton no longer controls runtime auth. |
| Pool populated, no renewable entry | `down` | Hermes has no pooled credential it can refresh. |
| Every pooled credential blocked | `quota` | The pool is a failover set. One usable entry and the bot still answers. |
| `resets_at` in the past | `ok` | The window rolled. A spent record stops paging by itself. |
| Blocked, no `resets_at`, last error older than `QUOTA_STALE_S` (6h) | `ok` | A live exhaustion re-stamps `last_status_at` on every attempt, so this cannot swallow a real outage. |

The active auth source determines precedence. A singleton sign-in failure outranks
quota only when no pool exists. With a populated pool, the watchdog evaluates that
pool for renewable credentials and quota state.

## The NEBOS Claude timer on the legacy VM

The August migration moved the TMN Codex gateway to neb-ops-gcp. The NEBOS v2
Claude check remains on hermes-tmn, so the two timers no longer share a host.

So each host config may name `sibling_timers`, and the codex check asserts them
locally through systemd: enabled, scheduled, and triggered within
`sibling_stale_s` (26h — 4x/day plus slack). No network, no heartbeat, nothing new
to rot. A never-triggered timer reads as a fresh install rather than a fault, and
a systemctl error reads as uncheckable rather than broken.

No shipped Codex config names a sibling timer after the migration. The NEBOS
Claude service retains its own `OnFailure=` escalation, but another node does not
detect a timer that never fires.

The `sibling` verdict is its own kind, with prose that says plainly that the box's
own credential is fine and points at the timer. It outranks the peer watch, being
local and certain where the peer watch is remote and inferential.

## Alerting

Routing differs per box, set on 2026-08-17. `@Screddy_bot` on src is Shawn's
own assistant, so it DMs and emails him and stays out of the team channel. `@Teamnebula_bot`
on neb-ops-gcp is company infrastructure, so it posts to Slack `#tmn-ops` and
emails. src does not create Linear tickets.

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
ok    -> failure            alert once on every configured channel
down/quota/sibling -> same  quiet for renotify_s (24h), then one reminder, no second ticket
peer  -> peer               quiet until recovery, with no scheduled reminders
down  -> quota              alerts again, even inside the quiet window
fail  -> ok                 silent re-arm, no "recovered" message
unknown                     never pages, never changes state
```

A change of failure kind breaks the quiet window on purpose. Inheriting the earlier
alert's silence would leave "go re-login" standing as the last instruction given,
for a problem no login fixes. That transition also files its own Linear ticket
rather than reusing the one whose body says to sign in again.

Peer alerts use edge-triggering because another 24-hour message carries no new
information. Recovery returns the state to `ok`, so a later peer outage still alerts.

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

On src, Telegram still delivers when a Composio key rotation breaks email.
`notify_failure.py` also sends a Telegram DM when the scheduled check exits 1.

`notify_failure.py` imports nothing from the health checks, on purpose. A last
resort that depends on the component which just failed is not a last resort, so it
carries its own config read, its own env resolution, and degrades to generic
wording rather than staying silent when `config.json` is unreadable. `install.sh`
dry-runs it on every deploy, so a notifier that could never fire fails the install
instead of waiting to disappoint you.

## The three-node watch graph

`OnFailure=` needs a run to hook, so it cannot fire for a check that never runs.
The peer watch covers that gap. Each check writes a heartbeat and serves it on
its Tailscale address. hermes-tmn-observer and neb-ops-gcp read src through a one-device
share from the consulting tailnet into the Team Nebula tailnet. The share grants
Team Nebula access to src without giving src access to company nodes.

```
hermes-tmn-observer ──reads──▶ http://100.79.251.126:8299/heartbeat  (src)
hermes-tmn-observer ──reads──▶ http://100.74.25.61:8299/heartbeat   (neb-ops-gcp)
neb-ops-gcp         ──reads──▶ http://100.79.251.126:8299/heartbeat  (src)
neb-ops-gcp         ──reads──▶ http://100.126.215.66:8299/heartbeat (observer)
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

### The backstop: hermes-tmn-observer

The post-migration topology is asymmetric: `neb-ops-gcp` can watch `src` and the
observer, but `src` cannot reach Team Nebula hosts. The legacy `hermes-tmn` VM
closes the uncovered paths. It is a third always-on host on the tailnet, holds no
Hermes credential, and reads both heartbeats four times a day on
`01,07,13,19:35`, offset from both Hermes hosts.

Each observer peer declares `covered_by`, the other live peers that already own
its lone outage. A dark `src` stays quiet while `neb-ops-gcp` has a fresh
heartbeat because the TMN watchdog reports it. A dark `neb-ops-gcp` alerts from
the observer even while `src` is fresh because `src` has no route back into the
Team Nebula tailnet. If both are dark, the observer alerts for the combined
outage. Malformed, self-referential, or unknown coverage declarations disarm the
observer instead of guessing.

It alerts by Telegram DM, and that is a deliberate choice of secret: the observer
needed some credential, and a bot token can only speak as a bot Shawn owns, where
`TMN_COMPOSIO_API_KEY` could send mail as him. Telegram also keeps working when
both boxes are off, being a cloud API that does not care whether either gateway
runs. The token lives in `~/.watchdog-observer/.env`, mode 600.

Observer mode is not a loophole in the `hermes_home` rule. A config with no
`mode: observer` still hard-fails without an auth store; the observer is exempt
only because it inspects no credential. Both halves have tests.

**The observer is watched too.** It serves a heartbeat like the others, and
neb-ops-gcp reads it. The observer reads src and neb-ops-gcp, while neb-ops-gcp
reads src and the observer. Every node has a watcher, and one dead node produces
one alert path.

**What remains uncovered:** all three hosts dark at once, which now requires three
independent failures across two providers and two regions.

The heartbeat server binds the tailnet address from `tailscale ip -4` and refuses
to start without one. It never falls back to `0.0.0.0`: src has a public IP,
and a monitoring tool that quietly opens a public port is the failure this repo
exists to prevent. The payload carries no secrets — host label, unit, timestamp,
last verdict.

## Healer behavior

The healer takes a nonblocking lock and processes faults in this order:

1. Stop when the role's `SELF_HEAL_PAUSED` file exists.
2. Validate the full pinned Hermes helper contract on credential hosts.
3. Repair the local health timer once, unless systemd reports a mask.
4. Restart an inactive gateway once, or reserve that restart for a due refresh.
5. Run one backed-up credential refresh or one post-reset quota probe.
6. Repair fixed peer timer, check, and heartbeat units after two missed heartbeats.

An enabled timer with no next elapse gets one timer restart and one health-check
start. A disabled timer gets one `enable --now`. The healer verifies enabled,
active, and next-elapse state after either action. It skips masked units.

A pool whose renewable entries all report quota blocks causes no Codex request
before the latest stored reset. The first healer cycle at or after that reset
runs one direct refresh. A successful persistence gets one live probe. The
state file records the attempt before the request, so a timeout or lost response
cannot reuse the same single-use token. A fresh 429 stores the next reset
without a probe or second request and returns to passive waiting.

When the live probe returns 429 after a verified refresh, the healer stores that
probe reset separately. It makes no request before the reset, then runs one
direct no-tool probe at the boundary without another OAuth refresh. A repeated
429 stores the next reset and ends the cycle.

After OAuth persistence, the state file records `gateway_restart` and then
`probe` as non-secret pending phases. Both phases belong to the
`local.credential` incident. The ordinary gateway step defers while either phase
exists. A failed restart waits for the credential cooldown, then resumes one
restart and one probe. A failed probe resumes one probe. Neither path repeats the
OAuth refresh. Success clears the pending phase and credential fault.
The state loader rejects a pending phase when quota retry action or reset state
also exists. A probe-origin 429 clears the pending phase and writes the quota
action and reset in one state save, so later cycles wait for that reset.

Credential roles pin the Hermes Python runtime, version, `auth.py`, and
`credential_pool.py`, including a SHA-256 for each source module. `src` uses
`/opt/hermes-agent`; Team Nebula uses the Hermes checkout under
`~/.hermes/hermes-agent`. The healer checks absolute paths, file type, hashes,
and the refresh, lock, selection, and persistence signatures before mutation.
`install.sh` runs the helper's readiness check before it enables or starts the
timer. Each normal credential-host cycle repeats the same full readiness check
before any mutation. A Hermes upgrade stops the healer until an operator reviews
and updates the source pins.

Each failed repair raises one `OnFailure=` notification. Later cycles retry at
the configured six-hour cooldown but exit without another notification while
the fault remains active. Between attempts, the healer still checks passive
postconditions and clears a recovered fault. It does not mutate the timer,
gateway, or credential before the cooldown boundary. A successful repair removes
the fault record and re-arms notification for a new incident.

## Peer repair topology

Peer repair uses Tailscale IPs in `100.64.0.0/10`, a mode-`0600`
`~/.ssh/watchdog-repair` identity, and a pinned
`~/.ssh/watchdog-repair-known_hosts` file. The runtime validates the SSH user,
maintenance-lock path, unit names, key permissions, and host-key file before it
opens SSH. It passes an argv array and permits these remote actions only:

- test the configured `SELF_HEAL_PAUSED` file;
- read fixed timer and service state;
- enable the fixed health timer;
- restart the fixed heartbeat service;
- start the fixed health check;
- read the same postconditions.

The one-device Tailscale share grants Team Nebula hosts access to `src`.
`neb-ops-gcp` and the observer may repair `src`; `src` has no peer list and gets
no access to Team Nebula hosts. The observer and `neb-ops-gcp` may repair each
other inside the Team Nebula tailnet. The healer rejects `sudo`, shell fragments,
unlisted units, and non-tailnet targets.

## Maintenance and state

Create the maintenance lock before planned work and remove it after the work:

```bash
# src or neb-ops-gcp
touch ~/.hermes/codex-health/SELF_HEAL_PAUSED
rm ~/.hermes/codex-health/SELF_HEAL_PAUSED

# observer
touch ~/.watchdog-observer/SELF_HEAL_PAUSED
rm ~/.watchdog-observer/SELF_HEAL_PAUSED
```

The health checks keep observing during the pause. The healer logs the pause,
makes no mutation, and exits zero.

The Codex roles store detection state at `~/.hermes/codex-health/state.json` and
healer state at `~/.hermes/codex-health/self-heal-state.json`. The observer uses
`~/.watchdog-observer/state.json` and
`~/.watchdog-observer/self-heal-state.json`. The healer writes private state by
atomic replace with mode `0600`. Credential backups live in the adjacent
`backups/` directory. `install.sh` preserves both state files and all backups.
It also requires the backup directory to remain private and writable by the
service user.

## Install

```bash
./watchdog/install.sh --host src           # or --host tmn
./watchdog/install.sh --host observer      # legacy hermes-tmn VM
```

Copy the repository to the target and run the installer as that role's user.
Targets do not run `git pull`. Install peer key material and pinned host keys
before installing a role whose config names peers.

The installer preserves `state.json`, `self-heal-state.json`, and `backups/`.
Before overwrite, it copies every existing deployed script, config, and unit file
into a private timestamped `install-backups/` snapshot and writes
`restore-map.tsv` with each retained source and deployment target.

Before it enables or starts a unit, the installer checks healer readiness,
`OnFailure=`, linger, notifier credentials, and isolated check and healer
dry-runs. A failed preflight activates nothing. After preflight, it tracks each
unit that was disabled or inactive before the run. A later failure stops and
disables only those newly activated units. Timer state, next elapses, and
heartbeat reachability remain post-activation success gates.

## Verify

```bash
python3 check.py --dry-run                          # detection, no side effects
python3 self_heal.py --dry-run                      # repair plan, no mutation or network
python3 check.py --force-down --dry-run             # alert rendering
python3 check.py --force-down --state-file /tmp/d.json   # real delivery drill
systemctl --user list-timers '*codex*' '*self-heal*'
journalctl --user -u hermes-codex-self-heal.service --since today
journalctl --user -u hermes-codex-self-heal-tmn.service --since today
journalctl --user -u codex-observer-self-heal.service --since today
```

Always pass `--state-file` for drills. Without it a `--force-down` writes `down`
into production state, leaving the host inside a 24h quiet window where a
genuine outage pages nobody.

Note `--force-down` bypasses `detect()` entirely, so it proves *delivery* only.
To prove *detection*, point `hermes_home` at a scratch directory holding a
crafted `auth.json` and a copied `config.yaml`. Without the latter, the
applicability guard exits without running the canary.

The healer caps command output and redacts bearer tokens, JWTs, and token-shaped
fields before it writes journal detail. Check recent journal entries after each
deploy and fail the canary if any credential-shaped value appears.

### Disposable repair canary

Use disposable user units to test repair paths. Do not stop a production gateway
or edit a production credential. Create a temporary oneshot service and timer in
`~/.config/systemd/user`, point a temporary copied config at those unit names,
and pass a temporary `--state-file`. For a peer canary, use the same disposable
unit names and the committed SSH target. Remove the temporary units and run
`systemctl --user daemon-reload` after the test.

## The probe

`codex_auth_probe.py` makes a real call to OpenAI. Operators may run it for
triage. The healer may run it once after an eligible credential repair or quota
reset. No healthy scheduled cycle invokes it.

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

Run the probe by hand when you need live headroom. Keep it off healthy schedules.

## Rollback

1. Create the role's `SELF_HEAL_PAUSED` file.
2. Disable the role's healer timer with `systemctl --user disable --now <timer>`.
3. Select the newest private snapshot under the role's
   `install-backups/<UTC timestamp>.<suffix>/` directory. Use
   `restore-map.tsv` to restore files from its `files/` and `systemd/`
   directories to the listed targets.
4. Run `systemctl --user daemon-reload`.
5. Restart the original health timer and heartbeat service.
6. Verify their active state and next elapse before removing the maintenance lock.

Keep `state.json`, `self-heal-state.json`, the Hermes auth store, and credential
backups in place. Operators must inspect a credential backup; they must not copy
it over live `auth.json`.

## Tests

```bash
pytest
```

## History

The browser-based reauth machinery is deleted from the working tree. The removal covered
17 modules plus the whole `deploy/` directory, and the 6 tests that covered them.
That includes the Chrome/CDP driver, the Xvfb launcher, the Webshare proxy
forwarder, the Gmail-OTP reader, and the legacy Mac-trigger flow. Playwright is
gone from `requirements.txt`; the watchdog is stdlib-only.

Recovering any of it:

| Want | Where |
|---|---|
| The retired browser reauth design | `docs/SELF-HEAL-codex-reauth.md` (kept) |
| The scripts as they ran on each VM | `watchdog/hosts-deployed/` (kept; they had never been in git) |
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

## Automated PR review

[Shawns QA Assist](https://github.com/Screddyice/shawns-qa-assist) reviews pull
requests here and merges once its gate passes. `.shawns-qa.toml` runs
`scripts/verify.sh`, which parses every tracked shell and Python file.

Without a gate the agent reports `merge_eligible=false` and hands every PR to a
human, because nothing can vouch for the change.

Syntax only, on purpose: this repo has no test suite wired into the gate, and a
gate that failed on pre-existing style would block every PR on faults it did not
introduce. Add a real test command here once there is a suite to run.

```bash
bash scripts/verify.sh   # non-zero and names the file on a syntax error
```

To pause the agent on this repo: `[behavior] enabled = false` in `.shawns-qa.toml`.
