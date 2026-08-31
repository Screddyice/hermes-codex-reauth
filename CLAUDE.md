# hermes-codex-reauth

## Project Overview

Monitoring for OpenAI Codex (ChatGPT-plan) OAuth on `src` and `neb-ops-gcp`,
with the legacy `hermes-tmn` VM serving as a credential-free observer.

The scheduled checks inspect passive state. A separate 15-minute healer performs
bounded timer, gateway, credential, quota-reset, and allowlisted peer repairs.
OpenAI device-code login and 2FA remain human work. See the README.

## Tech Stack
- Python 3, stdlib only (no runtime dependencies)
- bash + systemd user units
- `pytest` is the sole dev dependency

## Common Commands

```bash
pytest                                   # the whole suite
./watchdog/install.sh --host src         # deploy (or --host tmn)
```

## Layout

| Path | What |
|---|---|
| `watchdog/codex_health_check.py` | The watchdog. Canonical, shared by both hosts. |
| `watchdog/hosts/*.json` | Everything host-specific: auth store, gateway unit, channels, runbook. |
| `watchdog/auth_state.py` | Shared passive Codex credential and quota classification. |
| `watchdog/self_heal.py` | Bounded local and allowlisted peer repair. |
| `watchdog/codex_auth_probe.py` | Pool-aware probe for operators and one eligible repair attempt. |
| `watchdog/systemd/` | Role-specific check, heartbeat, notifier, and healer units. |
| `watchdog/hosts-deployed/` | Pre-consolidation scripts as they ran on each VM. Archaeology; do not edit. |
| `docs/SELF-HEAL-codex-reauth.md` | Describes the removed self-heal. Historical. |

## Rules specific to this repo

**Never add a default for `hermes_home`.** Each host config must name the store
its live gateway reads. A default can turn a future migration into a confident
check of an unused credential. A missing value must stay a hard failure.

**Never make a failure path quiet.** Every `except` that returns a benign value
and exits 0 is a way for the watchdog to go blind while systemd stays green,
which is exactly how a six-day outage went unnoticed. Raise `Disarmed` instead.

**`notify_failure.py` must not import the health checks.** It is the last thing
that speaks when a check cannot report, so it carries its own config read and env
resolution and stays stdlib-only. A last resort that depends on the component
which just failed is not a last resort. A test asserts the absence of those
imports.

**Its transport must stay independent of the alert channels.** Telegram uses a
different vendor and secret from Composio email. A `TMN_COMPOSIO_API_KEY`
rotation can break email on `src` while Telegram keeps the escalator working.

**The heartbeat server binds the tailnet address, never `0.0.0.0`.** `src` has
a public IP. `heartbeat_server.py` resolves the bind from `tailscale ip -4` and
exits 1 when it cannot, because a monitoring tool that quietly opens a public port
is precisely the class of mistake this repo exists to catch. There is a test.

**A local failure outranks the peer watch.** The peer is only consulted when this
box's own verdict is `ok`. Reporting a dark peer while this box's credential is
broken buries the more urgent problem.
**The observer alerts only when EVERY peer is dark.** While one Hermes box is up
it reports its dark partner, so an alert from `hermes-tmn-observer` would page
twice for one event. Widening it to "any peer dark" adds noise.

**Observer mode is not a loophole in the `hermes_home` rule.** It is exempt purely
because it inspects no credential; any config without `mode: observer` must still
hard-fail with no auth store. There is a test asserting both halves.


**Keep healer mutation bounded.** One cycle may attempt one local timer repair,
one gateway restart, one backed-up Hermes credential warmup plus one probe, and
one repair per allowlisted peer. The healer must verify each postcondition.

**Let Hermes write OAuth state.** The healer may make a mode-`0600` copy of
`auth.json`, retain five snapshots, and invoke one pinned Hermes warmup. It must
not edit token fields, restore an old snapshot, call `hermes auth reset`, redeem
usage-reset credits, or automate device-code login and 2FA.

**Keep peer SSH fixed and narrow.** Accept Tailscale IPs and committed users,
paths, and unit names only. Require a private identity and pinned host-key file.
Pass argv without shell fragments. Do not use `sudo` or accept an arbitrary
remote command.

**Keep healthy scheduled cycles passive.** The 15-minute healer may run the live
probe only after an eligible credential repair or recorded quota reset. The old
30-minute probe produced 3 detections and 209 quota errors. Keep the probe off
healthy schedules.

**Honor maintenance locks and systemd masks.** A role's `SELF_HEAL_PAUSED` file
blocks mutation and exits zero. A masked timer stays unchanged.

**Preserve first-failure alerting.** A repair fault sends one `OnFailure=` alert.
Repeated cycles stay quiet until recovery clears the fault and re-arms a later
incident.

**Quota detection stays passive.** The scheduled check reads exhaustion from the
`credential_pool` records Hermes already writes to `auth.json` (`last_status:
exhausted`, `last_error_code: 429`, `resets_at` in the stored 429 body). It costs
no network call. If you are tempted to improve it by scheduling the probe, that is
the mistake the rule above describes.

**Keep `quota` a separate verdict from `down`, and keep `reauth_url` out of quota
prose.** They need opposite actions. A `down` alert says complete a device-code
login; during the 2026-08-15..17 outage two logins were completed against an
exhausted plan and fixed nothing. A test asserts the device URL never appears in a
quota alert or ticket.

**Never page on `chatgpt_plan_type` alone.** The claim is baked at token issuance
and lags a plan change, so it read `free` while the upgraded account was already
serving. Print it as context; trigger on the 429 record.

**Deploy is by copy, never `git pull`.** Neither box has git credentials for this
private repo: `tar` + `scp` / `gcloud compute scp` + `install.sh`.

## Session Startup Protocol
On every session start:
1. Working context is auto-injected at session start (features, decisions, failures, rules)
2. Run `/claude-harness:start` for full context refresh with GitHub sync (optional)
3. Check `.claude-harness/features/active.json` for current priorities

## Development Rules
- Work on ONE feature at a time
- Always run /claude-harness:checkpoint after completing work
- Run tests before marking features complete
- Commit with descriptive messages
- Leave codebase in clean, working state

## Testing Requirements
- Test: `pytest`
- No build, lint, or typecheck step — this repo has no JavaScript.

## Progress Tracking
See: `.claude-harness/sessions/{session-id}/context.json` and `.claude-harness/features/active.json`

## Memory Architecture (v3.0)
- `sessions/{session-id}/` - Current session context (per-session, gitignored)
- `memory/episodic/` - Recent decisions (rolling window)
- `memory/semantic/` - Project knowledge (persistent)
- `memory/procedural/` - Success/failure patterns (append-only)
- `memory/learned/` - Rules from user corrections (append-only)
