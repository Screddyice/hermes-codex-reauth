# hermes-codex-reauth

## Project Overview

Monitoring for OpenAI Codex (ChatGPT-plan) OAuth on the two Hermes hosts
(`neb-brain-hostinger` and the GCP VM `hermes-tmn`).

Despite the repo name, **it no longer re-authenticates anything.** 2FA made
unattended device-code reauth impossible, so every mutating path was removed on
2026-08-11 and what remains is a detect-and-alert watchdog. The name is kept for
URL stability. See the README.

## Tech Stack
- Python 3, stdlib only (no runtime dependencies)
- bash + systemd user units
- `pytest` is the sole dev dependency

## Common Commands

```bash
pytest                                   # the whole suite
./watchdog/install.sh --host hostinger   # deploy (or --host tmn)
```

## Layout

| Path | What |
|---|---|
| `watchdog/codex_health_check.py` | The watchdog. Canonical, shared by both hosts. |
| `watchdog/hosts/*.json` | Everything host-specific: auth store, gateway unit, channels, runbook. |
| `watchdog/codex_auth_probe.py` | Live probe. **Operator tool, deliberately on no timer.** |
| `watchdog/systemd/` | The four unit files, byte-identical to what is deployed. |
| `watchdog/hosts-deployed/` | Pre-consolidation scripts as they ran on each VM. Archaeology; do not edit. |
| `docs/SELF-HEAL-codex-reauth.md` | Describes the removed self-heal. Historical. |

## Rules specific to this repo

**Never add a default for `hermes_home`.** The two hosts disagree (`~/.hermes` vs
`~/.hermes/profiles/tmn`), and a shared default silently points the TMN box at a
stale auth store and reports a confident, wrong `ok`. A missing value must stay a
hard failure. There is a test for this — do not relax it.

**Never make a failure path quiet.** Every `except` that returns a benign value
and exits 0 is a way for the watchdog to go blind while systemd stays green,
which is exactly how a six-day outage went unnoticed. Raise `Disarmed` instead.

**Do not put the live probe back on a timer.** It ran every 30 minutes under the
old design and produced 3 real detections against 209 quota-exhaustion errors,
consuming the plan quota it existed to protect. The README has the numbers.

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
