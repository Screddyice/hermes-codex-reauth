# Deployed Shell Scripts

This folder is the **source of truth for what is actually running in
production** on the OpenClaw fleet. Each file mirrors the script that lives
on a specific server's `~/.openclaw/scripts/` directory and is invoked from
that server's crontab.

If you change a file here, you must `scp` it to the matching server. If you
change a file on a server, you must commit the change back here. Drift is
a bug.

| File | Lives on | Cron schedule | Role |
|---|---|---|---|
| `neb-token-refresh-cron.sh` | NEB (`i-0697d5ce8e38b6fc6`) at `~/.openclaw/scripts/token-refresh-cron.sh` | `*/15 * * * *` | Token authority. Refreshes the OpenAI Codex token when it drops below 2h remaining, writes it to all local auth-profiles, and uploads the new token to S3 so workers can pull it. |
| `cliqk-pull-fresh-tokens-from-s3.sh` | Cliqk (`172.31.13.177`) at `~/.openclaw/scripts/pull-fresh-tokens-from-s3.sh` | `*/5 * * * *` | Worker. Pulls the canonical token from S3 every 5 minutes and writes it into local auth-profiles + cache. **Never** calls the OpenAI refresh endpoint directly. |

## Architecture

```
                           OpenAI /token
                                ▲
                                │ refresh (NEB only)
                                │
                          ┌─────┴─────┐
                          │    NEB    │   neb-token-refresh-cron.sh
                          │ (authority)│   ── refresh ─▶ S3
                          └─────┬─────┘
                                │ upload after refresh
                                ▼
                ┌──────────────────────────────────┐
                │  s3://openclaw-secrets-…/oauth/  │
                │     openai-auth-profiles.json    │
                └──────────────────┬───────────────┘
                                   │ pull every 5 min
                                   ▼
                          ┌─────────────┐
                          │    Cliqk    │   cliqk-pull-fresh-tokens-from-s3.sh
                          │  (worker)   │
                          └─────────────┘
```

The single-source-of-truth for the refresh token is **NEB**. OpenAI refresh
tokens are single-use, so only one server may call `/token`. Workers fan out
from S3.

## Sync workflow

After editing a script in this folder, deploy it like so:

```bash
# NEB
scp deploy/neb-token-refresh-cron.sh \
    neb-server:~/.openclaw/scripts/token-refresh-cron.sh

# Cliqk (via NEB jumphost — Cliqk is on a private VPC IP)
scp deploy/cliqk-pull-fresh-tokens-from-s3.sh neb-server:/tmp/p.sh
ssh neb-server 'scp -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=no \
    /tmp/p.sh ubuntu@172.31.13.177:~/.openclaw/scripts/pull-fresh-tokens-from-s3.sh && rm /tmp/p.sh'
```

## Relationship to the Python flow

The Python modules at the repo root (`oauth_manager.py`, `token_refresh.py`,
`token_logic.py`, `token_distribute.py`, `headless_reauth.py`, `configure.py`)
are a **second, more general design** that can replace these shell scripts
entirely. It is not currently deployed. Until it is, the shell scripts in
this folder are the authoritative running flow.
