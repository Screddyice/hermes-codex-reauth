# OpenClaw OAuth Manager — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Combine the existing headless-oauth-recovery and openclaw-oauth-protocol repos into a unified, generic, open-source OAuth management toolkit for OpenClaw servers supporting Claude, ChatGPT, Gemini, and Perplexity.

**Architecture:** Layered recovery system (API refresh -> S3 distribution -> headless browser recovery) orchestrated by a single `oauth_manager.py` entry point. Pure decision logic in `token_logic.py` (tested), I/O in `token_refresh.py` and `token_distribute.py`, headless browser in adapted `headless_reauth.py`, interactive setup in `configure.py`.

**Tech Stack:** Python 3.8+, boto3 (S3), playwright (headless Chrome CDP), pytest

**Spec:** `docs/2026-03-27-openclaw-oauth-manager-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `token_logic.py` | Create | Pure decision functions — no I/O, fully tested |
| `test_token_logic.py` | Create | Unit tests for all decision functions |
| `token_refresh.py` | Create | API-based token refresh, auth-profile read/write, provider constants |
| `test_token_refresh.py` | Create | Unit tests for provider mapping, token parsing, write logic |
| `token_distribute.py` | Create | S3 upload/download, SSH push, remote health probing |
| `oauth_manager.py` | Create | CLI entry point: check, refresh, recover, status |
| `headless_reauth.py` | Modify | Add module API (`recover_server()`), `--config` flag, Gemini flow |
| `configure.py` | Create | Interactive setup wizard + `--reconfigure` |
| `setup_gmail.py` | Keep | No changes |
| `config.example.json` | Rewrite | Updated schema with all 4 providers |
| `.gitignore` | Modify | Add new paths |
| `requirements.txt` | Create | Python dependencies |
| `LICENSE` | Create | MIT license |
| `README.md` | Rewrite | Full documentation |

Old files to remove: `pull-fresh-tokens-from-s3.sh`, `token-authority-refresh.sh`, `token-failure-watchdog.sh`, `token_pull_logic.py` (from archived repo — already in this repo's working tree if copied)

---

## Task 1: Project scaffolding and cleanup

**Files:**
- Modify: `.gitignore`
- Create: `requirements.txt`
- Create: `LICENSE`

- [ ] **Step 1: Update .gitignore**

Add to existing `.gitignore`:

```
# Existing
config.json
*.pyc
__pycache__/
.env
*.log
screenshots/
browser-profiles/

# New
.openclaw-oauth/
*.tmp
/tmp/
.pytest_cache/
venv/
```

- [ ] **Step 2: Create requirements.txt**

```
boto3>=1.26.0
playwright>=1.40.0
pytest>=7.0.0
```

- [ ] **Step 3: Create LICENSE**

MIT license with year 2026.

- [ ] **Step 4: Commit**

```bash
git add .gitignore requirements.txt LICENSE
git commit -m "chore: add project scaffolding — requirements, license, gitignore"
```

---

## Task 2: `token_logic.py` — Pure decision functions

Port and generalize `token_pull_logic.py` from the archived repo. Add new functions for headless cooldown and token health classification. All functions are pure (no I/O).

**Files:**
- Create: `token_logic.py`
- Create: `test_token_logic.py`

- [ ] **Step 1: Write failing tests for `token_health()`**

```python
# test_token_logic.py
import time
import pytest

NOW = int(time.time() * 1000)
ONE_HOUR = 3600 * 1000
ONE_MIN = 60 * 1000


class TestTokenHealth:

    def test_returns_no_token_for_zero(self):
        from token_logic import token_health
        assert token_health(0, NOW) == "NO_TOKEN"

    def test_returns_expired_when_past(self):
        from token_logic import token_health
        assert token_health(NOW - ONE_HOUR, NOW) == "EXPIRED"

    def test_returns_critical_under_1h(self):
        from token_logic import token_health
        assert token_health(NOW + 30 * ONE_MIN, NOW) == "CRITICAL"

    def test_returns_low_under_3h(self):
        from token_logic import token_health
        assert token_health(NOW + 2 * ONE_HOUR, NOW) == "LOW"

    def test_returns_ok_above_3h(self):
        from token_logic import token_health
        assert token_health(NOW + 5 * ONE_HOUR, NOW) == "OK"

    def test_returns_expired_at_exact_now(self):
        from token_logic import token_health
        assert token_health(NOW, NOW) == "EXPIRED"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python3 -m pytest test_token_logic.py::TestTokenHealth -v
```

Expected: FAIL — `token_logic` module not found

- [ ] **Step 3: Write `token_logic.py` with `token_health()`**

```python
"""
token_logic.py — Pure decision functions for OpenClaw OAuth management.
No I/O, no side effects. Easy to test and reason about.
"""


def token_health(expires_ms: int, now_ms: int) -> str:
    """Classify token health based on expiry timestamp.

    Returns: 'OK', 'LOW', 'CRITICAL', 'EXPIRED', or 'NO_TOKEN'.
    """
    if expires_ms <= 0:
        return "NO_TOKEN"
    if expires_ms <= now_ms:
        return "EXPIRED"
    remaining_hours = (expires_ms - now_ms) / 3600000
    if remaining_hours < 1.0:
        return "CRITICAL"
    if remaining_hours < 3.0:
        return "LOW"
    return "OK"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python3 -m pytest test_token_logic.py::TestTokenHealth -v
```

Expected: 6 passed

- [ ] **Step 5: Write failing tests for `should_self_refresh()`**

Add to `test_token_logic.py`:

```python
class TestShouldSelfRefresh:

    def test_false_when_local_valid(self):
        from token_logic import should_self_refresh
        assert should_self_refresh(
            local_expires=NOW + 2 * ONE_HOUR,
            s3_expires=NOW - ONE_HOUR,
            last_attempt=0, now=NOW,
            cooldown_ms=30 * ONE_MIN,
        ) is False

    def test_false_when_s3_valid(self):
        from token_logic import should_self_refresh
        assert should_self_refresh(
            local_expires=NOW - ONE_HOUR,
            s3_expires=NOW + 2 * ONE_HOUR,
            last_attempt=0, now=NOW,
            cooldown_ms=30 * ONE_MIN,
        ) is False

    def test_false_within_cooldown(self):
        from token_logic import should_self_refresh
        assert should_self_refresh(
            local_expires=NOW - ONE_HOUR,
            s3_expires=NOW - ONE_HOUR,
            last_attempt=NOW - 20 * ONE_MIN,
            now=NOW, cooldown_ms=30 * ONE_MIN,
        ) is False

    def test_true_both_expired_no_prior_attempt(self):
        from token_logic import should_self_refresh
        assert should_self_refresh(
            local_expires=NOW - ONE_HOUR,
            s3_expires=NOW - ONE_HOUR,
            last_attempt=0, now=NOW,
            cooldown_ms=30 * ONE_MIN,
        ) is True

    def test_true_both_expired_cooldown_passed(self):
        from token_logic import should_self_refresh
        assert should_self_refresh(
            local_expires=NOW - ONE_HOUR,
            s3_expires=NOW - ONE_HOUR,
            last_attempt=NOW - 31 * ONE_MIN,
            now=NOW, cooldown_ms=30 * ONE_MIN,
        ) is True

    def test_none_last_attempt_treated_as_zero(self):
        from token_logic import should_self_refresh
        assert should_self_refresh(
            local_expires=NOW - ONE_HOUR,
            s3_expires=NOW - ONE_HOUR,
            last_attempt=None, now=NOW,
            cooldown_ms=30 * ONE_MIN,
        ) is True
```

- [ ] **Step 6: Implement `should_self_refresh()`**

```python
def should_self_refresh(local_expires, s3_expires, last_attempt, now, cooldown_ms):
    """Whether to attempt API self-refresh. Rate-limited by cooldown_ms.

    Returns True only when:
      - Both local AND S3 tokens are expired
      - No recent attempt within cooldown window
    """
    if local_expires is not None and local_expires > now:
        return False
    if s3_expires is not None and s3_expires > now:
        return False
    attempt_ts = last_attempt or 0
    if attempt_ts > 0 and (now - attempt_ts) <= cooldown_ms:
        return False
    return True
```

- [ ] **Step 7: Run tests — verify pass**

```bash
python3 -m pytest test_token_logic.py::TestShouldSelfRefresh -v
```

Expected: 6 passed

- [ ] **Step 8: Write failing tests for `should_update_from_s3()`**

```python
class TestShouldUpdateFromS3:

    def test_updates_when_s3_fresher(self):
        from token_logic import should_update_from_s3
        assert should_update_from_s3(NOW + 3 * ONE_HOUR, NOW + ONE_HOUR, NOW) is True

    def test_no_update_when_local_fresher(self):
        from token_logic import should_update_from_s3
        assert should_update_from_s3(NOW + ONE_HOUR, NOW + 3 * ONE_HOUR, NOW) is False

    def test_no_update_when_s3_expired(self):
        from token_logic import should_update_from_s3
        assert should_update_from_s3(NOW - ONE_MIN, NOW - ONE_HOUR, NOW) is False

    def test_no_update_when_identical_expiry(self):
        from token_logic import should_update_from_s3
        t = NOW + 2 * ONE_HOUR
        assert should_update_from_s3(t, t, NOW) is False
```

- [ ] **Step 9: Implement `should_update_from_s3()`**

```python
def should_update_from_s3(s3_expires, local_expires, now):
    """Whether local token should be replaced with S3 token."""
    if s3_expires <= now:
        return False
    if s3_expires <= local_expires:
        return False
    return True
```

- [ ] **Step 10: Run tests — verify pass**

```bash
python3 -m pytest test_token_logic.py::TestShouldUpdateFromS3 -v
```

- [ ] **Step 11: Write failing tests for `needs_profile_cleanup()` and `should_headless_recover()`**

```python
class TestNeedsProfileCleanup:

    def test_clean_profile_returns_false(self):
        from token_logic import needs_profile_cleanup
        profile = {
            "profiles": {"openai-codex:codex-cli": {"access": "tok"}},
            "lastGood": {"openai-codex": "openai-codex:codex-cli"},
        }
        assert needs_profile_cleanup(profile, "openai-codex:codex-cli") is False

    def test_stale_api_key_returns_true(self):
        from token_logic import needs_profile_cleanup
        profile = {
            "profiles": {
                "openai-codex:codex-cli": {"access": "tok"},
                "openai-codex:api_key": {"key": "sk-xxx"},
            },
            "lastGood": {"openai-codex": "openai-codex:codex-cli"},
        }
        assert needs_profile_cleanup(profile, "openai-codex:codex-cli") is True

    def test_wrong_lastgood_returns_true(self):
        from token_logic import needs_profile_cleanup
        profile = {
            "profiles": {"openai-codex:codex-cli": {"access": "tok"}},
            "lastGood": {"openai-codex": "openai-codex:api_key"},
        }
        assert needs_profile_cleanup(profile, "openai-codex:codex-cli") is True

    def test_missing_lastgood_returns_true(self):
        from token_logic import needs_profile_cleanup
        profile = {"profiles": {"openai-codex:codex-cli": {"access": "tok"}}}
        assert needs_profile_cleanup(profile, "openai-codex:codex-cli") is True


class TestShouldHeadlessRecover:

    def test_allowed_when_no_prior_attempt(self):
        from token_logic import should_headless_recover
        assert should_headless_recover(0, NOW, 30 * ONE_MIN) is True

    def test_blocked_within_cooldown(self):
        from token_logic import should_headless_recover
        assert should_headless_recover(NOW - 10 * ONE_MIN, NOW, 30 * ONE_MIN) is False

    def test_allowed_after_cooldown(self):
        from token_logic import should_headless_recover
        assert should_headless_recover(NOW - 31 * ONE_MIN, NOW, 30 * ONE_MIN) is True
```

- [ ] **Step 12: Implement `needs_profile_cleanup()` and `should_headless_recover()`**

```python
def needs_profile_cleanup(profile: dict, provider_profile: str) -> bool:
    """Whether auth-profiles.json needs stale entries removed."""
    profiles = profile.get("profiles", {})
    # Extract provider name from profile key (e.g., "openai-codex" from "openai-codex:codex-cli")
    provider_name = provider_profile.split(":")[0]
    api_key_name = f"{provider_name}:api_key"
    if api_key_name in profiles:
        return True
    last_good = profile.get("lastGood", {})
    if last_good.get(provider_name) != provider_profile:
        return True
    return False


def should_headless_recover(last_attempt_ms: int, now_ms: int, cooldown_ms: int) -> bool:
    """Whether headless recovery is allowed (outside cooldown window)."""
    if last_attempt_ms <= 0:
        return True
    return (now_ms - last_attempt_ms) > cooldown_ms
```

- [ ] **Step 13: Run all tests**

```bash
python3 -m pytest test_token_logic.py -v
```

Expected: all passed (23 tests)

- [ ] **Step 14: Commit**

```bash
git add token_logic.py test_token_logic.py
git commit -m "feat: add token_logic.py — pure decision functions with full test coverage"
```

---

## Task 3: `token_refresh.py` — Provider constants, auth-profile I/O, API refresh

**Files:**
- Create: `token_refresh.py`
- Create: `test_token_refresh.py`

- [ ] **Step 1: Write failing tests for provider constants and profile path discovery**

```python
# test_token_refresh.py
import pytest


class TestProviderConstants:

    def test_claude_profile_key(self):
        from token_refresh import get_profile_key
        assert get_profile_key("claude") == "openai-codex:codex-cli"

    def test_chatgpt_profile_key(self):
        from token_refresh import get_profile_key
        assert get_profile_key("chatgpt") == "openai:oauth"

    def test_gemini_profile_key(self):
        from token_refresh import get_profile_key
        assert get_profile_key("gemini") == "google-gemini:oauth"

    def test_perplexity_profile_key(self):
        from token_refresh import get_profile_key
        assert get_profile_key("perplexity") == "perplexity:api_key"

    def test_unknown_provider_raises(self):
        from token_refresh import get_profile_key
        with pytest.raises(ValueError):
            get_profile_key("unknown")

    def test_claude_supports_api_refresh(self):
        from token_refresh import supports_api_refresh
        assert supports_api_refresh("claude") is True

    def test_chatgpt_no_api_refresh(self):
        from token_refresh import supports_api_refresh
        assert supports_api_refresh("chatgpt") is False

    def test_gemini_supports_api_refresh(self):
        from token_refresh import supports_api_refresh
        assert supports_api_refresh("gemini") is True

    def test_perplexity_no_api_refresh(self):
        from token_refresh import supports_api_refresh
        assert supports_api_refresh("perplexity") is False
```

- [ ] **Step 2: Run tests — verify fail**

```bash
python3 -m pytest test_token_refresh.py -v
```

- [ ] **Step 3: Implement provider constants**

```python
"""
token_refresh.py — API-based token refresh and auth-profile I/O.
"""
import glob
import json
import os
import time
import urllib.parse
import urllib.request
import urllib.error


# ── Provider Registry ──────────────────────────────────────────────────

PROVIDERS = {
    "claude": {
        "profile_key": "openai-codex:codex-cli",
        "provider_name": "openai-codex",
        "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
        "token_url": "https://platform.claude.com/v1/oauth/token",
        "api_refresh": True,
    },
    "chatgpt": {
        "profile_key": "openai:oauth",
        "provider_name": "openai",
        "client_id": None,
        "token_url": None,
        "api_refresh": False,
    },
    "gemini": {
        "profile_key": "google-gemini:oauth",
        "provider_name": "google-gemini",
        "client_id": None,  # Extracted at runtime from @google/gemini-cli
        "client_secret": None,
        "token_url": "https://oauth2.googleapis.com/token",
        "api_refresh": True,
    },
    "perplexity": {
        "profile_key": "perplexity:api_key",
        "provider_name": "perplexity",
        "client_id": None,
        "token_url": None,
        "api_refresh": False,
    },
}


# ── Exceptions ─────────────────────────────────────────────────────────

class TokenRefreshError(Exception):
    """Base class for token refresh failures."""

class InvalidGrantError(TokenRefreshError):
    """Refresh token was revoked or already consumed."""

class ProviderUnavailableError(TokenRefreshError):
    """Provider returned 5xx or timed out."""

class UnsupportedProviderError(TokenRefreshError):
    """Provider does not support API refresh."""


# ── Public API ─────────────────────────────────────────────────────────

def get_profile_key(provider: str) -> str:
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}")
    return PROVIDERS[provider]["profile_key"]


def supports_api_refresh(provider: str) -> bool:
    return PROVIDERS.get(provider, {}).get("api_refresh", False)


def get_provider_name(provider: str) -> str:
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}")
    return PROVIDERS[provider]["provider_name"]


def get_auth_profile_paths() -> list:
    """Glob for all auth-profiles.json files in standard OpenClaw locations."""
    return (
        glob.glob(os.path.expanduser("~/.openclaw/auth-profiles.json"))
        + glob.glob(os.path.expanduser("~/.openclaw/agents/*/agent/auth-profiles.json"))
    )


def find_best_token(paths: list, provider_profile: str) -> dict | None:
    """Scan auth-profiles.json files, return token with longest remaining life."""
    best = None
    best_expires = 0
    for p in paths:
        try:
            with open(p) as f:
                d = json.load(f)
            oauth = d.get("profiles", {}).get(provider_profile, {})
            exp = oauth.get("expires", 0)
            if exp > best_expires:
                best_expires = exp
                best = oauth
        except Exception:
            pass
    return best


def write_tokens(paths: list, provider_profile: str, oauth: dict) -> int:
    """Write new token to all local auth-profiles.json files.
    Cleans up stale api_key entries and sets lastGood. Returns count updated."""
    provider_name = provider_profile.split(":")[0]
    api_key_name = f"{provider_name}:api_key"
    updated = 0
    for p in paths:
        try:
            with open(p) as f:
                d = json.load(f)
            d.setdefault("profiles", {})[provider_profile] = oauth
            d.get("profiles", {}).pop(api_key_name, None)
            d.setdefault("lastGood", {})[provider_name] = provider_profile
            with open(p, "w") as f:
                json.dump(d, f)
            updated += 1
        except Exception:
            pass
    return updated


def refresh_token(provider: str, refresh_tok: str) -> dict:
    """Call provider's OAuth endpoint. Returns {access, refresh, expires, ...}.

    Raises:
      UnsupportedProviderError — provider has no API refresh
      InvalidGrantError — refresh token revoked/consumed
      ProviderUnavailableError — 5xx or timeout
    """
    if not supports_api_refresh(provider):
        raise UnsupportedProviderError(f"{provider} does not support API refresh")

    prov = PROVIDERS[provider]

    if provider == "claude":
        return _refresh_claude(prov, refresh_tok)
    elif provider == "gemini":
        return _refresh_gemini(prov, refresh_tok)
    else:
        raise UnsupportedProviderError(f"No refresh implementation for {provider}")


# ── Private refresh implementations ───────────────────────────────────

def _refresh_claude(prov: dict, refresh_tok: str) -> dict:
    payload = json.dumps({
        "grant_type": "refresh_token",
        "client_id": prov["client_id"],
        "refresh_token": refresh_tok,
    }).encode()
    req = urllib.request.Request(
        prov["token_url"],
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "OpenClawOAuth/1.0"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()
        except Exception:
            pass
        if e.code == 400 or "invalid_grant" in body:
            raise InvalidGrantError(f"HTTP {e.code}: {body[:200]}")
        if e.code >= 500:
            raise ProviderUnavailableError(f"HTTP {e.code}: {body[:200]}")
        raise TokenRefreshError(f"HTTP {e.code}: {body[:200]}")
    except Exception as e:
        raise ProviderUnavailableError(str(e))

    if "access_token" not in result:
        raise TokenRefreshError(f"No access_token in response: {json.dumps(result)[:200]}")

    return {
        "type": "oauth",
        "provider": prov["provider_name"],
        "access": result["access_token"],
        "refresh": result["refresh_token"],
        "expires": int(time.time() * 1000) + result["expires_in"] * 1000 - 5 * 60 * 1000,
        "scopes": ["user:inference", "user:profile"],
    }


def _refresh_gemini(prov: dict, refresh_tok: str) -> dict:
    client_id, client_secret = _get_gemini_credentials(prov)
    payload = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_tok,
    }).encode()
    req = urllib.request.Request(
        prov["token_url"],
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()
        except Exception:
            pass
        if e.code == 400 or "invalid_grant" in body:
            raise InvalidGrantError(f"HTTP {e.code}: {body[:200]}")
        if e.code >= 500:
            raise ProviderUnavailableError(f"HTTP {e.code}: {body[:200]}")
        raise TokenRefreshError(f"HTTP {e.code}: {body[:200]}")
    except Exception as e:
        raise ProviderUnavailableError(str(e))

    if "access_token" not in result:
        raise TokenRefreshError(f"No access_token: {json.dumps(result)[:200]}")

    return {
        "type": "oauth",
        "provider": prov["provider_name"],
        "access": result["access_token"],
        "refresh": result.get("refresh_token", refresh_tok),  # Google may not return new refresh token
        "expires": int(time.time() * 1000) + result.get("expires_in", 3600) * 1000 - 60 * 1000,
        "scopes": ["cloud-platform", "userinfo.email"],
    }


def _get_gemini_credentials(prov: dict) -> tuple:
    """Extract Gemini client ID and secret from installed npm package or fallback."""
    # Try extracting from installed @google/gemini-cli
    try:
        import subprocess
        result = subprocess.run(
            ["node", "-e", "const p=require.resolve('@google/gemini-cli/package.json');const fs=require('fs');const d=fs.readFileSync(p.replace('package.json','dist/oauth2.js'),'utf8');const id=d.match(/client_id['\"]?\\s*[:=]\\s*['\"]([^'\"]+)/);const sec=d.match(/client_secret['\"]?\\s*[:=]\\s*['\"]([^'\"]+)/);console.log(JSON.stringify({id:id?.[1],sec:sec?.[1]}))"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout.strip())
            if data.get("id") and data.get("sec"):
                return data["id"], data["sec"]
    except Exception:
        pass
    # Fallback to well-known values
    return (
        prov.get("client_id") or "NOT_CONFIGURED",
        prov.get("client_secret") or "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",
    )
```

- [ ] **Step 4: Run provider constant tests — verify pass**

```bash
python3 -m pytest test_token_refresh.py::TestProviderConstants -v
```

- [ ] **Step 5: Write failing tests for `find_best_token` and `write_tokens`**

```python
import json
import os
import tempfile

class TestFindBestToken:

    def test_finds_token_with_longest_expiry(self, tmp_path):
        from token_refresh import find_best_token
        p1 = tmp_path / "a.json"
        p2 = tmp_path / "b.json"
        p1.write_text(json.dumps({"profiles": {"openai-codex:codex-cli": {"access": "old", "expires": 1000}}}))
        p2.write_text(json.dumps({"profiles": {"openai-codex:codex-cli": {"access": "new", "expires": 2000}}}))
        result = find_best_token([str(p1), str(p2)], "openai-codex:codex-cli")
        assert result["access"] == "new"

    def test_returns_none_when_no_profiles(self, tmp_path):
        from token_refresh import find_best_token
        p = tmp_path / "empty.json"
        p.write_text(json.dumps({"profiles": {}}))
        assert find_best_token([str(p)], "openai-codex:codex-cli") is None


class TestWriteTokens:

    def test_writes_token_and_cleans_api_key(self, tmp_path):
        from token_refresh import write_tokens
        p = tmp_path / "prof.json"
        p.write_text(json.dumps({
            "profiles": {
                "openai-codex:codex-cli": {"access": "old"},
                "openai-codex:api_key": {"key": "stale"},
            },
            "lastGood": {},
        }))
        oauth = {"access": "new", "refresh": "ref", "expires": 9999}
        count = write_tokens([str(p)], "openai-codex:codex-cli", oauth)
        assert count == 1
        data = json.loads(p.read_text())
        assert data["profiles"]["openai-codex:codex-cli"]["access"] == "new"
        assert "openai-codex:api_key" not in data["profiles"]
        assert data["lastGood"]["openai-codex"] == "openai-codex:codex-cli"
```

- [ ] **Step 6: Run tests — verify pass (implementation already written above)**

```bash
python3 -m pytest test_token_refresh.py -v
```

Expected: all passed

- [ ] **Step 7: Commit**

```bash
git add token_refresh.py test_token_refresh.py
git commit -m "feat: add token_refresh.py — provider constants, auth-profile I/O, API refresh"
```

---

## Task 4: `token_distribute.py` — S3 and SSH distribution

**Files:**
- Create: `token_distribute.py`

No unit tests for this module — all functions require external services (S3, SSH). Tested via integration.

- [ ] **Step 1: Create `token_distribute.py`**

```python
"""
token_distribute.py — S3 upload/download and SSH push to remote servers.
"""
import json
import os
import subprocess
import tempfile


def upload_to_s3(oauth: dict, provider_profile: str, config: dict) -> bool:
    """Upload token to S3 bucket in versioned envelope format."""
    s3_config = config.get("s3", {})
    bucket = s3_config.get("bucket")
    key = s3_config.get("key", "oauth/tokens.json")
    region = s3_config.get("region", "us-east-2")
    if not bucket:
        return False
    try:
        import boto3
        s3_data = {"version": 1, "profiles": {provider_profile: oauth}}
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(s3_data, tmp)
        tmp.close()
        s3 = boto3.client("s3", region_name=region)
        s3.upload_file(tmp.name, bucket, key)
        os.unlink(tmp.name)
        return True
    except Exception:
        return False


def download_from_s3(config: dict, provider_profile: str) -> dict | None:
    """Download token from S3. Returns oauth dict or None."""
    s3_config = config.get("s3", {})
    bucket = s3_config.get("bucket")
    key = s3_config.get("key", "oauth/tokens.json")
    region = s3_config.get("region", "us-east-2")
    if not bucket:
        return None
    try:
        import boto3
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        s3 = boto3.client("s3", region_name=region)
        s3.download_file(bucket, key, tmp.name)
        with open(tmp.name) as f:
            data = json.load(f)
        os.unlink(tmp.name)
        return data.get("profiles", {}).get(provider_profile)
    except Exception:
        return None


def push_to_remote(server_name: str, server_config: dict, oauth: dict, provider_profile: str) -> bool:
    """SSH into remote, write token to all auth-profiles.json files."""
    hostname = server_config.get("hostname")
    ssh_user = server_config.get("ssh_user", "ubuntu")
    ssh_key = os.path.expanduser(server_config.get("ssh_key", "~/.ssh/id_ed25519"))
    instance_id = server_config.get("instance_id")
    if not hostname:
        return False

    # Optional: push SSH key via EC2 Instance Connect
    if instance_id:
        try:
            subprocess.run(
                ["aws", "ec2-instance-connect", "send-ssh-public-key",
                 "--instance-id", instance_id,
                 "--instance-os-user", ssh_user,
                 "--ssh-public-key", f"file://{ssh_key}.pub"],
                capture_output=True, timeout=15, check=True,
            )
        except Exception:
            pass

    # SCP tokens + remote inject script
    tokens_json = json.dumps(oauth)
    ssh_target = f"{ssh_user}@{hostname}"
    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
                "-o", "BatchMode=yes", "-i", ssh_key]

    inject_script = f"""import json, glob, os
tokens = json.loads('''{tokens_json}''')
profile_key = '{provider_profile}'
provider_name = profile_key.split(':')[0]
api_key_name = f'{{provider_name}}:api_key'
paths = glob.glob(os.path.expanduser('~/.openclaw/auth-profiles.json')) + \\
        glob.glob(os.path.expanduser('~/.openclaw/agents/*/agent/auth-profiles.json'))
updated = 0
for p in paths:
    try:
        with open(p) as f:
            d = json.load(f)
        d.setdefault('profiles', {{}})[profile_key] = tokens
        d.get('profiles', {{}}).pop(api_key_name, None)
        d.setdefault('lastGood', {{}})[provider_name] = profile_key
        with open(p, 'w') as f:
            json.dump(d, f)
        updated += 1
    except:
        pass
print(f'OK:{{updated}} files')
"""
    try:
        result = subprocess.run(
            ["ssh"] + ssh_opts + [ssh_target, f"python3 -c {repr(inject_script)}"],
            capture_output=True, text=True, timeout=30,
        )
        return "OK:" in result.stdout
    except Exception:
        return False


def probe_remote_health(server_name: str, server_config: dict, provider_profile: str) -> float:
    """SSH into remote, return hours remaining on best token. Returns -999 on failure."""
    hostname = server_config.get("hostname")
    ssh_user = server_config.get("ssh_user", "ubuntu")
    ssh_key = os.path.expanduser(server_config.get("ssh_key", "~/.ssh/id_ed25519"))
    if not hostname:
        return -999

    probe_script = f"""import json,time,glob,os
paths=glob.glob(os.path.expanduser('~/.openclaw/auth-profiles.json'))+glob.glob(os.path.expanduser('~/.openclaw/agents/*/agent/auth-profiles.json'))
best=max((json.load(open(p)).get('profiles',{{}}).get('{provider_profile}',{{}}).get('expires',0) for p in paths),default=0)
hrs=round((best-time.time()*1000)/3600000,1)
print(hrs)
"""
    try:
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
             "-o", "BatchMode=yes", "-i", ssh_key,
             f"{ssh_user}@{hostname}", f"python3 -c {repr(probe_script)}"],
            capture_output=True, text=True, timeout=20,
        )
        return float(result.stdout.strip())
    except Exception:
        return -999
```

- [ ] **Step 2: Commit**

```bash
git add token_distribute.py
git commit -m "feat: add token_distribute.py — S3 upload/download and SSH push"
```

---

## Task 5: `oauth_manager.py` — Unified CLI entry point

**Files:**
- Create: `oauth_manager.py`

- [ ] **Step 1: Create `oauth_manager.py`**

Implements: `check`, `refresh`, `recover`, `status` commands. Orchestrates recovery layers based on role and provider.

```python
#!/usr/bin/env python3
"""
oauth_manager.py — Unified entry point for OpenClaw OAuth management.

Usage:
  python3 oauth_manager.py check                # Health check + layered recovery
  python3 oauth_manager.py refresh              # Force API refresh
  python3 oauth_manager.py recover              # Force headless browser recovery
  python3 oauth_manager.py status               # Print token health summary
  python3 oauth_manager.py --config /path.json  # Custom config path
"""
import argparse
import json
import os
import sys
import time
import urllib.request

from token_logic import (
    token_health,
    should_self_refresh,
    should_update_from_s3,
    should_headless_recover,
)
from token_refresh import (
    get_profile_key,
    get_auth_profile_paths,
    find_best_token,
    write_tokens,
    refresh_token,
    supports_api_refresh,
    InvalidGrantError,
    ProviderUnavailableError,
    UnsupportedProviderError,
)

STATE_DIR = os.path.expanduser("~/.openclaw-oauth")
LOG_DIR = os.path.join(STATE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "oauth-manager.log")
HEADLESS_ATTEMPT_FILE = os.path.join(STATE_DIR, "last-headless-attempt")
SELF_REFRESH_ATTEMPT_FILE = os.path.join(STATE_DIR, "last-self-refresh-attempt")


def log(msg):
    os.makedirs(LOG_DIR, exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = f"[{ts}] {msg}"
    print(line)
    try:
        # Rotate if > 500 lines
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE) as f:
                lines = f.readlines()
            if len(lines) > 500:
                lines = lines[-200:]
                with open(LOG_FILE, "w") as f:
                    f.writelines(lines)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def read_timestamp(path: str) -> int:
    try:
        return int(open(path).read().strip())
    except Exception:
        return 0


def write_timestamp(path: str, ts: int):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(str(ts))


def load_config(config_path: str | None) -> dict:
    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            return json.load(f)
    search = [
        os.path.join(os.path.dirname(__file__), "config.json"),
        os.path.expanduser("~/.openclaw-oauth/config.json"),
    ]
    for p in search:
        if os.path.exists(p):
            with open(p) as f:
                return json.load(f)
    print("ERROR: No config.json found. Run: python3 configure.py")
    sys.exit(1)


# ── Commands ───────────────────────────────────────────────────────────

def cmd_status(config):
    provider = config["provider"]
    profile_key = get_profile_key(provider)
    paths = get_auth_profile_paths()
    token = find_best_token(paths, profile_key)
    now = int(time.time() * 1000)

    if provider == "perplexity":
        if token and token.get("access"):
            print(f"Provider: {provider}")
            print(f"API key: {token['access'][:12]}...")
            print("Status: OK (API keys don't expire)")
        else:
            print(f"Provider: {provider}")
            print("Status: NO_KEY — run configure.py to set API key")
        return

    if not token:
        print(f"Provider: {provider}")
        print("Status: NO_TOKEN")
        return

    expires = token.get("expires", 0)
    health = token_health(expires, now)
    hrs = round((expires - now) / 3600000, 1) if expires > now else 0

    print(f"Provider: {provider}")
    print(f"Profile:  {profile_key}")
    print(f"Status:   {health}")
    print(f"Expires:  {hrs}h remaining")
    print(f"Files:    {len(paths)} auth-profiles.json found")


def cmd_refresh(config):
    provider = config["provider"]
    if not supports_api_refresh(provider):
        log(f"Provider {provider} does not support API refresh")
        return False
    profile_key = get_profile_key(provider)
    paths = get_auth_profile_paths()
    token = find_best_token(paths, profile_key)
    if not token or not token.get("refresh"):
        log("No refresh token available")
        return False
    try:
        new_oauth = refresh_token(provider, token["refresh"])
        count = write_tokens(paths, profile_key, new_oauth)
        hrs = round((new_oauth["expires"] - time.time() * 1000) / 3600000, 1)
        log(f"Refreshed: {hrs}h, {count} files updated")
        return True
    except Exception as e:
        log(f"Refresh failed: {e}")
        return False


def cmd_recover(config):
    try:
        from headless_reauth import recover_all
        return recover_all(config)
    except ImportError:
        log("headless_reauth.py not found — headless recovery unavailable")
        return False
    except Exception as e:
        log(f"Headless recovery failed: {e}")
        return False


def cmd_check(config):
    provider = config["provider"]
    role = config.get("role", "standalone")
    profile_key = get_profile_key(provider)
    paths = get_auth_profile_paths()
    now = int(time.time() * 1000)
    cooldown_ms = config.get("headless_recovery_cooldown_minutes", 30) * 60 * 1000
    threshold_hrs = config.get("refresh_threshold_hours", 4)

    # Perplexity: just check key presence
    if provider == "perplexity":
        token = find_best_token(paths, profile_key)
        if token and token.get("access"):
            log("Perplexity API key present")
        else:
            log("WARNING: No Perplexity API key found. Run configure.py")
        return

    # Check local token health
    token = find_best_token(paths, profile_key)
    expires = token.get("expires", 0) if token else 0
    health = token_health(expires, now)
    hrs = round((expires - now) / 3600000, 1) if expires > now else 0

    log(f"Health: {health} ({hrs}h remaining)")

    # Authority: also check remotes
    if role == "authority":
        _authority_check_remotes(config, profile_key, token, paths)

    # If healthy and not authority, done
    if health == "OK" and role != "authority":
        return

    # Determine if we need intervention based on threshold
    remaining_hrs = (expires - now) / 3600000 if expires > now else 0
    if remaining_hrs >= threshold_hrs and health != "EXPIRED":
        return

    # Layer 1: API Refresh
    if supports_api_refresh(provider) and token and token.get("refresh"):
        log("Layer 1: Attempting API refresh...")
        try:
            new_oauth = refresh_token(provider, token["refresh"])
            count = write_tokens(paths, profile_key, new_oauth)
            new_hrs = round((new_oauth["expires"] - time.time() * 1000) / 3600000, 1)
            log(f"Layer 1 OK: refreshed {new_hrs}h, {count} files")
            # If authority, distribute
            if role == "authority":
                _distribute(config, new_oauth, profile_key)
            return
        except InvalidGrantError as e:
            log(f"Layer 1 FAIL (invalid grant): {e} — skipping to headless")
        except ProviderUnavailableError as e:
            log(f"Layer 1 FAIL (provider down): {e}")
        except Exception as e:
            log(f"Layer 1 FAIL: {e}")

    # Layer 2: S3 Pull (multi-server only)
    if role in ("receiver", "authority") and config.get("s3", {}).get("bucket"):
        log("Layer 2: Trying S3 pull...")
        from token_distribute import download_from_s3
        s3_oauth = download_from_s3(config, profile_key)
        if s3_oauth:
            s3_expires = s3_oauth.get("expires", 0)
            if should_update_from_s3(s3_expires, expires, now):
                count = write_tokens(paths, profile_key, s3_oauth)
                s3_hrs = round((s3_expires - now) / 3600000, 1)
                log(f"Layer 2 OK: S3 token applied, {s3_hrs}h, {count} files")
                return
            else:
                log("Layer 2: S3 token not fresher than local")
        else:
            log("Layer 2: S3 download failed or empty")

    # Layer 4: Headless Recovery
    # (Layer 3 — S3 Push — is handled inside Layer 1 success path via _distribute())
    if config.get("headless_enabled", True):
        last_headless = read_timestamp(HEADLESS_ATTEMPT_FILE)
        if should_headless_recover(last_headless, now, cooldown_ms):
            log("Layer 4: Attempting headless recovery...")
            write_timestamp(HEADLESS_ATTEMPT_FILE, now)
            if cmd_recover(config):
                log("Layer 4 OK: headless recovery succeeded")
                # Clear cooldown on success
                try:
                    os.remove(HEADLESS_ATTEMPT_FILE)
                except Exception:
                    pass
                return
            else:
                log("Layer 4 FAIL: headless recovery failed")
        else:
            remaining = round((last_headless + cooldown_ms - now) / 60000, 0)
            log(f"Layer 4: Headless cooldown active ({int(remaining)}m remaining)")

    log("All recovery layers exhausted")
    _notify_slack(config, f"OAuth recovery FAILED for {provider}. All layers exhausted.")


def _authority_check_remotes(config, profile_key, local_token, paths):
    """Authority: probe remotes and push if stale."""
    from token_distribute import probe_remote_health, push_to_remote, upload_to_s3
    servers = config.get("servers", {})
    threshold = config.get("refresh_threshold_hours", 4)
    need_push = False

    for name, srv in servers.items():
        hrs = probe_remote_health(name, srv, profile_key)
        log(f"  Remote {name}: {hrs}h")
        if hrs < threshold:
            need_push = True

    if need_push and local_token:
        _distribute(config, local_token, profile_key)


def _distribute(config, oauth, profile_key):
    """Push tokens to S3 and all remote servers."""
    from token_distribute import upload_to_s3, push_to_remote
    if config.get("s3", {}).get("bucket"):
        ok = upload_to_s3(oauth, profile_key, config)
        log(f"  S3 upload: {'OK' if ok else 'FAIL'}")
    for name, srv in config.get("servers", {}).items():
        ok = push_to_remote(name, srv, oauth, profile_key)
        log(f"  Push {name}: {'OK' if ok else 'FAIL'}")


def _notify_slack(config, message):
    """Send failure notification to Slack if configured."""
    slack = config.get("slack", {})
    token = slack.get("bot_token")
    channel = slack.get("channel")
    if not token or not channel:
        return
    try:
        payload = json.dumps({"channel": channel, "text": message}).encode()
        req = urllib.request.Request(
            "https://slack.com/api/chat.postMessage",
            data=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


# ── Main ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OpenClaw OAuth Manager")
    parser.add_argument("command", nargs="?", default="check",
                        choices=["check", "refresh", "recover", "status"])
    parser.add_argument("--config", default=None, help="Path to config.json")
    args = parser.parse_args()

    config = load_config(args.config)

    if args.command == "status":
        cmd_status(config)
    elif args.command == "refresh":
        cmd_refresh(config)
    elif args.command == "recover":
        cmd_recover(config)
    elif args.command == "check":
        cmd_check(config)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Commit**

```bash
git add oauth_manager.py
git commit -m "feat: add oauth_manager.py — unified CLI with layered recovery"
```

---

## Task 6: Adapt `headless_reauth.py` — Module API + Gemini support

**Files:**
- Modify: `headless_reauth.py`

- [ ] **Step 1: Add module-callable API at the top of headless_reauth.py**

After the existing imports and constants, add:

```python
def recover_server(server_name: str, config: dict, dry_run: bool = False) -> bool:
    """Module-callable entry point for headless recovery of a single server.
    Called by oauth_manager.py. Returns True on success."""
    global _config
    _config = config
    try:
        return _reauth_server(server_name, dry_run=dry_run)
    except Exception as e:
        log(f"[{server_name}] Recovery failed: {e}")
        return False


def recover_all(config: dict, dry_run: bool = False) -> bool:
    """Recover the local server. Called by oauth_manager.py.
    Uses the first server name from config, or 'local' as default."""
    global _config
    _config = config
    servers = config.get("servers", {})
    # For standalone/receiver, use "local" as the server name
    # and create a synthetic server entry from top-level config
    server_name = "local"
    if server_name not in get_servers():
        # Inject a temporary "local" server entry from top-level config
        _config.setdefault("servers", {})["local"] = {
            "hostname": "localhost",
            "provider": config.get("provider", "claude"),
            "email": config.get("email", ""),
            "password": config.get("password", ""),
        }
    try:
        return _reauth_server(server_name, dry_run=dry_run)
    except Exception as e:
        log(f"Recovery failed: {e}")
        return False
```

- [ ] **Step 2: Add `--config` flag to argparse in main()**

In the existing `if __name__ == "__main__"` block, add:

```python
parser.add_argument("--config", default=None, help="Path to config.json")
```

And pass it to `load_config()`.

- [ ] **Step 3: Add Gemini constants alongside Claude constants**

After the Claude constants block (around line 38-43 in the existing file, after `CLAUDE_SCOPES`).
Note: The existing file already defines `generate_pkce()`, `start_callback_server()`, `get_callback_port()`, and `build_claude_auth_url()` — the Gemini flow reuses these.

```python
# === Gemini OAuth Constants ===
GEMINI_TOKEN_URL = "https://oauth2.googleapis.com/token"
GEMINI_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/auth"
GEMINI_SCOPES = "https://www.googleapis.com/auth/cloud-platform openid email"
GEMINI_REDIRECT_URI = "http://localhost:{port}/callback"
```

- [ ] **Step 4: Add Gemini login flow function**

```python
def _reauth_gemini(page, server_name, config):
    """Gemini OAuth via Google Sign-In — reuses Google login automation from ChatGPT flow."""
    # Same Google Sign-In as ChatGPT, but with Gemini OAuth endpoints
    from token_refresh import _get_gemini_credentials
    client_id, client_secret = _get_gemini_credentials({"client_id": None, "client_secret": None})
    port = get_callback_port()
    verifier, challenge = generate_pkce()

    auth_url = (
        f"{GEMINI_AUTHORIZE_URL}?"
        f"client_id={client_id}&"
        f"redirect_uri={GEMINI_REDIRECT_URI.format(port=port)}&"
        f"response_type=code&"
        f"scope={urllib.parse.quote(GEMINI_SCOPES)}&"
        f"access_type=offline&"
        f"prompt=consent&"
        f"code_challenge={challenge}&"
        f"code_challenge_method=S256"
    )

    # Start callback server
    result, thread, server = start_callback_server(port)

    # Navigate to Google login
    page.goto(auth_url)
    # Enter email + password (same as ChatGPT Google Sign-In)
    email = config.get("email", "")
    password = config.get("password", "")
    _google_sign_in(page, server_name, email, password)

    # Wait for callback
    thread.join(timeout=120)
    if "code" not in result:
        raise RuntimeError("No auth code received from Gemini OAuth")

    # Exchange code for tokens
    payload = urllib.parse.urlencode({
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": result["code"],
        "redirect_uri": GEMINI_REDIRECT_URI.format(port=port),
        "code_verifier": verifier,
    }).encode()
    req = urllib.request.Request(
        GEMINI_TOKEN_URL, data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=15)
    tokens = json.loads(resp.read().decode())

    if "access_token" not in tokens:
        raise RuntimeError(f"Gemini token exchange failed: {json.dumps(tokens)[:300]}")

    return tokens
```

- [ ] **Step 5: Update the main reauth dispatcher to route by provider**

In the `_reauth_server` function (or equivalent), add provider routing:

```python
provider = server.get("provider", config.get("provider", "claude"))
if provider == "claude":
    tokens = _reauth_claude(page, server_name)
elif provider == "chatgpt":
    tokens = _reauth_chatgpt(page, server_name)
elif provider == "gemini":
    tokens = _reauth_gemini(page, server_name, config)
else:
    raise RuntimeError(f"Headless recovery not supported for {provider}")
```

- [ ] **Step 6: Commit**

```bash
git add headless_reauth.py
git commit -m "feat: add module API, --config flag, and Gemini login flow to headless_reauth"
```

---

## Task 7: `configure.py` — Interactive setup wizard

**Files:**
- Create: `configure.py`

- [ ] **Step 1: Create `configure.py` with full wizard flow**

```python
#!/usr/bin/env python3
"""
configure.py — Interactive setup wizard for OpenClaw OAuth Manager.

Usage:
  python3 configure.py                          # Full setup
  python3 configure.py --reconfigure provider   # Reconfigure one section
  python3 configure.py --reconfigure all        # Redo everything
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
VALID_SECTIONS = ["role", "provider", "credentials", "distribution", "servers",
                  "gmail", "slack", "schedule", "all"]


def ask_choice(prompt, options):
    """Ask user to pick from numbered options. Returns the value."""
    print(f"\n{prompt}")
    for i, (label, value) in enumerate(options, 1):
        print(f"  [{i}] {label}")
    while True:
        try:
            choice = int(input("\nChoice: ").strip())
            if 1 <= choice <= len(options):
                return options[choice - 1][1]
        except (ValueError, EOFError):
            pass
        print(f"Please enter a number 1-{len(options)}")


def ask_text(prompt, default=""):
    """Ask for text input with optional default."""
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def ask_yn(prompt, default=True):
    """Ask yes/no question."""
    suffix = " [Y/n]" if default else " [y/N]"
    value = input(f"{prompt}{suffix}: ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes")


# ── Environment Detection ──────────────────────────────────────────────

def detect_environment():
    """Auto-detect OS, Chrome, OpenClaw install, Python packages."""
    env = {"os": platform.system(), "chrome_path": None, "openclaw_installed": False,
           "installed_packages": []}

    # Chrome paths
    chrome_paths = {
        "Darwin": ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"],
        "Linux": ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
                  "/usr/bin/chromium-browser", "/snap/bin/chromium"],
    }
    for p in chrome_paths.get(env["os"], []):
        if os.path.exists(p):
            env["chrome_path"] = p
            break

    # OpenClaw install
    env["openclaw_installed"] = os.path.exists(os.path.expanduser("~/.openclaw"))

    # Installed packages
    for pkg in ["boto3", "playwright", "pytest"]:
        try:
            __import__(pkg)
            env["installed_packages"].append(pkg)
        except ImportError:
            pass

    return env


# ── Wizard Sections ────────────────────────────────────────────────────

def ask_role(config):
    role = ask_choice("How are you using this?", [
        ("Single server (standalone)", "standalone"),
        ("Multiple servers — this is the authority (refreshes + distributes)", "authority"),
        ("Multiple servers — this is a receiver (pulls from authority)", "receiver"),
    ])
    config["role"] = role
    return config


def ask_provider(config):
    provider = ask_choice("Which AI provider does this server use?", [
        ("Claude.ai (Anthropic)", "claude"),
        ("ChatGPT (OpenAI)", "chatgpt"),
        ("Gemini (Google)", "gemini"),
        ("Perplexity", "perplexity"),
    ])
    config["provider"] = provider
    if provider == "gemini":
        print("\n  Note: Gemini access tokens expire in ~60 minutes.")
        print("  Setting refresh_threshold_hours to 0.5 (30 min).")
        config["refresh_threshold_hours"] = 0.5
    return config


def ask_credentials(config):
    provider = config.get("provider", "claude")
    if provider == "perplexity":
        config["api_key"] = ask_text("Perplexity API key (pplx-...)")
        config["email"] = ""
        config["password"] = ""
    else:
        config["email"] = ask_text(f"Login email for {provider}")
        if provider in ("chatgpt", "gemini"):
            config["password"] = ask_text("Google account password (for Google Sign-In)")
        else:
            config["password"] = ""
            print("  Claude uses magic link login — no password needed.")
        config["api_key"] = ""
    return config


def ask_distribution(config):
    if config.get("role") not in ("authority", "receiver"):
        return config
    print("\n--- S3 Distribution ---")
    bucket = ask_text("S3 bucket for token sharing")
    config["s3"] = {
        "bucket": bucket,
        "key": ask_text("S3 key", default="oauth/tokens.json"),
        "region": ask_text("AWS region", default="us-east-2"),
    }
    return config


def ask_remote_servers(config):
    if config.get("role") != "authority":
        return config
    print("\n--- Remote Servers ---")
    print("Add servers to push tokens to.\n")
    servers = {}
    while True:
        name = ask_text("Server name (e.g., PROD, STAGING)")
        if not name:
            break
        srv = {
            "hostname": ask_text("SSH host (alias or IP)"),
            "ssh_user": ask_text("SSH user", default="ubuntu"),
            "ssh_key": ask_text("SSH key path", default="~/.ssh/id_ed25519"),
            "instance_id": ask_text("EC2 instance ID (optional, press Enter to skip)"),
            "provider": ask_text("Provider for this server", default=config.get("provider", "claude")),
            "email": ask_text("Login email for headless recovery on this server"),
            "password": "",
        }
        if srv["provider"] in ("chatgpt", "gemini"):
            srv["password"] = ask_text("Google password for this server")
        servers[name] = srv
        if not ask_yn("Add another server?", default=False):
            break
    config["servers"] = servers
    return config


def ask_headless(config, env):
    if config.get("provider") == "perplexity":
        config["headless_enabled"] = False
        return config
    enabled = ask_yn("Enable headless browser recovery as a fallback?")
    config["headless_enabled"] = enabled
    if not enabled:
        return config
    chrome = ask_text("Chrome path", default=env.get("chrome_path", ""))
    config["chrome_path"] = chrome
    if config.get("provider") == "claude":
        if ask_yn("Set up Gmail API for magic link login?"):
            print("\n  Run: python3 setup_gmail.py --client-id YOUR_ID --client-secret YOUR_SECRET --email YOUR_EMAIL")
            print("  Then add the credentials to config.json under 'gmail'.\n")
    return config


def ask_notifications(config):
    if not ask_yn("Send Slack alerts on failure?", default=False):
        config["slack"] = {"bot_token": "", "channel": ""}
        return config
    config["slack"] = {
        "bot_token": ask_text("Slack bot token (xoxb-...)"),
        "channel": ask_text("Slack channel or user ID"),
    }
    return config


def ask_schedule(config, env):
    if not ask_yn("Set up automatic health checks?"):
        return config
    interval = int(ask_text("Check interval in minutes", default="15"))
    config["check_interval_minutes"] = interval
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "oauth_manager.py"))

    if env["os"] == "Darwin":
        plist_name = "com.openclaw-oauth.check"
        plist_path = os.path.expanduser(f"~/Library/LaunchAgents/{plist_name}.plist")
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{plist_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{script_path}</string>
        <string>check</string>
    </array>
    <key>StartInterval</key><integer>{interval * 60}</integer>
    <key>StandardOutPath</key><string>/tmp/openclaw-oauth-stdout.log</string>
    <key>StandardErrorPath</key><string>/tmp/openclaw-oauth-stderr.log</string>
</dict>
</plist>"""
        print(f"\n  launchd plist:\n{plist}\n")
        if ask_yn(f"Install to {plist_path}?"):
            with open(plist_path, "w") as f:
                f.write(plist)
            subprocess.run(["launchctl", "load", plist_path], capture_output=True)
            print(f"  Installed and loaded: {plist_path}")
    else:
        cron_line = f"*/{interval} * * * * {sys.executable} {script_path} check >> /var/log/openclaw-oauth.log 2>&1"
        print(f"\n  Cron entry:\n  {cron_line}\n")
        if ask_yn("Add to crontab?"):
            existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
            if cron_line not in existing:
                new_crontab = existing.rstrip() + "\n" + cron_line + "\n"
                subprocess.run(["crontab", "-"], input=new_crontab, text=True, capture_output=True)
                print("  Added to crontab.")
    return config


def install_dependencies(config, env):
    if not ask_yn("Install required Python packages?"):
        return
    deps = ["pytest"]
    if config.get("s3", {}).get("bucket"):
        deps.append("boto3")
    if config.get("headless_enabled"):
        deps.append("playwright")
    missing = [d for d in deps if d not in env.get("installed_packages", [])]
    if not missing:
        print("  All dependencies already installed.")
        return
    print(f"  Installing: {', '.join(missing)}")
    subprocess.run([sys.executable, "-m", "pip", "install"] + missing)
    if "playwright" in missing:
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"])


def validate_config(config):
    print("\n--- Validation ---")
    ok = True
    # SSH
    for name, srv in config.get("servers", {}).items():
        hostname = srv.get("hostname")
        ssh_key = os.path.expanduser(srv.get("ssh_key", "~/.ssh/id_ed25519"))
        ssh_user = srv.get("ssh_user", "ubuntu")
        try:
            result = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "-o", "BatchMode=yes", "-i", ssh_key,
                 f"{ssh_user}@{hostname}", "echo ok"],
                capture_output=True, text=True, timeout=10,
            )
            status = "OK" if result.returncode == 0 else "FAIL"
        except Exception:
            status = "FAIL"
        print(f"  SSH {name} ({hostname}): {status}")
        if status == "FAIL":
            ok = False
    # S3
    bucket = config.get("s3", {}).get("bucket")
    if bucket:
        try:
            import boto3
            s3 = boto3.client("s3", region_name=config["s3"].get("region", "us-east-2"))
            s3.head_bucket(Bucket=bucket)
            print(f"  S3 {bucket}: OK")
        except Exception as e:
            print(f"  S3 {bucket}: FAIL ({e})")
            ok = False
    if ok:
        print("\n  All validations passed!")
    else:
        print("\n  Some validations failed. You can fix these later and re-run configure.py --reconfigure <section>")


def write_config(config, path=None):
    path = path or CONFIG_PATH
    # Set defaults for fields not covered by wizard
    config.setdefault("check_interval_minutes", 15)
    config.setdefault("refresh_threshold_hours", 4)
    config.setdefault("headless_recovery_cooldown_minutes", 30)
    config.setdefault("headless_enabled", True)
    config.setdefault("callback_port", 19876)
    config.setdefault("screenshot_dir", "~/.openclaw-oauth/screenshots")
    config.setdefault("browser_profile_dir", "~/.openclaw-oauth/browser-profiles")
    config.setdefault("servers", {})
    config.setdefault("s3", {"bucket": "", "key": "oauth/tokens.json", "region": "us-east-2"})
    config.setdefault("gmail", {"default": {"client_id": "", "client_secret": "",
                                            "refresh_token": "", "token_uri": "https://oauth2.googleapis.com/token",
                                            "email": ""}})
    config.setdefault("slack", {"bot_token": "", "channel": ""})

    with open(path, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(path, 0o600)
    print(f"\n  Config written to: {path}")
    print(f"  Run: python3 oauth_manager.py check")


# ── Main ───────────────────────────────────────────────────────────────

SECTION_MAP = {
    "role": ask_role,
    "provider": ask_provider,
    "credentials": ask_credentials,
    "distribution": ask_distribution,
    "servers": ask_remote_servers,
    "notifications": ask_notifications,
    "slack": ask_notifications,
}


def main():
    parser = argparse.ArgumentParser(description="OpenClaw OAuth Manager — Setup Wizard")
    parser.add_argument("--reconfigure", metavar="SECTION",
                        help=f"Reconfigure one section: {', '.join(VALID_SECTIONS)}")
    parser.add_argument("--output", default=None, help="Output path for config.json")
    args = parser.parse_args()

    env = detect_environment()

    if args.reconfigure:
        section = args.reconfigure
        if section not in VALID_SECTIONS:
            print(f"Unknown section: {section}. Valid: {', '.join(VALID_SECTIONS)}")
            sys.exit(1)
        # Load existing config
        if not os.path.exists(CONFIG_PATH):
            print("No existing config.json found. Run without --reconfigure first.")
            sys.exit(1)
        with open(CONFIG_PATH) as f:
            config = json.load(f)
        if section == "all":
            # Re-run everything
            pass
        elif section in SECTION_MAP:
            config = SECTION_MAP[section](config)
            write_config(config, args.output)
            return
        elif section == "gmail":
            print("Run: python3 setup_gmail.py --client-id YOUR_ID --client-secret YOUR_SECRET --email YOUR_EMAIL")
            print("Then update config.json gmail section manually.")
            return
        elif section == "schedule":
            config = ask_schedule(config, env)
            write_config(config, args.output)
            return

    # Full wizard
    print("=" * 50)
    print("  OpenClaw OAuth Manager — Setup")
    print("=" * 50)

    # Environment detection
    print(f"\n  OS: {env['os']}")
    print(f"  Chrome: {env['chrome_path'] or 'not found'}")
    print(f"  OpenClaw: {'installed' if env['openclaw_installed'] else 'not found'}")
    print(f"  Packages: {', '.join(env['installed_packages']) or 'none'}")

    config = {}
    config = ask_role(config)
    config = ask_provider(config)
    config = ask_credentials(config)
    config = ask_distribution(config)
    config = ask_remote_servers(config)
    config = ask_headless(config, env)
    config = ask_notifications(config)
    config = ask_schedule(config, env)
    install_dependencies(config, env)
    validate_config(config)
    write_config(config, args.output)


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Test wizard manually**

```bash
python3 configure.py
```

Walk through each step, verify config.json is written correctly.

- [ ] **Step 3: Commit**

```bash
git add configure.py
git commit -m "feat: add configure.py — interactive setup wizard with reconfigure support"
```

---

## Task 8: Update `config.example.json` and `README.md`

**Files:**
- Rewrite: `config.example.json`
- Rewrite: `README.md`

- [ ] **Step 1: Rewrite config.example.json**

```json
{
  "role": "standalone",
  "provider": "claude",
  "email": "",
  "password": "",
  "api_key": "",
  "check_interval_minutes": 15,
  "refresh_threshold_hours": 4,
  "_comment_refresh_threshold": "Set to 0.5 for Gemini (60-min token TTL)",
  "headless_recovery_cooldown_minutes": 30,
  "headless_enabled": true,
  "chrome_path": "",
  "callback_port": 19876,
  "screenshot_dir": "~/.openclaw-oauth/screenshots",
  "browser_profile_dir": "~/.openclaw-oauth/browser-profiles",
  "servers": {},
  "s3": {
    "bucket": "",
    "key": "oauth/tokens.json",
    "region": "us-east-2"
  },
  "gmail": {
    "default": {
      "client_id": "",
      "client_secret": "",
      "refresh_token": "",
      "token_uri": "https://oauth2.googleapis.com/token",
      "email": ""
    }
  },
  "slack": {
    "bot_token": "",
    "channel": ""
  }
}
```

- [ ] **Step 2: Rewrite README.md**

Cover:
- What it does (one paragraph)
- Supported providers table (Claude, ChatGPT, Gemini, Perplexity)
- Quick start (`python3 configure.py` → `python3 oauth_manager.py check`)
- Server roles (standalone, authority, receiver)
- Recovery layers diagram
- Commands reference
- Automated scheduling (cron/launchd)
- Gmail API setup
- Troubleshooting
- License

- [ ] **Step 3: Commit**

```bash
git add config.example.json README.md
git commit -m "docs: rewrite README and config template for unified OAuth manager"
```

---

## Task 9: Remove old shell scripts from working tree

**Files:**
- Remove: `pull-fresh-tokens-from-s3.sh` (if present)
- Remove: `token-authority-refresh.sh` (if present)
- Remove: `token-failure-watchdog.sh` (if present)
- Remove: `token_pull_logic.py` (if present — replaced by `token_logic.py`)

Note: these files exist in the archived `openclaw-oauth-protocol` repo. If they were copied into this repo during merging, remove them. If they were never copied, skip this task.

- [ ] **Step 1: Check which old files exist**

```bash
ls -la *.sh token_pull_logic.py 2>/dev/null
```

- [ ] **Step 2: Remove any that exist**

```bash
git rm pull-fresh-tokens-from-s3.sh token-authority-refresh.sh token-failure-watchdog.sh token_pull_logic.py 2>/dev/null || true
```

- [ ] **Step 3: Commit (only if files were removed)**

```bash
git add -A && git commit -m "chore: remove legacy shell scripts — replaced by Python modules"
```

---

## Task 10: End-to-end smoke test

**Files:** None (testing only)

- [ ] **Step 1: Run all unit tests**

```bash
python3 -m pytest test_token_logic.py test_token_refresh.py -v
```

Expected: all pass

- [ ] **Step 2: Test `status` command (should work without config)**

```bash
echo '{"provider":"claude","role":"standalone"}' > /tmp/test-config.json
python3 oauth_manager.py status --config /tmp/test-config.json
```

Expected: prints provider/status info (may show NO_TOKEN if no OpenClaw installed)

- [ ] **Step 3: Test `configure.py --help`**

```bash
python3 configure.py --help
```

Expected: shows usage info

- [ ] **Step 4: Test imports work**

```bash
python3 -c "from token_logic import token_health; from token_refresh import get_profile_key; from token_distribute import upload_to_s3; print('All imports OK')"
```

Expected: "All imports OK"

- [ ] **Step 5: Final commit if any fixes needed**

```bash
git add -A && git commit -m "fix: address smoke test issues"
```
