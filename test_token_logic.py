"""Tests for token decision logic. Run with: python3 -m pytest test_token_logic.py -v"""
import time
import pytest
from token_logic import (
    token_health,
    should_self_refresh,
    should_update_from_s3,
    needs_profile_cleanup,
    should_headless_recover,
)

NOW = int(time.time() * 1000)
ONE_HOUR = 3600 * 1000
ONE_MIN = 60 * 1000


class TestTokenHealth:
    def test_returns_no_token_for_zero(self):
        assert token_health(0, NOW) == "NO_TOKEN"

    def test_returns_expired_when_past(self):
        assert token_health(NOW - ONE_HOUR, NOW) == "EXPIRED"

    def test_returns_critical_under_1h(self):
        assert token_health(NOW + 30 * ONE_MIN, NOW) == "CRITICAL"

    def test_returns_low_under_3h(self):
        assert token_health(NOW + 2 * ONE_HOUR, NOW) == "LOW"

    def test_returns_ok_above_3h(self):
        assert token_health(NOW + 5 * ONE_HOUR, NOW) == "OK"

    def test_returns_expired_at_exact_now(self):
        assert token_health(NOW, NOW) == "EXPIRED"


class TestShouldSelfRefresh:
    def test_false_when_local_valid(self):
        assert should_self_refresh(NOW + 2*ONE_HOUR, NOW - ONE_HOUR, 0, NOW, 30*ONE_MIN) is False

    def test_false_when_s3_valid(self):
        assert should_self_refresh(NOW - ONE_HOUR, NOW + 2*ONE_HOUR, 0, NOW, 30*ONE_MIN) is False

    def test_false_within_cooldown(self):
        assert should_self_refresh(NOW - ONE_HOUR, NOW - ONE_HOUR, NOW - 20*ONE_MIN, NOW, 30*ONE_MIN) is False

    def test_true_both_expired_no_prior_attempt(self):
        assert should_self_refresh(NOW - ONE_HOUR, NOW - ONE_HOUR, 0, NOW, 30*ONE_MIN) is True

    def test_true_both_expired_cooldown_passed(self):
        assert should_self_refresh(NOW - ONE_HOUR, NOW - ONE_HOUR, NOW - 31*ONE_MIN, NOW, 30*ONE_MIN) is True

    def test_none_last_attempt_treated_as_zero(self):
        assert should_self_refresh(NOW - ONE_HOUR, NOW - ONE_HOUR, None, NOW, 30*ONE_MIN) is True


class TestShouldUpdateFromS3:
    def test_updates_when_s3_fresher(self):
        assert should_update_from_s3(NOW + 3*ONE_HOUR, NOW + ONE_HOUR, NOW) is True

    def test_no_update_when_local_fresher(self):
        assert should_update_from_s3(NOW + ONE_HOUR, NOW + 3*ONE_HOUR, NOW) is False

    def test_no_update_when_s3_expired(self):
        assert should_update_from_s3(NOW - ONE_MIN, NOW - ONE_HOUR, NOW) is False

    def test_no_update_when_identical_expiry(self):
        t = NOW + 2 * ONE_HOUR
        assert should_update_from_s3(t, t, NOW) is False


class TestNeedsProfileCleanup:
    def test_clean_profile_returns_false(self):
        profile = {
            "profiles": {"openai-codex:codex-cli": {"access": "tok"}},
            "lastGood": {"openai-codex": "openai-codex:codex-cli"},
        }
        assert needs_profile_cleanup(profile, "openai-codex:codex-cli") is False

    def test_stale_api_key_returns_true(self):
        profile = {
            "profiles": {
                "openai-codex:codex-cli": {"access": "tok"},
                "openai-codex:api_key": {"key": "sk-xxx"},
            },
            "lastGood": {"openai-codex": "openai-codex:codex-cli"},
        }
        assert needs_profile_cleanup(profile, "openai-codex:codex-cli") is True

    def test_wrong_lastgood_returns_true(self):
        profile = {
            "profiles": {"openai-codex:codex-cli": {"access": "tok"}},
            "lastGood": {"openai-codex": "openai-codex:api_key"},
        }
        assert needs_profile_cleanup(profile, "openai-codex:codex-cli") is True

    def test_missing_lastgood_returns_true(self):
        profile = {"profiles": {"openai-codex:codex-cli": {"access": "tok"}}}
        assert needs_profile_cleanup(profile, "openai-codex:codex-cli") is True


class TestShouldHeadlessRecover:
    def test_allowed_when_no_prior_attempt(self):
        assert should_headless_recover(0, NOW, 30 * ONE_MIN) is True

    def test_blocked_within_cooldown(self):
        assert should_headless_recover(NOW - 10 * ONE_MIN, NOW, 30 * ONE_MIN) is False

    def test_allowed_after_cooldown(self):
        assert should_headless_recover(NOW - 31 * ONE_MIN, NOW, 30 * ONE_MIN) is True
