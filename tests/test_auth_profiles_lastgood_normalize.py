"""Regression test for lastGood string-vs-dict normalization in write_tokens.

Background: when bringing up a fresh server and hand-seeding ~/.openclaw/auth-profiles.json
from the oauth-token-cache.json shape, an older convention sometimes used a bare
string (`"lastGood": "openai-codex:codex-cli"`) instead of the canonical dict
(`"lastGood": {"openai-codex": "openai-codex:codex-cli"}`).

Before this fix, the first headless reauth would crash at the write step with
`TypeError: 'str' object does not support item assignment`, AFTER successfully
running through the full Chrome+Xvfb+Gmail flow — burning a real OAuth + email
for nothing. write_tokens now coerces a string lastGood to a fresh dict.
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from auth_profiles import write_tokens


class _FakeTokens:
    """Minimal stand-in for CodexTokens — only to_hermes_profile() is called."""

    def to_hermes_profile(self) -> dict:
        return {
            "type": "oauth",
            "provider": "openai-codex",
            "mode": "oauth",
            "access": "fake-access",
            "refresh": "fake-refresh",
            "expires": 1779000000000,
        }


def _seed(tmpdir: str, lastGood) -> str:
    p = os.path.join(tmpdir, "auth-profiles.json")
    with open(p, "w") as f:
        json.dump({"version": 1, "profiles": {}, "lastGood": lastGood}, f)
    return p


def test_dict_lastGood_round_trips():
    with tempfile.TemporaryDirectory() as d:
        p = _seed(d, {"openai-codex": "openai-codex:codex-cli"})
        assert write_tokens([p], _FakeTokens()) == 1
        out = json.load(open(p))
        assert out["lastGood"]["openai-codex"] == "openai-codex:codex-cli"
        assert out["profiles"]["openai-codex:codex-cli"]["access"] == "fake-access"


def test_string_lastGood_normalized_to_dict():
    with tempfile.TemporaryDirectory() as d:
        # The exact malformed shape we hit on first TRC bring-up.
        p = _seed(d, "openai-codex:codex-cli")
        assert write_tokens([p], _FakeTokens()) == 1
        out = json.load(open(p))
        # No more TypeError, and lastGood is now correctly shaped.
        assert isinstance(out["lastGood"], dict)
        assert out["lastGood"]["openai-codex"] == "openai-codex:codex-cli"


def test_missing_lastGood_creates_dict():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "auth-profiles.json")
        with open(p, "w") as f:
            json.dump({"version": 1, "profiles": {}}, f)
        assert write_tokens([p], _FakeTokens()) == 1
        out = json.load(open(p))
        assert out["lastGood"] == {"openai-codex": "openai-codex:codex-cli"}


def test_none_lastGood_normalized():
    with tempfile.TemporaryDirectory() as d:
        p = _seed(d, None)
        assert write_tokens([p], _FakeTokens()) == 1
        out = json.load(open(p))
        assert isinstance(out["lastGood"], dict)
        assert out["lastGood"]["openai-codex"] == "openai-codex:codex-cli"
