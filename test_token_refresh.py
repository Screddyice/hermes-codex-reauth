"""Tests for token_refresh.py. Run with: python3 -m pytest test_token_refresh.py -v"""
import json
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
