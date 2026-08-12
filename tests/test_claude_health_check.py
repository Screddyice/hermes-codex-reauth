"""Tests for the Claude OAuth watchdog.

Detection here is a single live HTTP call, so the thing worth pinning is how
each response class is judged. Getting that wrong is expensive in both
directions: page on a rate limit and the alert gets ignored, stay quiet on a
401 and NEBOS is down with nobody told.
"""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import time
import urllib.error

import pytest

HERE = pathlib.Path(__file__).resolve().parent
WATCHDOG = HERE.parent / "watchdog"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, WATCHDOG / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


chk = _load("claude_health_check")


def write_cfg(tmp_path, **overrides) -> pathlib.Path:
    cfg = {
        "label": "test-target",
        "secret_name": "SOME_SECRET",
        "gcp_project": "some-project",
        "probe_model": "claude-haiku-4-5-20251001",
        "subject": "s",
        "channels": {"email": {"to": ["x@y.z"], "key_env": "K", "composio_user_id": "u"}},
        "runbook": ["do the thing"], "context_note": ["because"],
    }
    cfg.update(overrides)
    p = tmp_path / "config.json"
    p.write_text(json.dumps(cfg))
    return p


def http_error(code: int, body: str = "{}") -> urllib.error.HTTPError:
    return urllib.error.HTTPError("u", code, "err", {}, io.BytesIO(body.encode()))


@pytest.fixture(autouse=True)
def token(monkeypatch):
    monkeypatch.setattr(chk, "read_token", lambda cfg: "sk-ant-oat01-TESTTOKEN")


def set_response(monkeypatch, *, status=200, raises=None):
    if raises is not None:
        monkeypatch.setattr(chk.urllib.request, "urlopen",
                            lambda *a, **k: (_ for _ in ()).throw(raises))
        return
    class R:
        def __init__(self): self.status = status
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(chk.urllib.request, "urlopen", lambda *a, **k: R())


# --- config ---------------------------------------------------------------

def test_missing_required_key_is_fatal(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"label": "x"}))
    with pytest.raises(chk.Disarmed):
        chk.load_config(p)


def test_no_channels_is_fatal(tmp_path):
    with pytest.raises(chk.Disarmed, match="no alert channels"):
        chk.load_config(write_cfg(tmp_path, channels={}))


def test_unreadable_config_is_fatal(tmp_path):
    with pytest.raises(chk.Disarmed, match="cannot read config"):
        chk.load_config(tmp_path / "nope.json")


def test_shipped_nebos_config_targets_the_right_secret():
    cfg = chk.load_config(WATCHDOG / "hosts" / "nebos-claude.json")
    assert cfg["gcp_project"] == "nebos-dev"
    assert cfg["secret_name"] == "CLAUDE_CODE_OAUTH_TOKEN"
    # the runbook must add a NEW version, never edit in place
    rb = "\n".join(cfg["runbook"])
    assert "versions add" in rb and "make deploy" in rb


# --- detection verdicts ---------------------------------------------------

def test_200_is_ok(tmp_path, monkeypatch):
    set_response(monkeypatch, status=200)
    status, detail = chk.detect(chk.load_config(write_cfg(tmp_path)))
    assert status == "ok" and "lineage=" in detail


def test_401_is_down(tmp_path, monkeypatch):
    set_response(monkeypatch, raises=http_error(401, '{"error":"unauthorized"}'))
    status, detail = chk.detect(chk.load_config(write_cfg(tmp_path)))
    assert status == "down" and "lineage=" in detail


def test_403_is_down(tmp_path, monkeypatch):
    set_response(monkeypatch, raises=http_error(403))
    assert chk.detect(chk.load_config(write_cfg(tmp_path)))[0] == "down"


def test_429_is_unknown_not_down(tmp_path, monkeypatch):
    """A rate limit says nothing about the credential. Paging on it trains you to ignore."""
    set_response(monkeypatch, raises=http_error(429, '{"type":"rate_limit_error"}'))
    status, detail = chk.detect(chk.load_config(write_cfg(tmp_path)))
    assert status == "unknown" and "not an auth verdict" in detail


def test_500_is_unknown(tmp_path, monkeypatch):
    set_response(monkeypatch, raises=http_error(500))
    assert chk.detect(chk.load_config(write_cfg(tmp_path)))[0] == "unknown"


def test_network_error_is_unknown(tmp_path, monkeypatch):
    set_response(monkeypatch, raises=OSError("connection refused"))
    assert chk.detect(chk.load_config(write_cfg(tmp_path)))[0] == "unknown"


def test_unreadable_secret_is_disarmed(tmp_path, monkeypatch):
    """Cannot read the credential == cannot do the job. Must be loud, never 'ok'."""
    def boom(cfg):
        raise chk.Disarmed("cannot read secret")
    monkeypatch.setattr(chk, "read_token", boom)
    with pytest.raises(chk.Disarmed):
        chk.detect(chk.load_config(write_cfg(tmp_path)))


def test_lineage_distinguishes_tokens():
    assert chk.lineage("a") != chk.lineage("b")
    assert chk.lineage("") == "none"


# --- edge-trigger through run() -------------------------------------------

class Args:
    def __init__(self, config, state_file, **kw):
        self.config, self.state_file = str(config), str(state_file)
        self.dry_run = kw.get("dry_run", False)
        self.force_down = kw.get("force_down", False)
        self.no_email = kw.get("no_email", False)
        self.no_slack = kw.get("no_slack", False)


@pytest.fixture
def sent(monkeypatch):
    out = []
    monkeypatch.setattr(chk, "env_val", lambda n: "key-present")
    monkeypatch.setattr(chk, "send_email", lambda ch, s, b, k: out.append(b))
    return out


def test_healthy_is_silent(tmp_path, monkeypatch, sent):
    set_response(monkeypatch, status=200)
    assert chk.run(Args(write_cfg(tmp_path), tmp_path / "s.json")) == 0
    assert sent == []


def test_first_failure_alerts_then_quiet(tmp_path, monkeypatch, sent):
    set_response(monkeypatch, raises=http_error(401))
    cfg, st = write_cfg(tmp_path), tmp_path / "s.json"
    assert chk.run(Args(cfg, st)) == 0
    assert len(sent) == 1
    chk.run(Args(cfg, st))
    assert len(sent) == 1          # inside quiet window


def test_recovery_is_silent_and_rearms(tmp_path, monkeypatch, sent):
    cfg, st = write_cfg(tmp_path), tmp_path / "s.json"
    set_response(monkeypatch, raises=http_error(401))
    chk.run(Args(cfg, st))
    assert len(sent) == 1

    set_response(monkeypatch, status=200)
    chk.run(Args(cfg, st))
    assert len(sent) == 1          # no "recovered" message
    assert json.loads(st.read_text())["status"] == "ok"

    set_response(monkeypatch, raises=http_error(401))
    chk.run(Args(cfg, st))
    assert len(sent) == 2          # re-armed


def test_unknown_never_writes_state(tmp_path, monkeypatch, sent):
    set_response(monkeypatch, raises=http_error(429))
    st = tmp_path / "s.json"
    assert chk.run(Args(write_cfg(tmp_path), st)) == 0
    assert not st.exists() and sent == []


def test_total_delivery_failure_exits_nonzero(tmp_path, monkeypatch, sent):
    set_response(monkeypatch, raises=http_error(401))
    monkeypatch.setattr(chk, "env_val", lambda n: "")     # secret rotated away
    assert chk.run(Args(write_cfg(tmp_path), tmp_path / "s.json")) == 1


def test_drill_cannot_write_production_state(tmp_path, monkeypatch, sent):
    set_response(monkeypatch, status=200)
    prod = tmp_path / "prod.json"
    prod.write_text(json.dumps({"status": "ok", "last_alert": 0}))
    chk.run(Args(write_cfg(tmp_path), tmp_path / "drill.json", force_down=True))
    assert json.loads(prod.read_text())["status"] == "ok"


def test_corrupt_state_is_disarmed(tmp_path):
    p = tmp_path / "s.json"
    p.write_text("{nope")
    with pytest.raises(chk.Disarmed, match="corrupt"):
        chk.load_state(p)
