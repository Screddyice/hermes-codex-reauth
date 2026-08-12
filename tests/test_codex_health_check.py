"""Tests for the canonical codex watchdog.

The repo previously had zero coverage of the watchdog, which is uncomfortable for
code whose entire job is to be trustworthy when everything else is broken.

Two things matter most here and get the most attention:

  1. Which auth store each host resolves to. Unifying two scripts that disagreed
     on this default is the highest-consequence bug available: pointing the TMN
     box at its stale root auth.json yields a confident, wrong "ok".
  2. That every way the watchdog can stop working is LOUD. A monitor that fails
     silently is worse than no monitor, because it also removes the suspicion
     that you are unmonitored.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import pathlib
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
WATCHDOG = REPO / "watchdog"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, WATCHDOG / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


chk = _load("codex_health_check")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def jwt_with_exp(exp: int | None) -> str:
    """A syntactically valid JWT carrying just the claims detect() reads."""
    claims = {"https://api.openai.com/auth": {"chatgpt_account_id": "acct-test"}}
    if exp is not None:
        claims["exp"] = exp
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{payload}.sig"


def auth_doc(*, refresh="rt-aaa", exp_offset=+86400, last_error=None,
             last_refresh="2026-08-01T00:00:00Z", empty=False) -> dict:
    if empty:
        return {"providers": {}, "credential_pool": {}}
    exp = int(time.time()) + exp_offset if exp_offset is not None else None
    prov = {"tokens": {"access_token": jwt_with_exp(exp)}, "last_refresh": last_refresh}
    if refresh:
        prov["tokens"]["refresh_token"] = refresh
    if last_error:
        prov["last_auth_error"] = last_error
    return {"providers": {"openai-codex": prov}}


def write_host(tmp_path, name: str, hermes_home, **overrides) -> pathlib.Path:
    cfg = {
        "host_label": name,
        "bot_label": f"@{name}",
        "gateway_unit": f"hermes-gateway-{name}.service",
        "subject": "s", "ticket_title": "t",
        "channels": {"email": {"to": ["x@y.z"], "key_env": "K", "composio_user_id": "u"}},
        "runbook": ["do the thing"], "context_note": ["because"],
    }
    if hermes_home is not None:
        cfg["hermes_home"] = hermes_home
    cfg.update(overrides)
    p = tmp_path / f"{name}.json"
    p.write_text(json.dumps(cfg))
    return p


@pytest.fixture(autouse=True)
def gateway_up(monkeypatch):
    """Default the gateway to running so auth assertions stay isolated."""
    monkeypatch.setattr(chk, "gateway_active", lambda unit: (True, "active"))


# --------------------------------------------------------------------------
# config — the no-default rule
# --------------------------------------------------------------------------

def test_missing_hermes_home_is_fatal_not_defaulted(tmp_path):
    """The whole point. A missing auth store must stop the run, never be guessed.

    The two scripts this replaces disagreed (~/.hermes vs ~/.hermes/profiles/tmn).
    Any shared default silently points one host at the wrong credential.
    """
    cfg = write_host(tmp_path, "nohome", hermes_home=None)
    with pytest.raises(chk.Disarmed, match="hermes_home"):
        chk.load_config(cfg)


def test_unreadable_config_is_fatal(tmp_path):
    with pytest.raises(chk.Disarmed, match="cannot read config"):
        chk.load_config(tmp_path / "does-not-exist.json")


def test_config_with_no_channels_is_fatal(tmp_path):
    cfg = write_host(tmp_path, "nochan", "~/.hermes", channels={})
    with pytest.raises(chk.Disarmed, match="no alert channels"):
        chk.load_config(cfg)


def test_shipped_host_configs_resolve_to_the_right_auth_store():
    """Regression guard for the exact defect fixed on 2026-07-29.

    TMN's gateway runs with HERMES_HOME=~/.hermes/profiles/tmn. Its root
    ~/.hermes/auth.json is stale and unused; watching it reports a healthy
    credential that nothing runs on.
    """
    tmn = chk.load_config(WATCHDOG / "hosts" / "tmn.json")
    assert tmn["hermes_home"] == "~/.hermes/profiles/tmn"
    assert not tmn["hermes_home"].rstrip("/").endswith(".hermes")

    host = chk.load_config(WATCHDOG / "hosts" / "hostinger.json")
    assert host["hermes_home"] == "~/.hermes"

    assert tmn["hermes_home"] != host["hermes_home"]
    assert tmn["gateway_unit"] != host["gateway_unit"]


def test_shipped_configs_carry_their_own_runbook_only():
    """Each host's runbook must not tell an operator to log into the other box."""
    tmn = chk.load_config(WATCHDOG / "hosts" / "tmn.json")
    host = chk.load_config(WATCHDOG / "hosts" / "hostinger.json")
    tmn_rb, host_rb = "\n".join(tmn["runbook"]), "\n".join(host["runbook"])

    assert "--profile tmn" in tmn_rb and "hermes-gateway-tmn.service" in tmn_rb
    assert "ssh hostinger" not in tmn_rb

    assert "ssh hostinger" in host_rb
    assert "--profile tmn" not in host_rb and "tunnel-through-iap" not in host_rb


# --------------------------------------------------------------------------
# detect()
# --------------------------------------------------------------------------

def test_healthy_credential(tmp_path):
    (tmp_path / "auth.json").write_text(json.dumps(auth_doc()))
    status, detail = chk.detect(tmp_path / "auth.json", "u.service")
    assert status == "ok"
    assert "lineage=" in detail


def test_no_refresh_token_is_down(tmp_path):
    (tmp_path / "auth.json").write_text(json.dumps(auth_doc(refresh=None)))
    status, detail = chk.detect(tmp_path / "auth.json", "u.service")
    assert status == "down" and "NO refresh token" in detail


def test_expired_access_token_is_down(tmp_path):
    (tmp_path / "auth.json").write_text(json.dumps(auth_doc(exp_offset=-3600)))
    status, detail = chk.detect(tmp_path / "auth.json", "u.service")
    assert status == "down" and "expired" in detail


def test_no_credential_at_all_is_down(tmp_path):
    (tmp_path / "auth.json").write_text(json.dumps(auth_doc(empty=True)))
    status, _ = chk.detect(tmp_path / "auth.json", "u.service")
    assert status == "down"


def test_relogin_required_newer_than_last_refresh_is_down(tmp_path):
    err = {"code": "relogin_required", "relogin_required": True,
           "at": "2026-08-09T00:00:00Z"}
    (tmp_path / "auth.json").write_text(json.dumps(
        auth_doc(last_error=err, last_refresh="2026-08-01T00:00:00Z")))
    status, detail = chk.detect(tmp_path / "auth.json", "u.service")
    assert status == "down" and "relogin_required=True" in detail


def test_stale_auth_error_older_than_last_refresh_is_ignored(tmp_path):
    """A repaired outage leaves its error record behind; it must not page forever."""
    err = {"code": "refresh_token_reused", "relogin_required": True,
           "at": "2026-07-01T00:00:00Z"}
    (tmp_path / "auth.json").write_text(json.dumps(
        auth_doc(last_error=err, last_refresh="2026-08-01T00:00:00Z")))
    status, _ = chk.detect(tmp_path / "auth.json", "u.service")
    assert status == "ok"


def test_unreadable_auth_is_disarmed_not_silently_ok(tmp_path):
    with pytest.raises(chk.Disarmed):
        chk.detect(tmp_path / "missing.json", "u.service")


def test_malformed_auth_json_is_disarmed(tmp_path):
    (tmp_path / "auth.json").write_text("{not json")
    with pytest.raises(chk.Disarmed):
        chk.detect(tmp_path / "auth.json", "u.service")


def test_dead_gateway_is_down_even_with_valid_credential(tmp_path, monkeypatch):
    """Codex auth can be perfect while the bot is dead. Nothing used to notice."""
    monkeypatch.setattr(chk, "gateway_active", lambda unit: (False, "failed"))
    (tmp_path / "auth.json").write_text(json.dumps(auth_doc()))
    status, detail = chk.detect(tmp_path / "auth.json", "hermes-gateway.service")
    assert status == "down"
    assert "hermes-gateway.service is failed" in detail


def test_lineage_is_stable_and_distinguishes_credentials():
    assert chk.lineage("rt-aaa") == chk.lineage("rt-aaa")
    assert chk.lineage("rt-aaa") != chk.lineage("rt-bbb")
    assert chk.lineage("") == "none"


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

def test_corrupt_state_is_disarmed_not_reset_to_ok(tmp_path):
    """Resetting to ok would turn a live outage into a fabricated recovery."""
    p = tmp_path / "state.json"
    p.write_text("{corrupt")
    with pytest.raises(chk.Disarmed, match="corrupt"):
        chk.load_state(p)


def test_absent_state_starts_clean(tmp_path):
    assert chk.load_state(tmp_path / "none.json")["status"] == "ok"


# --------------------------------------------------------------------------
# edge-trigger state machine, end to end through run()
# --------------------------------------------------------------------------

class Args:
    def __init__(self, config, state_file, **kw):
        self.config, self.state_file = str(config), str(state_file)
        self.dry_run = kw.get("dry_run", False)
        self.force_down = kw.get("force_down", False)
        self.no_email = kw.get("no_email", False)
        self.no_slack = kw.get("no_slack", False)
        self.no_linear = kw.get("no_linear", False)


@pytest.fixture
def host(tmp_path, monkeypatch):
    """A configured host whose gateway is on codex and whose email always sends."""
    home = tmp_path / "hermes"
    home.mkdir()
    (home / "config.yaml").write_text("model:\n  provider: openai-codex\n")
    (home / "auth.json").write_text(json.dumps(auth_doc()))
    cfg = write_host(tmp_path, "h1", str(home))
    monkeypatch.setattr(chk, "env_val", lambda name, hh: "key-present")
    sent = []
    monkeypatch.setattr(chk, "send_email", lambda ch, s, b, k: sent.append(b))
    return {"cfg": cfg, "home": home, "state": tmp_path / "state.json", "sent": sent}


def test_healthy_is_silent(host):
    rc = chk.run(Args(host["cfg"], host["state"]))
    assert rc == 0 and host["sent"] == []


def test_first_failure_alerts_once_then_goes_quiet(host):
    (host["home"] / "auth.json").write_text(json.dumps(auth_doc(refresh=None)))

    assert chk.run(Args(host["cfg"], host["state"])) == 0
    assert len(host["sent"]) == 1                     # ok -> down

    assert chk.run(Args(host["cfg"], host["state"])) == 0
    assert len(host["sent"]) == 1                     # down -> down, quiet window


def test_reminder_fires_after_renotify_window(host):
    (host["home"] / "auth.json").write_text(json.dumps(auth_doc(refresh=None)))
    chk.run(Args(host["cfg"], host["state"]))
    assert len(host["sent"]) == 1

    st = json.loads(host["state"].read_text())
    st["last_alert"] = int(time.time()) - (24 * 3600 + 60)
    host["state"].write_text(json.dumps(st))

    chk.run(Args(host["cfg"], host["state"]))
    assert len(host["sent"]) == 2


def test_recovery_is_silent_and_rearms(host):
    (host["home"] / "auth.json").write_text(json.dumps(auth_doc(refresh=None)))
    chk.run(Args(host["cfg"], host["state"]))
    assert len(host["sent"]) == 1

    (host["home"] / "auth.json").write_text(json.dumps(auth_doc()))
    chk.run(Args(host["cfg"], host["state"]))
    assert len(host["sent"]) == 1                     # no "recovered" message
    assert json.loads(host["state"].read_text())["status"] == "ok"

    (host["home"] / "auth.json").write_text(json.dumps(auth_doc(refresh=None)))
    chk.run(Args(host["cfg"], host["state"]))
    assert len(host["sent"]) == 2                     # re-armed: alerts again


def test_alert_with_every_channel_failing_exits_nonzero(host, monkeypatch):
    """The most dangerous failure mode: an outage nobody was told about.

    The version this replaces printed the delivery error and still exited 0, so
    systemd stayed green while the page went nowhere.
    """
    (host["home"] / "auth.json").write_text(json.dumps(auth_doc(refresh=None)))
    monkeypatch.setattr(chk, "env_val", lambda name, hh: "")   # secret rotated away
    assert chk.run(Args(host["cfg"], host["state"])) == 1




def test_dry_run_never_writes_state(host):
    before = host["state"].exists()
    chk.run(Args(host["cfg"], host["state"], dry_run=True, force_down=True))
    assert host["state"].exists() == before
    assert host["sent"] == []


def test_force_down_respects_state_file_override(host, tmp_path):
    """Drills must not be able to write production state.

    Without this, a --force-down drill leaves the host inside a 24h quiet window
    and a genuine outage in that window pages nobody.
    """
    prod = tmp_path / "prod-state.json"
    prod.write_text(json.dumps({"status": "ok", "last_alert": 0, "ticket_url": None}))
    drill = tmp_path / "drill.json"

    chk.run(Args(host["cfg"], drill, force_down=True))

    assert json.loads(prod.read_text())["status"] == "ok"
    assert json.loads(drill.read_text())["status"] == "down"


# --------------------------------------------------------------------------
# applicability guard
# --------------------------------------------------------------------------

def test_non_codex_gateway_is_quiet_but_unreadable_config_is_loud(tmp_path):
    """"Not applicable" and "cannot tell" must not look the same.

    Collapsing them meant a YAML typo silently disarmed the watchdog.
    """
    yaml = tmp_path / "config.yaml"
    yaml.write_text("model:\n  provider: anthropic\n")
    assert chk.gateway_uses_codex(yaml) is False

    with pytest.raises(chk.Disarmed):
        chk.gateway_uses_codex(tmp_path / "absent.yaml")
