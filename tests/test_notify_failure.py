"""Tests for the last-resort escalator.

This is the thing that speaks when nothing else can, so the cases that matter are
the degraded ones: a corrupt config, a missing secret, a dead transport. It must
still send when it can, and it must fail loudly when it cannot. Silence here is
indistinguishable from health, which is the failure mode the whole repo exists to
remove.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
WATCHDOG = REPO / "watchdog"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, WATCHDOG / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


nf = _load("notify_failure")


class Args:
    def __init__(self, config, unit="u.service", lines=5, dry_run=False):
        self.config, self.unit = (str(config) if config else None), unit
        self.lines, self.dry_run = lines, dry_run


@pytest.fixture(autouse=True)
def no_journal(monkeypatch):
    monkeypatch.setattr(nf, "journal_tail", lambda unit, lines=15: "tail-line-one")


@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(nf, "send_telegram",
                        lambda tok, chat, text, thread="": calls.append(
                            {"token": tok, "chat": chat, "text": text, "thread": thread}))
    return calls


def write_cfg(tmp_path, **over) -> pathlib.Path:
    cfg = {"host_label": "hermes-tmn", "bot_label": "@Teamnebula_bot",
           "hermes_home": str(tmp_path / "home")}
    cfg.update(over)
    (tmp_path / "home").mkdir(exist_ok=True)
    p = tmp_path / "config.json"
    p.write_text(json.dumps(cfg))
    return p


def write_env(tmp_path, **vals):
    body = "\n".join(f"{k}={v}" for k, v in vals.items())
    (tmp_path / "home" / ".env").write_text(body + "\n")


# --------------------------------------------------------------------------
# it does not depend on the thing that failed
# --------------------------------------------------------------------------

def test_it_never_imports_the_health_check():
    """A last resort that imports the failed component is not a last resort."""
    src = (WATCHDOG / "notify_failure.py").read_text()
    assert "codex_health_check" not in src
    assert "claude_health_check" not in src


def test_corrupt_config_still_sends(tmp_path, sent, monkeypatch):
    """A broken config degrades the wording; it must not suppress the alert."""
    (tmp_path / "home").mkdir()
    bad = tmp_path / "config.json"
    bad.write_text("{not json")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")
    monkeypatch.setenv("TELEGRAM_HOME_CHANNEL", "123")

    assert nf.run(Args(bad, unit="hermes-codex-health.service")) == 0
    assert len(sent) == 1
    assert "hermes-codex-health.service" in sent[0]["text"]
    assert "unknown host" in sent[0]["text"]


def test_missing_config_file_still_sends(tmp_path, sent, monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")
    monkeypatch.setenv("TELEGRAM_HOME_CHANNEL", "123")
    assert nf.run(Args(tmp_path / "absent.json")) == 0
    assert len(sent) == 1


# --------------------------------------------------------------------------
# credential resolution
# --------------------------------------------------------------------------

def test_profile_env_wins_over_the_root_env(tmp_path, sent, monkeypatch):
    """hermes-tmn holds two bot tokens; the profile one must win.

    The root ~/.hermes/.env on that box carries a different bot. Resolving it
    would send the Team Nebula alert through the wrong bot, to the wrong chat.
    """
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_HOME_CHANNEL", raising=False)
    cfg = write_cfg(tmp_path)
    write_env(tmp_path, TELEGRAM_BOT_TOKEN="profile-token", TELEGRAM_HOME_CHANNEL="555")

    fake_home = tmp_path / "fakehome"
    (fake_home / ".hermes").mkdir(parents=True)
    (fake_home / ".hermes" / ".env").write_text(
        "TELEGRAM_BOT_TOKEN=root-token\nTELEGRAM_HOME_CHANNEL=999\n")
    monkeypatch.setattr(nf, "HOME", fake_home)

    assert nf.run(Args(cfg)) == 0
    assert sent[0]["token"] == "profile-token"
    assert sent[0]["chat"] == "555"


def test_quoted_env_values_are_unwrapped(tmp_path, sent, monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_HOME_CHANNEL", raising=False)
    cfg = write_cfg(tmp_path)
    write_env(tmp_path, TELEGRAM_BOT_TOKEN='"quoted-token"', TELEGRAM_HOME_CHANNEL="'42'")
    monkeypatch.setattr(nf, "HOME", tmp_path / "nowhere")

    assert nf.run(Args(cfg)) == 0
    assert sent[0]["token"] == "quoted-token"
    assert sent[0]["chat"] == "42"


def test_thread_id_is_forwarded_when_set(tmp_path, sent, monkeypatch):
    """Both boxes set TELEGRAM_HOME_CHANNEL_THREAD_ID; a forum topic needs it."""
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_HOME_CHANNEL", raising=False)
    monkeypatch.delenv("TELEGRAM_HOME_CHANNEL_THREAD_ID", raising=False)
    cfg = write_cfg(tmp_path)
    write_env(tmp_path, TELEGRAM_BOT_TOKEN="t", TELEGRAM_HOME_CHANNEL="1",
              TELEGRAM_HOME_CHANNEL_THREAD_ID="77")
    monkeypatch.setattr(nf, "HOME", tmp_path / "nowhere")

    assert nf.run(Args(cfg)) == 0
    assert sent[0]["thread"] == "77"


# --------------------------------------------------------------------------
# loud failure
# --------------------------------------------------------------------------

def test_missing_token_exits_nonzero(tmp_path, sent, monkeypatch, capsys):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_HOME_CHANNEL", raising=False)
    cfg = write_cfg(tmp_path)
    write_env(tmp_path, TELEGRAM_HOME_CHANNEL="1")      # chat present, token absent
    monkeypatch.setattr(nf, "HOME", tmp_path / "nowhere")

    assert nf.run(Args(cfg)) == 1
    assert sent == []
    assert "CANNOT ESCALATE" in capsys.readouterr().err


def test_transport_failure_exits_nonzero(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")
    monkeypatch.setenv("TELEGRAM_HOME_CHANNEL", "123")
    cfg = write_cfg(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("telegram error: chat not found")
    monkeypatch.setattr(nf, "send_telegram", boom)

    assert nf.run(Args(cfg)) == 1
    assert "CANNOT ESCALATE" in capsys.readouterr().err


def test_dry_run_reports_unusable_credentials_as_nonzero(tmp_path, monkeypatch):
    """install.sh gates on this: a notifier that could never fire must fail the install."""
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_HOME_CHANNEL", raising=False)
    cfg = write_cfg(tmp_path)
    monkeypatch.setattr(nf, "HOME", tmp_path / "nowhere")
    assert nf.run(Args(cfg, dry_run=True)) == 1

    write_env(tmp_path, TELEGRAM_BOT_TOKEN="t", TELEGRAM_HOME_CHANNEL="1")
    assert nf.run(Args(cfg, dry_run=True)) == 0


def test_dry_run_sends_nothing(tmp_path, sent, monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "tok")
    monkeypatch.setenv("TELEGRAM_HOME_CHANNEL", "123")
    assert nf.run(Args(write_cfg(tmp_path), dry_run=True)) == 0
    assert sent == []


# --------------------------------------------------------------------------
# message
# --------------------------------------------------------------------------

def test_message_names_the_unit_host_and_next_step(tmp_path):
    cfg = json.loads(write_cfg(tmp_path).read_text())
    text = nf.build_message(cfg, "hermes-codex-health-tmn.service", "boom")
    assert "hermes-tmn" in text and "@Teamnebula_bot" in text
    assert "hermes-codex-health-tmn.service" in text
    assert "systemctl --user status" in text
    assert "boom" in text


def test_message_stays_inside_telegram_limit(tmp_path):
    """Telegram rejects over 4096 chars, and a rejected alert is no alert."""
    cfg = json.loads(write_cfg(tmp_path).read_text())
    text = nf.build_message(cfg, "u.service", "x" * 20000)
    assert len(text) <= 4096
    assert text.rstrip().endswith("x")          # trimmed from the front, newest kept


# --------------------------------------------------------------------------
# wiring — the directive that was claimed for months and never existed
# --------------------------------------------------------------------------

def test_every_check_unit_wires_onfailure_to_its_notifier():
    """The docstring promised OnFailure= since before it existed. Assert it now."""
    pairs = {
        "hermes-codex-health.service": "hermes-codex-health-notify.service",
        "hermes-codex-health-tmn.service": "hermes-codex-health-tmn-notify.service",
        "nebos-claude-health.service": "nebos-claude-health-notify.service",
    }
    for unit, notify in pairs.items():
        body = (WATCHDOG / "systemd" / unit).read_text()
        assert f"OnFailure={notify}" in body, f"{unit} is not wired to {notify}"

        notify_body = (WATCHDOG / "systemd" / notify).read_text()
        assert "notify_failure.py" in notify_body
        assert f"--unit {unit}" in notify_body


def test_notifier_units_read_the_env_that_holds_the_bot_token():
    """tmn must load the profile .env first; without it the token never resolves."""
    tmn = (WATCHDOG / "systemd" / "hermes-codex-health-tmn-notify.service").read_text()
    assert tmn.index("profiles/tmn/.env") < tmn.index("%h/.hermes/.env")

    host = (WATCHDOG / "systemd" / "hermes-codex-health-notify.service").read_text()
    assert "%h/.hermes/.env" in host


def test_install_ships_the_notifier_and_asserts_the_wiring():
    """A silent install is how the previous gap survived. It must gate on both."""
    sh = (WATCHDOG / "install.sh").read_text()
    assert 'install -m 0755 "$HERE/notify_failure.py" "$DEST/notify_failure.py"' in sh
    assert 'install -m 0644 "$HERE/systemd/$NOTIFY"' in sh
    assert "-p OnFailure --value" in sh
    assert "notify_failure.py" in sh and "--dry-run" in sh


# --------------------------------------------------------------------------
# heartbeat server — the peer's only view of this box
# --------------------------------------------------------------------------

hb = _load("heartbeat_server")


def test_refuses_to_start_without_a_tailnet_address(monkeypatch, capsys):
    """Falling back to 0.0.0.0 would publish this on hostinger's public IP.

    A monitoring tool that quietly opens a public port is the kind of mistake
    this repo exists to prevent, so no-tailnet-address is fatal.
    """
    monkeypatch.setattr(hb, "tailnet_ip", lambda: "")
    monkeypatch.setattr(sys, "argv", ["heartbeat_server.py", "--file", "/tmp/x.json"])
    assert hb.main() == 1
    assert "REFUSING TO START" in capsys.readouterr().err


def test_units_bind_the_heartbeat_to_the_documented_port():
    for unit in ("hermes-codex-heartbeat.service", "hermes-codex-heartbeat-tmn.service"):
        body = (WATCHDOG / "systemd" / unit).read_text()
        assert "heartbeat_server.py" in body
        assert "--port 8299" in body
        assert "Restart=always" in body
        # no --bind override: the server must resolve the tailnet address itself
        assert "--bind" not in body


def test_install_ships_and_starts_the_heartbeat():
    sh = (WATCHDOG / "install.sh").read_text()
    assert 'install -m 0755 "$HERE/heartbeat_server.py"' in sh
    assert 'systemctl --user enable "$BEAT"' in sh
    assert "heartbeat server" in sh


def test_env_beside_the_script_is_used_when_there_is_no_hermes_home(tmp_path, sent, monkeypatch):
    """The observer host has no auth store and keeps its .env next to check.py.

    Without this the escalator looked only under ~/.hermes and ~/, which do not
    exist on that box, so it could never have fired. install.sh caught it.
    """
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_HOME_CHANNEL", raising=False)
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"host_label": "neb-ops-gcp", "mode": "observer"}))
    (tmp_path / ".env").write_text("TELEGRAM_BOT_TOKEN=obs-token\nTELEGRAM_HOME_CHANNEL=42\n")
    monkeypatch.setattr(nf, "HOME", tmp_path / "nowhere")

    assert nf.run(Args(cfg)) == 0
    assert sent[0]["token"] == "obs-token" and sent[0]["chat"] == "42"
