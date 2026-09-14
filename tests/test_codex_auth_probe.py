"""Exit-code contract for the operator probe.

The contract is the whole interface — a human reads the exit code during triage
and decides whether to spend 10 minutes on a 2FA re-login. Getting BROKEN and
UNKNOWN backwards wastes that time in one direction and hides an outage in the
other.
"""
from __future__ import annotations

import base64
import importlib.util
import io
import json
import pathlib
import sys
import time
import urllib.error

import pytest

HERE = pathlib.Path(__file__).resolve().parent
WATCHDOG = HERE.parent / "watchdog"


def _load(name: str):
    sys.path.insert(0, str(WATCHDOG))
    spec = importlib.util.spec_from_file_location(name, WATCHDOG / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


probe = _load("codex_auth_probe")


def write_auth(tmp_path, *, valid_jwt=True) -> pathlib.Path:
    if valid_jwt:
        claims = {"https://api.openai.com/auth": {"chatgpt_account_id": "acct"},
                  "exp": int(time.time()) + 3600}
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        at = f"h.{payload}.s"
    else:
        at = "not-a-jwt"
    p = tmp_path / "auth.json"
    p.write_text(json.dumps(
        {"providers": {"openai-codex": {"tokens": {"access_token": at, "refresh_token": "rt"}}}}))
    return p


def run_probe(monkeypatch, auth_path, *, raises=None, status=200):
    if raises is not None:
        monkeypatch.setattr(probe.urllib.request, "urlopen",
                            lambda *a, **k: (_ for _ in ()).throw(raises))
    else:
        class R:
            def __init__(self): self.status = status
            def __enter__(self): return self
            def __exit__(self, *a): return False
        monkeypatch.setattr(probe.urllib.request, "urlopen", lambda *a, **k: R())
    monkeypatch.setattr("sys.argv", ["probe", "--auth-json", str(auth_path)])
    return probe.main()


def http_error(code: str | int, body: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("u", int(code), "err", {}, io.BytesIO(body.encode()))


def test_success_is_zero(tmp_path, monkeypatch):
    assert run_probe(monkeypatch, write_auth(tmp_path)) == 0


def test_probe_uses_selected_pool_entry_instead_of_stale_singleton(tmp_path, monkeypatch):
    def jwt(account_id: str) -> str:
        claims = {
            "https://api.openai.com/auth": {"chatgpt_account_id": account_id},
            "exp": int(time.time()) + 3600,
        }
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        return f"h.{payload}.s"

    singleton = jwt("acct-singleton")
    backup = jwt("acct-backup")
    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps({
        "providers": {"openai-codex": {"tokens": {
            "access_token": singleton, "refresh_token": "dead-rt"
        }}},
        "credential_pool": {"openai-codex": [
            {"id": "backup", "label": "backup", "auth_type": "oauth",
             "source": "manual:oauth", "access_token": backup,
             "refresh_token": "backup-rt", "last_status": "ok", "priority": 1}
        ]}
    }))
    seen = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_open(req, timeout):
        seen["authorization"] = req.headers["Authorization"]
        seen["account"] = req.headers["Chatgpt-account-id"]
        return Response()

    monkeypatch.setattr(probe.urllib.request, "urlopen", fake_open)
    monkeypatch.setattr("sys.argv", ["probe", "--auth-json", str(auth)])
    assert probe.main() == 0
    assert seen == {"authorization": f"Bearer {backup}", "account": "acct-backup"}


def test_401_is_broken(tmp_path, monkeypatch):
    rc = run_probe(monkeypatch, write_auth(tmp_path),
                   raises=http_error(401, '{"error":"token_invalidated"}'))
    assert rc == 1


def test_401_with_novel_body_is_still_broken(tmp_path, monkeypatch):
    """The inverted bias.

    The previous probe required the body to match a substring allowlist, so a
    reworded OpenAI error became UNKNOWN and the outage went unreported. In a
    notify-only system a false page is cheap and a swallowed 401 is not.
    """
    rc = run_probe(monkeypatch, write_auth(tmp_path),
                   raises=http_error(401, '{"error":{"code":"something_new_2027"}}'))
    assert rc == 1


def test_403_is_broken(tmp_path, monkeypatch):
    assert run_probe(monkeypatch, write_auth(tmp_path),
                     raises=http_error(403, "{}")) == 1


def test_429_usage_limit_is_quota_not_broken_and_not_unknown(tmp_path, monkeypatch):
    """Quota exhaustion is not an auth failure and must be distinguishable.

    209 of these in 7 weeks were previously indistinguishable from health.
    """
    rc = run_probe(monkeypatch, write_auth(tmp_path),
                   raises=http_error(429, '{"error":{"type":"usage_limit_reached"}}'))
    assert rc == 3


def test_500_is_unknown(tmp_path, monkeypatch):
    assert run_probe(monkeypatch, write_auth(tmp_path),
                     raises=http_error(500, "server error")) == 2


def test_network_error_is_unknown(tmp_path, monkeypatch):
    assert run_probe(monkeypatch, write_auth(tmp_path),
                     raises=OSError("connection refused")) == 2


def test_missing_auth_file_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["probe", "--auth-json", str(tmp_path / "nope.json")])
    assert probe.main() == 2


def test_unparseable_token_is_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv",
                        ["probe", "--auth-json", str(write_auth(tmp_path, valid_jwt=False))])
    assert probe.main() == 2


def test_config_without_hermes_home_refuses_to_guess(tmp_path, monkeypatch):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"host_label": "x"}))
    monkeypatch.setattr("sys.argv", ["probe", "--config", str(cfg)])
    with pytest.raises(SystemExit):
        probe.main()


def test_config_resolves_auth_from_hermes_home(tmp_path, monkeypatch):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"hermes_home": str(tmp_path / "hh")}))

    class A:
        auth_json = None
        config = str(cfg)
    assert probe.resolve_auth(A()) == tmp_path / "hh" / "auth.json"
