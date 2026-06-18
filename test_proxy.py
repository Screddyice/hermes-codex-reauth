"""Tests for proxy support. Run with: python3 -m pytest test_proxy.py -v"""
import base64

import pytest  # noqa: F401  (kept for parity with the rest of the suite)

import headless_reauth
from proxy_forwarder import build_proxy_auth_header, CredentialInjectingForwarder


def _set_proxy(monkeypatch, **proxy):
    full = {"proxy": proxy}
    monkeypatch.setattr(headless_reauth, "_config", full, raising=False)
    monkeypatch.setattr(headless_reauth, "get_config", lambda *a, **k: full)


class TestGetProxyConfig:
    def test_defaults_when_absent(self, monkeypatch):
        monkeypatch.setattr(headless_reauth, "get_config", lambda *a, **k: {})
        p = headless_reauth.get_proxy_config()
        assert p["enabled"] is False
        assert p["mode"] == "ip_auth"
        assert p["endpoint"] == "p.webshare.io:80"
        assert p["host"] == "p.webshare.io" and p["port"] == 80
        assert p["local_forwarder_port"] == 1080

    def test_strips_http_scheme(self, monkeypatch):
        _set_proxy(monkeypatch, enabled=True, endpoint="http://p.webshare.io:80")
        p = headless_reauth.get_proxy_config()
        assert p["endpoint"] == "p.webshare.io:80"
        assert p["host"] == "p.webshare.io"

    def test_strips_https_scheme_and_trailing_slash(self, monkeypatch):
        _set_proxy(monkeypatch, enabled=True, endpoint="https://p.webshare.io:80/")
        p = headless_reauth.get_proxy_config()
        assert p["endpoint"] == "p.webshare.io:80"
        assert p["host"] == "p.webshare.io" and p["port"] == 80

    def test_userpass_fields_passthrough(self, monkeypatch):
        _set_proxy(monkeypatch, enabled=True, mode="userpass",
                   endpoint="gate.webshare.io:9999", username="u", password="p",
                   local_forwarder_port=2020)
        p = headless_reauth.get_proxy_config()
        assert p["enabled"] is True
        assert p["mode"] == "userpass"
        assert p["host"] == "gate.webshare.io" and p["port"] == 9999
        assert p["username"] == "u" and p["password"] == "p"
        assert p["local_forwarder_port"] == 2020


class TestProxyArgConstruction:
    """launch_chrome_cdp arg construction per mode + mandatory bypass list."""

    def _args(self, monkeypatch, **proxy):
        _set_proxy(monkeypatch, **proxy)
        captured = {}

        class FakeProc:
            def terminate(self):
                pass

        def fake_popen(args, **kw):
            captured["args"] = args
            return FakeProc()

        monkeypatch.setattr(headless_reauth.subprocess, "Popen", fake_popen)
        monkeypatch.setattr(headless_reauth, "get_chrome_path", lambda: "/bin/true")
        monkeypatch.setattr(headless_reauth, "get_browser_profile_dir", lambda s: "/tmp/x")
        monkeypatch.setattr(headless_reauth.time, "sleep", lambda *_: None)
        monkeypatch.setattr(headless_reauth.subprocess, "run", lambda *a, **k: None)
        headless_reauth.launch_chrome_cdp("TEST", headed=False)
        return captured["args"]

    def test_disabled_adds_no_proxy_args(self, monkeypatch):
        args = self._args(monkeypatch, enabled=False)
        assert not any(a.startswith("--proxy-server") for a in args)
        assert not any(a.startswith("--proxy-bypass-list") for a in args)

    def test_ip_auth_points_at_endpoint(self, monkeypatch):
        args = self._args(monkeypatch, enabled=True, mode="ip_auth", endpoint="p.webshare.io:80")
        assert "--proxy-server=http://p.webshare.io:80" in args

    def test_proxy_bypass_list_covers_loopback(self, monkeypatch):
        args = self._args(monkeypatch, enabled=True, mode="ip_auth", endpoint="p.webshare.io:80")
        bypass = next(a for a in args if a.startswith("--proxy-bypass-list="))
        for token in ("localhost", "127.0.0.1", "<-loopback>"):
            assert token in bypass

    def test_userpass_points_at_local_forwarder(self, monkeypatch):
        # forwarder.start() must be stubbed so no socket is bound
        import proxy_forwarder

        class FakeFwd:
            port = 1080

            def __init__(self, *a, **k):
                pass

            def start(self):
                return self

            def stop(self):
                pass

        monkeypatch.setattr(proxy_forwarder, "CredentialInjectingForwarder", FakeFwd)
        args = self._args(monkeypatch, enabled=True, mode="userpass",
                          endpoint="p.webshare.io:80", username="u", password="p",
                          local_forwarder_port=1080)
        assert "--proxy-server=http://127.0.0.1:1080" in args

    def test_returns_three_tuple(self, monkeypatch):
        """The signature change: (proc, cdp_port, forwarder)."""
        _set_proxy(monkeypatch, enabled=False)

        class FakeProc:
            def terminate(self):
                pass

        monkeypatch.setattr(headless_reauth.subprocess, "Popen", lambda *a, **k: FakeProc())
        monkeypatch.setattr(headless_reauth, "get_chrome_path", lambda: "/bin/true")
        monkeypatch.setattr(headless_reauth, "get_browser_profile_dir", lambda s: "/tmp/x")
        monkeypatch.setattr(headless_reauth.time, "sleep", lambda *_: None)
        monkeypatch.setattr(headless_reauth.subprocess, "run", lambda *a, **k: None)
        result = headless_reauth.launch_chrome_cdp("TEST", headed=False)
        assert len(result) == 3
        proc, cdp_port, forwarder = result
        assert forwarder is None  # disabled -> no forwarder


class TestForwarderCredentialInjection:
    def test_basic_auth_header_format(self):
        hdr = build_proxy_auth_header("user", "pass")
        expected = base64.b64encode(b"user:pass").decode()
        assert hdr == f"Proxy-Authorization: Basic {expected}\r\n"

    def test_binds_loopback_only(self):
        fwd = CredentialInjectingForwarder("p.webshare.io", 80, "u", "p",
                                           local_host="127.0.0.1", local_port=0)
        fwd.start()
        try:
            assert fwd.local_host == "127.0.0.1"
            assert fwd.port > 0          # ephemeral port actually bound
        finally:
            fwd.stop()

    def test_stop_is_idempotent(self):
        fwd = CredentialInjectingForwarder("p.webshare.io", 80, "u", "p", local_port=0)
        fwd.stop()      # never started
        fwd.start()
        fwd.stop()
        fwd.stop()      # double stop

    def test_start_is_idempotent(self):
        fwd = CredentialInjectingForwarder("p.webshare.io", 80, "u", "p", local_port=0)
        fwd.start()
        first_port = fwd.port
        fwd.start()      # second start is a no-op, same bound port
        try:
            assert fwd.port == first_port
        finally:
            fwd.stop()

    def test_inject_auth_after_request_line(self):
        fwd = CredentialInjectingForwarder("p.webshare.io", 80, "user", "pass", local_port=0)
        head = b"CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443"
        out = fwd._inject_auth(head)
        lines = out.split(b"\r\n")
        assert lines[0] == b"CONNECT chatgpt.com:443 HTTP/1.1"
        expected = base64.b64encode(b"user:pass").decode().encode()
        assert lines[1] == b"Proxy-Authorization: Basic " + expected
        assert b"Host: chatgpt.com:443" in out

    def test_inject_auth_not_duplicated(self):
        fwd = CredentialInjectingForwarder("p.webshare.io", 80, "user", "pass", local_port=0)
        existing = b"Proxy-Authorization: Basic preexisting"
        head = b"CONNECT chatgpt.com:443 HTTP/1.1\r\n" + existing
        out = fwd._inject_auth(head)
        assert out.count(b"Proxy-Authorization:") == 1
        assert out == head  # unchanged


class TestForwarderEndToEnd:
    """Drive a real client through the forwarder into a local fake 'upstream'.

    Fully offline (loopback only): a tiny stand-in upstream replaces Webshare.
    Verifies the forwarder injects Proxy-Authorization and blind-relays bytes.
    """

    def test_relays_and_injects_through_real_sockets(self):
        import socket
        import threading

        received = {}
        upstream_ready = threading.Event()

        # Fake upstream: accept one connection, read what the forwarder sent,
        # then echo a fixed reply back (stands in for the Webshare gateway).
        up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        up.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        up.bind(("127.0.0.1", 0))
        up.listen(1)
        up_port = up.getsockname()[1]

        def upstream_serve():
            upstream_ready.set()
            conn, _ = up.accept()
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            received["head"] = data
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            conn.close()

        t = threading.Thread(target=upstream_serve, daemon=True)
        t.start()
        upstream_ready.wait(2)

        fwd = CredentialInjectingForwarder("127.0.0.1", up_port, "user", "pass", local_port=0)
        fwd.start()
        try:
            client = socket.create_connection(("127.0.0.1", fwd.port), timeout=3)
            client.sendall(b"CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n")
            reply = client.recv(4096)
            client.close()
            t.join(timeout=2)
        finally:
            fwd.stop()
            up.close()

        # Upstream saw the injected auth header on the CONNECT.
        expected = base64.b64encode(b"user:pass").decode().encode()
        assert b"Proxy-Authorization: Basic " + expected in received["head"]
        assert received["head"].startswith(b"CONNECT chatgpt.com:443 HTTP/1.1")
        # Forwarder blind-relayed the upstream's reply back to the client.
        assert b"200 Connection established" in reply
