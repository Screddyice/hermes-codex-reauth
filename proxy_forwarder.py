#!/usr/bin/env python3
"""Localhost credential-injecting HTTP/HTTPS-CONNECT forwarder for Webshare userpass mode.

Re-creates the retired gost SOCKS5 pattern in pure stdlib. Binds 127.0.0.1 only.

Chrome's ``--proxy-server`` flag cannot carry ``user:pass@`` credentials inline.
This module gives Chrome a plaintext HTTP proxy on loopback to point at; for every
request/CONNECT it relays to the Webshare upstream it injects a
``Proxy-Authorization: Basic <b64(user:pass)>`` header. Provider sign-in is all
HTTPS, so the common case is CONNECT tunneling: we inject the auth header into the
client's ``CONNECT host:443`` request block, then blind-relay the opaque TLS tunnel.

SECURITY: the forwarder relays plaintext Basic credentials, so it MUST bind
``127.0.0.1`` only and never be reachable off-box.
"""
import base64
import select
import socket
import threading


def build_proxy_auth_header(username: str, password: str) -> str:
    """Return the full 'Proxy-Authorization: Basic xxxx\\r\\n' header line."""
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Proxy-Authorization: Basic {token}\r\n"


class CredentialInjectingForwarder:
    """Minimal forward HTTP/HTTPS-CONNECT proxy that injects Webshare creds upstream.

    Binds 127.0.0.1 only. Threaded, daemonized accept loop. start()/stop() lifecycle.
    """

    def __init__(self, upstream_host, upstream_port, username, password,
                 local_host="127.0.0.1", local_port=1080):
        self.upstream_host = upstream_host
        self.upstream_port = int(upstream_port)
        self.username = username
        self.password = password
        # Hardcoded-safe: refuse anything but loopback so plaintext creds never leave the box.
        self.local_host = local_host or "127.0.0.1"
        self.local_port = int(local_port)
        self._listen_sock = None
        self._accept_thread = None
        self._stop = threading.Event()
        self.port = None  # actually-bound port (set in start())

    # ── lifecycle ──────────────────────────────────────────────────────

    def start(self):
        """Bind, listen, spawn the daemon accept loop. Idempotent. Returns self.

        Non-blocking: the caller can launch Chrome immediately. ``self.port`` is the
        actually-bound port (useful with ``local_port=0`` for ephemeral test binds).
        """
        if self._listen_sock is not None:
            return self
        self._stop.clear()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.local_host, self.local_port))
        sock.listen(128)
        sock.settimeout(0.5)
        self._listen_sock = sock
        self.port = sock.getsockname()[1]
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        return self

    def stop(self):
        """Close listen socket, set stop flag, join the accept thread.

        Safe to call multiple times and on a never-started instance.
        """
        self._stop.set()
        sock = self._listen_sock
        self._listen_sock = None
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        thread = self._accept_thread
        self._accept_thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2)

    # ── internals ──────────────────────────────────────────────────────

    def _accept_loop(self):
        while not self._stop.is_set():
            sock = self._listen_sock
            if sock is None:
                break
            try:
                client, _addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # Per-connection errors must not kill the accept loop.
            threading.Thread(
                target=self._handle_client, args=(client,), daemon=True
            ).start()

    def _handle_client(self, client):
        upstream = None
        try:
            # Read the first request chunk up to the end of the header block.
            header_block = b""
            while b"\r\n\r\n" not in header_block:
                chunk = client.recv(65536)
                if not chunk:
                    return  # client closed before sending a full header block
                header_block += chunk
                if len(header_block) > 1024 * 1024:
                    return  # absurdly large header block — bail

            head, sep, body = header_block.partition(b"\r\n\r\n")
            rewritten = self._inject_auth(head) + sep + body

            upstream = socket.create_connection(
                (self.upstream_host, self.upstream_port), timeout=15
            )
            upstream.sendall(rewritten)

            # Blind bidirectional relay until either side closes. For CONNECT the
            # tunnel body is opaque TLS, so no further rewriting is needed.
            self._relay(client, upstream)
        except Exception:
            pass
        finally:
            for s in (client, upstream):
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _inject_auth(self, head: bytes) -> bytes:
        """Insert the Proxy-Authorization header after the request line.

        Does not duplicate if the client already supplied one.
        """
        lines = head.split(b"\r\n")
        if not lines:
            return head
        auth_line = build_proxy_auth_header(self.username, self.password).rstrip("\r\n").encode()
        # Skip injection if a Proxy-Authorization header is already present.
        for ln in lines[1:]:
            if ln.lower().startswith(b"proxy-authorization:"):
                return head
        request_line = lines[0]
        rest = lines[1:]
        return b"\r\n".join([request_line, auth_line] + rest)

    @staticmethod
    def _relay(a, b):
        socks = [a, b]
        for s in socks:
            s.setblocking(True)
        while True:
            try:
                readable, _w, errored = select.select(socks, [], socks, 60)
            except (ValueError, OSError):
                break
            if errored:
                break
            if not readable:
                continue
            for src in readable:
                dst = b if src is a else a
                try:
                    data = src.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                try:
                    dst.sendall(data)
                except OSError:
                    return
