from __future__ import annotations

import contextlib
import socket
import ssl
import subprocess
import tempfile
import threading

import pytest

from probe.lib.probe_control import probe_control
from probe.lib.verdict import VerdictCode


def test_control_probe_against_local_listener_returns_ok() -> None:
    with tempfile.TemporaryDirectory() as d:
        subprocess.check_call(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                f"{d}/key.pem",
                "-out",
                f"{d}/cert.pem",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
            ],
            stderr=subprocess.DEVNULL,
        )
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(f"{d}/cert.pem", f"{d}/key.pem")

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def accept() -> None:
            conn, _ = server.accept()
            with contextlib.suppress(Exception):
                ctx.wrap_socket(conn, server_side=True).close()

        threading.Thread(target=accept, daemon=True).start()
        verdict = probe_control(host="127.0.0.1", port=port, timeout=2.0)
        server.close()

    assert verdict.code == VerdictCode.OK


def test_control_probe_against_dead_target_returns_non_ok() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    verdict = probe_control(host="127.0.0.1", port=port, timeout=1.0)
    assert verdict.code != VerdictCode.OK


def test_control_probe_emits_latency_ms() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    verdict = probe_control(host="127.0.0.1", port=port, timeout=0.5)
    assert verdict.latency_ms > 0.0


def test_control_probe_bad_hostname_returns_non_ok_verdict() -> None:
    verdict = probe_control(host="nonexistent.invalid", port=443, timeout=0.5)
    assert verdict.code != VerdictCode.OK


def test_control_probe_timeout_ssl_error_maps_to_tls_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    def accept_then_stall() -> None:
        conn, _ = sock.accept()
        try:
            conn.recv(4096)
        finally:
            conn.close()

    def fake_wrap_socket(
        self: ssl.SSLContext,
        raw_sock: socket.socket,
        **kwargs: object,
    ) -> ssl.SSLSocket:
        raise ssl.SSLError("The handshake operation timed out")

    threading.Thread(target=accept_then_stall, daemon=True).start()
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", fake_wrap_socket)
    verdict = probe_control(host="127.0.0.1", port=port, timeout=0.5)
    sock.close()

    assert verdict.code == VerdictCode.TLS_TIMEOUT
