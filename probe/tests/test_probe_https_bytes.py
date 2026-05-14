"""Tests for probe_https_bytes: post-handshake bytes-counter probe."""

from __future__ import annotations

import socket
import ssl
import struct
import subprocess
import threading
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path

import pytest

from probe.lib import probe_https_bytes
from probe.lib.resolver import DohCheckResult
from probe.lib.verdict import VerdictCode


def _make_self_signed_cert(tmp_path: Path) -> tuple[Path, Path]:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def _tls_echo_server(sock: socket.socket, ctx: ssl.SSLContext, rst_after_bytes: int | None) -> None:
    try:
        raw, _ = sock.accept()
    except OSError:
        return
    try:
        tls = ctx.wrap_socket(raw, server_side=True)
    except (ssl.SSLError, OSError):
        raw.close()
        return
    received = 0
    while True:
        try:
            chunk = tls.recv(4096)
        except (ssl.SSLError, OSError):
            break
        if not chunk:
            break
        received += len(chunk)
        if rst_after_bytes is not None and received >= rst_after_bytes:
            tls.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            tls.close()
            return
        try:
            tls.sendall(chunk)
        except (ssl.SSLError, OSError):
            break
    with suppress(OSError):
        tls.close()


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[tuple[ssl.SSLContext, socket.socket, int]]:
    cert, key = _make_self_signed_cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(1)
    try:
        yield ctx, sock, port
    finally:
        sock.close()


def test_bytes_counter_no_throttle_returns_ok(
    tls_server: tuple[ssl.SSLContext, socket.socket, int],
) -> None:
    ctx, sock, port = tls_server
    t = threading.Thread(target=_tls_echo_server, args=(sock, ctx, None), daemon=True)
    t.start()
    v = probe_https_bytes.probe(
        dns="127.0.0.1",
        port=port,
        sni="localhost",
        timeout=5.0,
        push_bytes=24_576,
        expect_rst_window=(14_000, 34_000),
    )
    t.join(timeout=2.0)
    assert v.code == VerdictCode.OK, f"got {v.code}: {v.reason}"


def test_bytes_counter_rst_in_window_returns_throttle(
    tls_server: tuple[ssl.SSLContext, socket.socket, int],
) -> None:
    ctx, sock, port = tls_server
    t = threading.Thread(target=_tls_echo_server, args=(sock, ctx, 18_000), daemon=True)
    t.start()
    v = probe_https_bytes.probe(
        dns="127.0.0.1",
        port=port,
        sni="localhost",
        timeout=5.0,
        push_bytes=40_960,
        expect_rst_window=(14_000, 34_000),
    )
    t.join(timeout=2.0)
    assert v.code == VerdictCode.THROTTLE_DETECTED, f"got {v.code}: {v.reason}"
    assert v.bytes_before_fail is not None
    assert 14_000 <= v.bytes_before_fail <= 34_000


def test_bytes_counter_rst_outside_window_returns_generic_rst(
    tls_server: tuple[ssl.SSLContext, socket.socket, int],
) -> None:
    ctx, sock, port = tls_server
    t = threading.Thread(target=_tls_echo_server, args=(sock, ctx, 100), daemon=True)
    t.start()
    v = probe_https_bytes.probe(
        dns="127.0.0.1",
        port=port,
        sni="localhost",
        timeout=5.0,
        push_bytes=40_960,
        expect_rst_window=(14_000, 34_000),
    )
    t.join(timeout=2.0)
    assert v.code == VerdictCode.TCP_RST_MID_STREAM, f"got {v.code}: {v.reason}"


def test_bytes_counter_ssl_error_in_window_is_not_throttle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeSocket:
        def settimeout(self, timeout: float) -> None:
            pass

        def connect(self, addr: tuple[str, int]) -> None:
            pass

        def close(self) -> None:
            pass

    class FakeTLS:
        def sendall(self, payload: bytes) -> None:
            pass

        def close(self) -> None:
            pass

    class FakeContext:
        check_hostname = False
        verify_mode = ssl.CERT_NONE

        def wrap_socket(
            self,
            raw: FakeSocket,
            *,
            server_hostname: str,
            do_handshake_on_connect: bool,
        ) -> FakeTLS:
            return FakeTLS()

    calls = 0

    def fake_send_and_probe(tls: FakeTLS, payload: bytes, cumulative: int) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return 16_000
        raise ssl.SSLError("clean tls shutdown")

    monkeypatch.setattr(
        probe_https_bytes,
        "resolve_with_doh_check",
        lambda dns, timeout: DohCheckResult("127.0.0.1", 0.0, frozenset(), False, None),
    )
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: FakeSocket())
    monkeypatch.setattr(ssl, "create_default_context", lambda: FakeContext())
    monkeypatch.setattr(probe_https_bytes, "_send_and_probe", fake_send_and_probe)

    v = probe_https_bytes.probe(
        dns="127.0.0.1",
        port=443,
        sni="localhost",
        timeout=5.0,
        push_bytes=40_960,
        expect_rst_window=(14_000, 34_000),
    )
    assert v.code == VerdictCode.TCP_RST_MID_STREAM
    assert "not a confirmed TCP RST" in v.reason
