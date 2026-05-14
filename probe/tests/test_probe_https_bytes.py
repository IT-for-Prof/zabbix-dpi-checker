"""Smoke test for redesigned probe_https_bytes."""
from __future__ import annotations

import contextlib
import socket
import ssl
import struct
import subprocess
import threading
from pathlib import Path

import pytest

from probe.lib import probe_https_bytes
from probe.lib.verdict import VerdictCode


def _make_cert(tmp_path: Path) -> tuple[Path, Path]:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(key), "-out", str(cert),
         "-days", "1", "-nodes", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return cert, key


def _tls_echo_server(sock, ctx, rst_after_bytes: int | None) -> None:
    """Echo received bytes back. Optionally force RST after N bytes received.

    Force-RST pattern: SO_LINGER 0 on the raw socket BEFORE TLS wrap, then
    hard-close. tls.close() closes the underlying raw socket; the SO_LINGER
    causes the kernel to send RST instead of FIN.
    """
    try:
        raw, _ = sock.accept()
    except OSError:
        return
    # Set linger BEFORE wrapping so it sticks on the underlying fd
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
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
            # Hard-close → kernel emits RST because of SO_LINGER 0
            with contextlib.suppress(ssl.SSLError, OSError):
                tls.close()
            return
        # Echo back so client's blocking interleave-read drains
        try:
            tls.sendall(chunk)
        except (ssl.SSLError, OSError):
            break
    with contextlib.suppress(OSError):
        tls.close()


@pytest.fixture
def tls_server(tmp_path):
    cert, key = _make_cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(1)
    return ctx, sock, port


def test_bytes_counter_no_throttle_returns_ok(tls_server) -> None:
    ctx, sock, port = tls_server
    t = threading.Thread(target=_tls_echo_server, args=(sock, ctx, None), daemon=True)
    t.start()
    v = probe_https_bytes.probe(
        dns="127.0.0.1", port=port, sni="localhost", timeout=5.0,
        push_bytes=65536, expect_rst_window=(14000, 34000),
    )
    sock.close()
    t.join(timeout=3.0)
    assert v.code == VerdictCode.OK, f"got {v.code}: {v.reason}"


def test_bytes_counter_rst_in_window_returns_throttle(tls_server) -> None:
    ctx, sock, port = tls_server
    t = threading.Thread(target=_tls_echo_server, args=(sock, ctx, 18000), daemon=True)
    t.start()
    v = probe_https_bytes.probe(
        dns="127.0.0.1", port=port, sni="localhost", timeout=5.0,
        push_bytes=65536, expect_rst_window=(14000, 34000),
        chunk_size=1024,
    )
    sock.close()
    t.join(timeout=3.0)
    assert v.code == VerdictCode.THROTTLE_DETECTED, f"got {v.code}: {v.reason}"
    assert v.bytes_before_fail is not None
    assert 14000 <= v.bytes_before_fail <= 34000, f"bytes_before_fail={v.bytes_before_fail}"


def test_bytes_counter_rst_outside_window_returns_generic_rst(tls_server) -> None:
    ctx, sock, port = tls_server
    t = threading.Thread(target=_tls_echo_server, args=(sock, ctx, 200), daemon=True)
    t.start()
    v = probe_https_bytes.probe(
        dns="127.0.0.1", port=port, sni="localhost", timeout=5.0,
        push_bytes=65536, expect_rst_window=(14000, 34000),
        chunk_size=1024,
    )
    sock.close()
    t.join(timeout=3.0)
    assert v.code == VerdictCode.TCP_RST_MID_STREAM, f"got {v.code}: {v.reason}"


def test_bytes_counter_clean_tls_close_is_not_throttle(tls_server) -> None:
    """Server cleanly closes TLS (close-notify) mid-stream → ssl.SSLZeroReturnError
    on the client → must classify as OK (no RST), NOT THROTTLE_DETECTED.
    Guards the _is_rst_error logic that says SSLZeroReturnError is a clean close.
    """
    ctx, sock, port = tls_server

    def _tls_clean_close_mid_stream(sock, ctx, close_after_bytes):
        """Echo until close_after_bytes received, then do a graceful TLS close-notify."""
        import ssl as _ssl
        try:
            raw, _ = sock.accept()
        except OSError:
            return
        # NOTE: no SO_LINGER here — we want a clean close, not a RST
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except (_ssl.SSLError, OSError):
            raw.close()
            return
        received = 0
        try:
            while True:
                try:
                    chunk = tls.recv(4096)
                except (_ssl.SSLError, OSError):
                    break
                if not chunk:
                    break
                received += len(chunk)
                # Echo chunk back
                try:
                    tls.sendall(chunk)
                except (_ssl.SSLError, OSError):
                    break
                if received >= close_after_bytes:
                    # We've echoed enough; gracefully close
                    break
        finally:
            # Clean close with close-notify
            with contextlib.suppress(_ssl.SSLError, OSError):
                tls.unwrap()
            with contextlib.suppress(OSError):
                tls.close()

    t = threading.Thread(
        target=_tls_clean_close_mid_stream, args=(sock, ctx, 18000), daemon=True,
    )
    t.start()
    v = probe_https_bytes.probe(
        dns="127.0.0.1", port=port, sni="localhost", timeout=5.0,
        push_bytes=65536, expect_rst_window=(14000, 34000),
        chunk_size=1024,
    )
    sock.close()
    t.join(timeout=3.0)
    # Clean close mid-stream must NOT be classified as THROTTLE_DETECTED.
    # OK or REMOTE_HUNGUP_AFTER_CONNECT are both acceptable (not a RST).
    assert v.code != VerdictCode.THROTTLE_DETECTED, (
        f"clean TLS close misclassified as throttle: {v.code}: {v.reason}"
    )
