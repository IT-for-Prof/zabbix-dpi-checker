"""Tests for probe_tls_frag: split-ClientHello SNI bypass test."""

from __future__ import annotations

import socket
import ssl
import subprocess
import threading
from collections.abc import Iterator
from contextlib import suppress
from pathlib import Path

import pytest

from probe.lib import probe_tls_frag
from probe.lib.verdict import VerdictCode


def _make_cert(tmp_path: Path) -> tuple[Path, Path]:
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


def _tls_server_one_handshake(sock: socket.socket, ctx: ssl.SSLContext) -> None:
    try:
        raw, _ = sock.accept()
    except OSError:
        return
    with suppress(ssl.SSLError, OSError):
        tls = ctx.wrap_socket(raw, server_side=True)
        tls.recv(1024)
        tls.close()


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[tuple[ssl.SSLContext, socket.socket, int]]:
    cert, key = _make_cert(tmp_path)
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


def test_frag_against_real_tls_server_completes(
    tls_server: tuple[ssl.SSLContext, socket.socket, int],
) -> None:
    ctx, sock, port = tls_server
    t = threading.Thread(target=_tls_server_one_handshake, args=(sock, ctx), daemon=True)
    t.start()
    v = probe_tls_frag.probe(
        dns="127.0.0.1",
        port=port,
        sni="localhost",
        timeout=5.0,
        frag_size=4,
    )
    t.join(timeout=2.0)
    assert v.code in (VerdictCode.OK, VerdictCode.TLS_TIMEOUT, VerdictCode.CERT_MISMATCH), (
        f"unexpected {v.code}: {v.reason}"
    )


def test_frag_records_fragment_count_in_extra(
    tls_server: tuple[ssl.SSLContext, socket.socket, int],
) -> None:
    ctx, sock, port = tls_server
    t = threading.Thread(target=_tls_server_one_handshake, args=(sock, ctx), daemon=True)
    t.start()
    v = probe_tls_frag.probe(
        dns="127.0.0.1",
        port=port,
        sni="localhost",
        timeout=5.0,
        frag_size=4,
    )
    t.join(timeout=2.0)
    assert "fragments_sent" in v.extra
    assert v.extra["fragments_sent"] >= 2
