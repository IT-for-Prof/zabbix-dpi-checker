"""Tests for probe_quic: RFC-9000 Initial packet probe."""

from __future__ import annotations

import socket
import threading

from probe.lib import probe_quic
from probe.lib.verdict import VerdictCode


def _udp_echo(sock: socket.socket, response: bytes) -> None:
    sock.settimeout(2.0)
    try:
        _, addr = sock.recvfrom(2048)
        if response:
            sock.sendto(response, addr)
    except OSError:
        pass


def test_quic_no_reply_returns_port_filtered() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    v = probe_quic.probe(dns="127.0.0.1", port=port, sni="example.test", timeout=0.8)
    s.close()
    assert v.code == VerdictCode.PORT_FILTERED


def test_quic_long_header_response_is_ok() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    response = b"\xc0" + b"\x00\x00\x00\x01" + b"\x00" * 60
    t = threading.Thread(target=_udp_echo, args=(s, response), daemon=True)
    t.start()
    v = probe_quic.probe(dns="127.0.0.1", port=port, sni="example.test", timeout=2.0)
    t.join(timeout=2.0)
    s.close()
    assert v.code == VerdictCode.OK


def test_quic_short_header_response_is_banner_mismatch() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    response = b"\x40" + b"\x00" * 60
    t = threading.Thread(target=_udp_echo, args=(s, response), daemon=True)
    t.start()
    v = probe_quic.probe(dns="127.0.0.1", port=port, sni="example.test", timeout=2.0)
    t.join(timeout=2.0)
    s.close()
    assert v.code == VerdictCode.BANNER_MISMATCH
