from __future__ import annotations

import socket
import threading

from probe.lib import probe_wireguard
from probe.lib.verdict import VerdictCode


def _udp_echo_responder(sock: socket.socket, response_bytes: bytes) -> None:
    sock.settimeout(2.0)
    try:
        _data, addr = sock.recvfrom(2048)
        sock.sendto(response_bytes, addr)
    except OSError:
        pass


def test_wireguard_blind_without_pubkey_returns_udp_blind() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    v = probe_wireguard.probe(dns="127.0.0.1", port=port, pubkey_b64=None, timeout=1.0)
    s.close()
    assert v.code == VerdictCode.UDP_BLIND


def test_wireguard_with_pubkey_and_correct_response_is_ok() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    fake_response = b"\x02\x00\x00\x00" + b"\x00" * 88
    t = threading.Thread(target=_udp_echo_responder, args=(s, fake_response), daemon=True)
    t.start()
    pubkey = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQT0="  # base64 for 32 'A's
    v = probe_wireguard.probe(dns="127.0.0.1", port=port, pubkey_b64=pubkey, timeout=2.0)
    t.join(timeout=2.0)
    s.close()
    assert v.code == VerdictCode.OK


def test_wireguard_with_pubkey_no_response_is_port_filtered() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    pubkey = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQT0="
    v = probe_wireguard.probe(dns="127.0.0.1", port=port, pubkey_b64=pubkey, timeout=0.8)
    s.close()
    assert v.code == VerdictCode.PORT_FILTERED
