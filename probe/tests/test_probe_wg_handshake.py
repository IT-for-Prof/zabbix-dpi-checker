from __future__ import annotations

import base64
import socket
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from probe.lib import probe_wg_handshake
from probe.lib.verdict import VerdictCode


def _raw_pub(p: X25519PrivateKey) -> bytes:
    return p.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _raw_priv(p: X25519PrivateKey) -> bytes:
    return p.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())


def _fake_wg_server(sock: socket.socket, response_first_byte: int = 0x02) -> None:
    sock.settimeout(3.0)
    try:
        data, addr = sock.recvfrom(2048)
        if len(data) == 148 and data[0] == 0x01:
            reply = bytes([response_first_byte, 0, 0, 0]) + b"\x00" * 88
            sock.sendto(reply, addr)
    except (TimeoutError, OSError):
        pass


def test_handshake_pass_when_server_returns_type02() -> None:
    server_priv = X25519PrivateKey.generate()
    client_priv = X25519PrivateKey.generate()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    t = threading.Thread(target=_fake_wg_server, args=(s, 0x02), daemon=True)
    t.start()
    v = probe_wg_handshake.probe(
        dns="127.0.0.1", port=port, timeout=2.0,
        server_pub_b64=base64.b64encode(_raw_pub(server_priv)).decode(),
        client_priv_b64=base64.b64encode(_raw_priv(client_priv)).decode(),
        client_pub_b64=base64.b64encode(_raw_pub(client_priv)).decode(),
    )
    t.join(timeout=3.0)
    s.close()
    assert v.code == VerdictCode.WG_HANDSHAKE_PASS, f"got {v.code}: {v.reason}"


def test_handshake_blocked_on_silence() -> None:
    server_priv = X25519PrivateKey.generate()
    client_priv = X25519PrivateKey.generate()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    v = probe_wg_handshake.probe(
        dns="127.0.0.1", port=port, timeout=0.5,
        server_pub_b64=base64.b64encode(_raw_pub(server_priv)).decode(),
        client_priv_b64=base64.b64encode(_raw_priv(client_priv)).decode(),
        client_pub_b64=base64.b64encode(_raw_pub(client_priv)).decode(),
    )
    s.close()
    assert v.code == VerdictCode.WG_HANDSHAKE_BLOCKED, f"got {v.code}: {v.reason}"


def test_handshake_banner_mismatch_on_wrong_first_byte() -> None:
    server_priv = X25519PrivateKey.generate()
    client_priv = X25519PrivateKey.generate()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    t = threading.Thread(target=_fake_wg_server, args=(s, 0x03), daemon=True)
    t.start()
    v = probe_wg_handshake.probe(
        dns="127.0.0.1", port=port, timeout=2.0,
        server_pub_b64=base64.b64encode(_raw_pub(server_priv)).decode(),
        client_priv_b64=base64.b64encode(_raw_priv(client_priv)).decode(),
        client_pub_b64=base64.b64encode(_raw_pub(client_priv)).decode(),
    )
    t.join(timeout=3.0)
    s.close()
    assert v.code == VerdictCode.BANNER_MISMATCH, f"got {v.code}: {v.reason}"


def test_handshake_bad_base64_key_returns_internal_error() -> None:
    v = probe_wg_handshake.probe(
        dns="127.0.0.1", port=51820, timeout=1.0,
        server_pub_b64="not-base64!!!",
        client_priv_b64="AAAA",
        client_pub_b64="AAAA",
    )
    assert v.code == VerdictCode.ERROR_INTERNAL
    assert "base64" in v.reason.lower() or "32" in v.reason
