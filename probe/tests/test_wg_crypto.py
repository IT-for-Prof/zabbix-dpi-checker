"""Smoke test for wg_crypto extracted from plan."""
from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from probe.lib import wg_crypto


def _raw_pub(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )


def _raw_priv(priv: X25519PrivateKey) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def test_handshake_init_total_length_is_148() -> None:
    server_priv = X25519PrivateKey.generate()
    client_priv = X25519PrivateKey.generate()
    pkt, _e, _c, _h = wg_crypto.build_handshake_init(
        server_pub=_raw_pub(server_priv),
        client_priv=_raw_priv(client_priv),
        client_pub=_raw_pub(client_priv),
    )
    assert len(pkt) == 148, f"expected 148 bytes, got {len(pkt)}"
    assert pkt[0] == 0x01, f"first byte must be 0x01, got 0x{pkt[0]:02x}"
    assert pkt[1:4] == b"\x00\x00\x00"


def test_handshake_init_mac1_verifies_with_server_pub() -> None:
    import hashlib
    server_priv = X25519PrivateKey.generate()
    client_priv = X25519PrivateKey.generate()
    server_pub_bytes = _raw_pub(server_priv)
    pkt, _e, _c, _h = wg_crypto.build_handshake_init(
        server_pub=server_pub_bytes,
        client_priv=_raw_priv(client_priv),
        client_pub=_raw_pub(client_priv),
    )
    mac1_key = hashlib.blake2s(
        wg_crypto.LABEL_MAC1 + server_pub_bytes, digest_size=32,
    ).digest()
    expected_mac1 = hashlib.blake2s(
        pkt[:116], key=mac1_key, digest_size=16,
    ).digest()
    assert pkt[116:132] == expected_mac1, "MAC1 mismatch — server would silently drop"
    assert pkt[132:148] == b"\x00" * 16


def test_handshake_init_server_can_decrypt_static() -> None:
    import hashlib
    server_priv = X25519PrivateKey.generate()
    client_priv = X25519PrivateKey.generate()
    server_pub_bytes = _raw_pub(server_priv)
    client_pub_bytes = _raw_pub(client_priv)

    pkt, _e, _c, _h = wg_crypto.build_handshake_init(
        server_pub=server_pub_bytes,
        client_priv=_raw_priv(client_priv),
        client_pub=client_pub_bytes,
    )

    Ci = hashlib.blake2s(wg_crypto.NOISE_CONSTRUCTION, digest_size=32).digest()
    Hi = hashlib.blake2s(Ci + wg_crypto.WG_IDENTIFIER, digest_size=32).digest()
    Hi = hashlib.blake2s(Hi + server_pub_bytes, digest_size=32).digest()

    e_pub_in_pkt = pkt[8:40]
    Ci_after_e, = wg_crypto.hkdf(Ci, e_pub_in_pkt, 1)
    Hi = hashlib.blake2s(Hi + e_pub_in_pkt, digest_size=32).digest()

    dh1 = server_priv.exchange(X25519PublicKey.from_public_bytes(e_pub_in_pkt))
    Ci_after_dh1, K1 = wg_crypto.hkdf(Ci_after_e, dh1, 2)
    encrypted_static = pkt[40:88]
    decrypted_static = ChaCha20Poly1305(K1).decrypt(
        bytes(12), encrypted_static, Hi,
    )
    assert decrypted_static == client_pub_bytes


def test_invalid_key_size_raises() -> None:
    with pytest.raises(ValueError, match="32"):
        wg_crypto.build_handshake_init(
            server_pub=b"\x00" * 31,
            client_priv=b"\x00" * 32,
            client_pub=b"\x00" * 32,
        )


def test_handshake_response_parser_accepts_valid_response() -> None:
    response = bytes([0x02, 0x00, 0x00, 0x00]) + os.urandom(88)
    assert wg_crypto.is_valid_handshake_response_shape(response) is True


def test_handshake_response_parser_rejects_wrong_type() -> None:
    response = bytes([0x01, 0x00, 0x00, 0x00]) + os.urandom(88)
    assert wg_crypto.is_valid_handshake_response_shape(response) is False


def test_handshake_response_parser_rejects_wrong_length() -> None:
    assert wg_crypto.is_valid_handshake_response_shape(b"\x02\x00\x00\x00" + b"\x00" * 50) is False
