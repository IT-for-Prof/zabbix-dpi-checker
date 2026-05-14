"""WireGuard Noise IKpsk2 handshake primitives for DirectDPI probe initialization.

Implements the Noise IKpsk2 initiator handshake (message 1) used by WireGuard to
establish encrypted tunnels. Includes byte-level packet construction and MAC
computation per RFC 7539 / WireGuard whitepaper.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NOISE_CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
WG_IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"

_KEY_LEN = 32
_MAC_LEN = 16
_AEAD_TAG_LEN = 16
_HANDSHAKE_INIT_LEN = 148
_HANDSHAKE_RESPONSE_LEN = 92
_TAI64_EPOCH_OFFSET = 4611686018427387914


def _hash(*chunks: bytes) -> bytes:
    h = hashlib.blake2s(digest_size=32)
    for c in chunks:
        h.update(c)
    return h.digest()


def _mac(key: bytes, msg: bytes) -> bytes:
    return hashlib.blake2s(msg, key=key, digest_size=_MAC_LEN).digest()


def hkdf(chaining_key: bytes, input_key_material: bytes, n: int) -> tuple[bytes, ...]:
    if not 1 <= n <= 3:
        raise ValueError(f"hkdf n must be 1..3, got {n}")
    prk = hmac.new(chaining_key, input_key_material, hashlib.blake2s).digest()
    outs: list[bytes] = []
    prev = b""
    for i in range(1, n + 1):
        prev = hmac.new(prk, prev + bytes([i]), hashlib.blake2s).digest()
        outs.append(prev)
    return tuple(outs)


def _aead(key: bytes, counter: int, plaintext: bytes, ad: bytes) -> bytes:
    nonce = b"\x00\x00\x00\x00" + struct.pack("<Q", counter)
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, ad)


def _tai64n_now() -> bytes:
    now = time.time()
    secs = int(now) + _TAI64_EPOCH_OFFSET
    nanos = int((now - int(now)) * 1e9)
    return struct.pack(">Q", secs) + struct.pack(">I", nanos)


def _validate_key(name: str, key: bytes) -> None:
    if len(key) != _KEY_LEN:
        raise ValueError(
            f"{name} must be exactly {_KEY_LEN} bytes (X25519), got {len(key)}"
        )


# WireGuard whitepaper §5.4 — Noise IKpsk2 initiator state machine.
def build_handshake_init(
    server_pub: bytes,
    client_priv: bytes,
    client_pub: bytes,
    psk: bytes | None = None,
    sender_index: bytes | None = None,
    ephemeral: X25519PrivateKey | None = None,
) -> tuple[bytes, X25519PrivateKey, bytes, bytes]:
    _validate_key("server_pub", server_pub)
    _validate_key("client_priv", client_priv)
    _validate_key("client_pub", client_pub)
    if psk is not None:
        _validate_key("psk", psk)

    # PSK mixing is not yet implemented. The protocol requires an extra HKDF
    # step between DH2 and the timestamp encryption when psk != zeros. Raise
    # rather than silently produce wrong packets — a future task can add it.
    if psk is not None and psk != b"\x00" * 32:
        raise NotImplementedError(
            "non-zero psk not supported by build_handshake_init yet; "
            "the IKpsk2 PSK-mixing HKDF step is unimplemented"
        )
    if sender_index is None:
        sender_index = os.urandom(4)
    elif len(sender_index) != 4:
        raise ValueError("sender_index must be 4 bytes")
    if ephemeral is None:
        ephemeral = X25519PrivateKey.generate()

    ci = _hash(NOISE_CONSTRUCTION)
    hi = _hash(ci, WG_IDENTIFIER)
    hi = _hash(hi, server_pub)

    e_pub = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    (ci,) = hkdf(ci, e_pub, 1)
    hi = _hash(hi, e_pub)

    dh1 = ephemeral.exchange(X25519PublicKey.from_public_bytes(server_pub))
    ci, k1 = hkdf(ci, dh1, 2)
    encrypted_static = _aead(k1, 0, client_pub, hi)
    hi = _hash(hi, encrypted_static)

    dh2 = X25519PrivateKey.from_private_bytes(client_priv).exchange(
        X25519PublicKey.from_public_bytes(server_pub)
    )
    ci, k2 = hkdf(ci, dh2, 2)
    encrypted_timestamp = _aead(k2, 0, _tai64n_now(), hi)
    hi = _hash(hi, encrypted_timestamp)

    # Packet layout (§5.4): type(1) + reserved(3) + sender_index(4) + e_pub(32)
    #                       + encrypted_static(32+16) + encrypted_timestamp(12+16)
    #                       + mac1(16) + mac2(16) = 148 bytes total.
    msg_body = (
        bytes([0x01]) + b"\x00\x00\x00"
        + sender_index
        + e_pub
        + encrypted_static
        + encrypted_timestamp
    )
    assert len(msg_body) == 116, f"msg_body len {len(msg_body)} != 116"

    mac1_key = _hash(LABEL_MAC1, server_pub)
    mac1 = _mac(mac1_key, msg_body)
    mac2 = b"\x00" * _MAC_LEN

    packet = msg_body + mac1 + mac2
    assert len(packet) == _HANDSHAKE_INIT_LEN, \
        f"packet len {len(packet)} != {_HANDSHAKE_INIT_LEN}"
    return packet, ephemeral, ci, hi


def is_valid_handshake_response_shape(response: bytes) -> bool:
    return (
        len(response) == _HANDSHAKE_RESPONSE_LEN
        and response[0] == 0x02
        and response[1:4] == b"\x00\x00\x00"
    )
