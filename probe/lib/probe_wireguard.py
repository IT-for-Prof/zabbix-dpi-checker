"""WireGuard probe — handshake_init UDP packet, optional pubkey-aware response check.

When pubkey is provided we build a syntactically-valid handshake_init (no Curve25519
math — random ephemeral / static fields are fine for blind probing because the *server*
will only attempt decryption if the static field matches its expected initiator. For
our purposes, we just need to observe whether the server *responds at all*: a 92-byte
handshake_response is a strong positive; silence is ambiguous unless we know the server
is configured to respond to our test traffic.

Without pubkey, we emit UDP_BLIND — we cannot distinguish blocking from policy drop.
"""

from __future__ import annotations

import base64
import os
import socket
import struct
import time

from probe.lib.resolver import resolve_with_doh_check
from probe.lib.verdict import Verdict, VerdictCode


def _build_handshake_init(static_pubkey: bytes) -> bytes:
    """Build a 148-byte WireGuard handshake_init message.

    Layout (RFC noise IKpsk2 framing, WireGuard whitepaper §5.4.2):
      1 byte  : type = 0x01
      3 bytes : reserved = 0x00 0x00 0x00
      4 bytes : sender index (random)
      32 bytes: ephemeral public key (random)
      32 bytes: encrypted static (we put pubkey here; real impl would MAC it)
      16 bytes: poly1305 tag for static
      12 bytes: encrypted timestamp
      16 bytes: poly1305 tag for timestamp
      16 bytes: mac1 (we put zeros — real impl computes BLAKE2s)
      16 bytes: mac2 (zeros)
    Total: 148 bytes.
    """
    sender_index = os.urandom(4)
    ephemeral = os.urandom(32)
    enc_static = static_pubkey[:32].ljust(32, b"\x00")
    tag_static = os.urandom(16)
    enc_ts = os.urandom(12)
    tag_ts = os.urandom(16)
    mac1 = b"\x00" * 16
    mac2 = b"\x00" * 16
    return (
        struct.pack("!B3x", 0x01)
        + sender_index
        + ephemeral
        + enc_static
        + tag_static
        + enc_ts
        + tag_ts
        + mac1
        + mac2
    )


def probe(*, dns: str, port: int, timeout: float, pubkey_b64: str | None = None) -> Verdict:
    """Probe a WireGuard endpoint.

    Args:
        pubkey_b64: server static public key, base64-encoded (44 chars). If None,
                    emits UDP_BLIND verdict because handshake will be silently dropped
                    regardless of network reachability.
    """
    t0 = time.monotonic()
    res = resolve_with_doh_check(dns, timeout=timeout)
    if res.ip is None:
        # System resolver failed. DoH success means the name is valid → likely
        # locally-blocked → DNS_LIE. DoH also failing → genuine NXDOMAIN/typo.
        code = VerdictCode.DNS_LIE if res.doh_ips else VerdictCode.ERROR_INTERNAL
        return Verdict(
            code=code,
            reason=f"DNS lookup failed: {res.system_error}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            extra={"doh_ips": sorted(res.doh_ips)} if res.doh_ips else {},
        )
    ip = res.ip
    # res.mismatch is INFORMATIONAL only — CDN edge variance produces routine
    # mismatch on legitimate services. Record in extra below if present; do
    # NOT short-circuit with DNS_LIE here.

    if not pubkey_b64:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(b"\x01" + b"\x00" * 147, (ip, port))
        except OSError as e:
            sock.close()
            return Verdict(
                code=VerdictCode.ROUTE_BLACKHOLE,
                reason=f"UDP send failed: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
                resolved_ip=ip,
            )
        sock.close()
        return Verdict(
            code=VerdictCode.UDP_BLIND,
            reason="no pubkey configured; UDP send succeeded but response cannot be classified",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )

    try:
        pubkey = base64.b64decode(pubkey_b64, validate=True)
    except (ValueError, TypeError) as e:
        return Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=f"invalid base64 pubkey: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )

    payload = _build_handshake_init(pubkey)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (ip, port))
    except OSError as e:
        sock.close()
        return Verdict(
            code=VerdictCode.ROUTE_BLACKHOLE,
            reason=f"UDP send failed: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )

    try:
        response, _ = sock.recvfrom(2048)
    except TimeoutError:
        sock.close()
        return Verdict(
            code=VerdictCode.PORT_FILTERED,
            reason="no UDP response within timeout",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    except OSError as e:
        sock.close()
        return Verdict(
            code=VerdictCode.ROUTE_BLACKHOLE,
            reason=f"UDP recv failed (likely ICMP unreachable): {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    finally:
        sock.close()

    latency_ms = (time.monotonic() - t0) * 1000.0
    if len(response) >= 1 and response[0] == 0x02:
        return Verdict(
            code=VerdictCode.OK,
            reason="WireGuard handshake_response received (type=0x02)",
            latency_ms=latency_ms,
            bytes_before_fail=None,
            resolved_ip=ip,
            extra={"response_bytes": len(response)},
        )
    return Verdict(
        code=VerdictCode.BANNER_MISMATCH,
        reason=f"response is not a WG handshake_response: type=0x{response[0]:02x}",
        latency_ms=latency_ms,
        bytes_before_fail=len(response),
        resolved_ip=ip,
    )
