"""Userspace WireGuard handshake probe — extracted from plan Section 5.2."""

from __future__ import annotations

import base64
import binascii
import contextlib
import socket
import time
import traceback

from probe.lib import wg_crypto
from probe.lib.resolver import resolve_with_doh_check
from probe.lib.verdict import Verdict, VerdictCode


def _decode_key(name: str, b64: str) -> bytes:
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"{name}: not valid base64: {e}") from e
    if len(raw) != 32:
        raise ValueError(f"{name}: must decode to 32 bytes, got {len(raw)}")
    return raw


def probe(
    *,
    dns: str,
    port: int,
    timeout: float,
    server_pub_b64: str,
    client_priv_b64: str,
    client_pub_b64: str,
) -> Verdict:
    t0 = time.monotonic()

    res = resolve_with_doh_check(dns, timeout=timeout)
    if res.ip is None:
        code = VerdictCode.DNS_LIE if res.doh_ips else VerdictCode.ERROR_INTERNAL
        return Verdict(
            code=code,
            reason=f"DNS lookup failed: {res.system_error}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            extra={"doh_ips": sorted(res.doh_ips)} if res.doh_ips else {},
        )
    ip = res.ip

    try:
        server_pub = _decode_key("server_pub_b64", server_pub_b64)
        client_priv = _decode_key("client_priv_b64", client_priv_b64)
        client_pub = _decode_key("client_pub_b64", client_pub_b64)
    except ValueError as e:
        return Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=str(e),
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )

    try:
        packet, _e, _ci, _hi = wg_crypto.build_handshake_init(
            server_pub=server_pub,
            client_priv=client_priv,
            client_pub=client_pub,
        )
    except Exception as e:
        return Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=f"handshake build failed: {type(e).__name__}: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
            extra={"traceback": traceback.format_exc().splitlines()[-3:]},
        )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (ip, port))
    except OSError as e:
        sock.close()
        return Verdict(
            code=VerdictCode.ROUTE_BLACKHOLE,
            reason=f"UDP send failed: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )

    try:
        response, _addr = sock.recvfrom(2048)
    except TimeoutError:
        sock.close()
        return Verdict(
            code=VerdictCode.WG_HANDSHAKE_BLOCKED,
            reason="no HandshakeResponse within timeout",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    except ConnectionRefusedError:
        sock.close()
        return Verdict(
            code=VerdictCode.REMOTE_DOWN,
            reason="ICMP unreachable",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    except OSError as e:
        sock.close()
        return Verdict(
            code=VerdictCode.ROUTE_BLACKHOLE,
            reason=f"UDP recv error: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    finally:
        with contextlib.suppress(OSError):
            sock.close()

    latency_ms = (time.monotonic() - t0) * 1000.0

    if wg_crypto.is_valid_handshake_response_shape(response):
        return Verdict(
            code=VerdictCode.WG_HANDSHAKE_PASS,
            reason=f"HandshakeResponse received ({len(response)} B)",
            latency_ms=latency_ms,
            resolved_ip=ip,
            extra={"response_bytes": len(response)},
        )
    return Verdict(
        code=VerdictCode.BANNER_MISMATCH,
        reason=f"unexpected response shape: {len(response)} B, first byte 0x{response[0]:02x}",
        latency_ms=latency_ms,
        bytes_before_fail=len(response),
        resolved_ip=ip,
        extra={"first_byte": f"0x{response[0]:02x}"},
    )
