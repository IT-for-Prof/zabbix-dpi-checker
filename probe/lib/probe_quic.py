"""QUIC Initial packet reachability probe."""

from __future__ import annotations

import os
import socket
import time
from contextlib import suppress

from probe.lib.resolver import resolve_with_doh_check
from probe.lib.verdict import Verdict, VerdictCode

_MIN_INITIAL_SIZE = 1200


def _build_initial(sni: str) -> bytes:
    """Build a QUIC v1 long-header Initial-shaped datagram padded to 1200B."""
    _ = sni
    dcid = os.urandom(8)
    header = (
        b"\xc0"
        + b"\x00\x00\x00\x01"
        + bytes([len(dcid)])
        + dcid
        + b"\x00"
        + b"\x00"
        + b"\x40\x40"
        + b"\x00"
    )
    payload = os.urandom(63)
    pkt = header + payload
    if len(pkt) < _MIN_INITIAL_SIZE:
        pkt += b"\x00" * (_MIN_INITIAL_SIZE - len(pkt))
    return pkt


def probe(*, dns: str, port: int, sni: str, timeout: float) -> Verdict:
    """Send an Initial-shaped UDP datagram and classify the first response byte."""
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
    pkt = _build_initial(sni)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (ip, port))
        response, _ = sock.recvfrom(4096)
    except TimeoutError:
        return Verdict(
            code=VerdictCode.UDP_BLIND,
            reason=(
                "no response to Initial-shaped UDP probe; inconclusive because "
                "stdlib probe does not construct a decryptable QUIC Initial"
            ),
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    except ConnectionRefusedError:
        return Verdict(
            code=VerdictCode.REMOTE_DOWN,
            reason="ICMP unreachable on QUIC port",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    except OSError as e:
        return Verdict(
            code=VerdictCode.ROUTE_BLACKHOLE,
            reason=f"UDP error: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    finally:
        with suppress(OSError):
            sock.close()

    latency_ms = (time.monotonic() - t0) * 1000.0
    if response and (response[0] & 0xC0) == 0xC0:
        return Verdict(
            code=VerdictCode.OK,
            reason=f"QUIC long-header response received ({len(response)}B)",
            latency_ms=latency_ms,
            resolved_ip=ip,
            extra={"response_bytes": len(response), "first_byte": f"0x{response[0]:02x}"},
        )
    return Verdict(
        code=VerdictCode.BANNER_MISMATCH,
        reason=(
            f"response is not QUIC long-header: first byte 0x{response[0]:02x}"
            if response
            else "empty response"
        ),
        latency_ms=latency_ms,
        bytes_before_fail=len(response) if response else 0,
        resolved_ip=ip,
    )
