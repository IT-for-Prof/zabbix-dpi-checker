"""RDP probe — X.224 Connection Request + Confirm classification."""

from __future__ import annotations

import socket
import time

from probe.lib.resolver import resolve_with_doh_check
from probe.lib.verdict import Verdict, VerdictCode


def _build_x224_connection_request(cookie: str) -> bytes:
    """Build an X.224 Connection Request PDU wrapped in TPKT.

    Layout (RFC 1006 + ITU T.123 + MS-RDPBCGR §2.2.1.1):
      TPKT header   : 03 00 LL LL      (TPKT length = whole packet)
      X.224 header  : LI E0 00 00 00 00 00   (LI = 6, fixed for CR-TPDU; covers
                                              the 6 bytes after LI, NOT the cookie)
      Cookie data   : "Cookie: mstshash=<user>\\r\\n"   (TPDU user data, appended)
    """
    cookie_field = f"Cookie: mstshash={cookie}\r\n".encode("ascii")
    # X.224 LI is fixed at 6 (the length of the CR-TPDU header excluding LI itself).
    # Cookie/user data follows the CR-TPDU and is NOT counted in LI.
    x224_header = bytes([6]) + b"\xe0\x00\x00\x00\x00\x00\x00"
    x224_pdu = x224_header + cookie_field
    total_len = 4 + len(x224_pdu)  # TPKT length includes the 4-byte TPKT header
    tpkt = b"\x03\x00" + total_len.to_bytes(2, "big")
    return tpkt + x224_pdu


def probe(*, dns: str, port: int, cookie: str = "rdp-probe", timeout: float) -> Verdict:
    """Probe an RDP endpoint with X.224 Connection Request.

    Args:
        dns: target hostname/IP.
        port: TCP port (3389, 43389, etc.).
        cookie: mstshash value (irrelevant for blind probing, but must be present).
        timeout: total budget.
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

    payload = _build_x224_connection_request(cookie)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
    except TimeoutError:
        return Verdict(
            code=VerdictCode.PORT_FILTERED,
            reason="TCP connect timeout",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    except ConnectionRefusedError:
        return Verdict(
            code=VerdictCode.REMOTE_DOWN,
            reason="TCP RST on connect (port closed)",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    except ConnectionResetError as e:
        return Verdict(
            code=VerdictCode.TCP_RST_HANDSHAKE,
            reason=f"RST during TCP connect: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    except OSError as e:
        return Verdict(
            code=VerdictCode.ROUTE_BLACKHOLE,
            reason=f"connect failed: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )

    try:
        sock.sendall(payload)
    except (ConnectionResetError, BrokenPipeError) as e:
        return Verdict(
            code=VerdictCode.TCP_RST_HANDSHAKE,
            reason=f"RST while sending X.224 Request: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            bytes_before_fail=0,
            resolved_ip=ip,
        )

    response = b""
    try:
        response = sock.recv(4096)
    except (ConnectionResetError, BrokenPipeError) as e:
        return Verdict(
            code=VerdictCode.TCP_RST_MID_STREAM if response else VerdictCode.TCP_RST_HANDSHAKE,
            reason=f"RST while reading X.224 Confirm (likely RDP DPI): {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            bytes_before_fail=len(response),
            resolved_ip=ip,
        )
    except TimeoutError:
        return Verdict(
            code=VerdictCode.PORT_FILTERED,
            reason="timeout reading X.224 Confirm",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    except OSError as e:
        return Verdict(
            code=VerdictCode.ROUTE_BLACKHOLE,
            reason=f"socket error reading X.224 Confirm: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            bytes_before_fail=len(response),
            resolved_ip=ip,
        )
    finally:
        sock.close()

    latency_ms = (time.monotonic() - t0) * 1000.0
    if not response:
        return Verdict(
            code=VerdictCode.REMOTE_HUNGUP_AFTER_CONNECT,
            reason="peer closed TCP after X.224 ConnectionRequest without responding",
            latency_ms=latency_ms,
            bytes_before_fail=0,
            resolved_ip=ip,
        )
    if len(response) < 4 or response[0:2] != b"\x03\x00":
        return Verdict(
            code=VerdictCode.BANNER_MISMATCH,
            reason=f"response is not a TPKT frame: {response[:32]!r}",
            latency_ms=latency_ms,
            bytes_before_fail=len(response),
            resolved_ip=ip,
        )
    if len(response) >= 6 and response[5] != 0xD0:
        return Verdict(
            code=VerdictCode.BANNER_MISMATCH,
            reason=f"TPKT received but PDU type is 0x{response[5]:02x}, expected 0xD0 (CC)",
            latency_ms=latency_ms,
            bytes_before_fail=len(response),
            resolved_ip=ip,
        )

    return Verdict(
        code=VerdictCode.OK,
        reason="X.224 Connection Confirm received",
        latency_ms=latency_ms,
        resolved_ip=ip,
        extra={"response_bytes": len(response)},
    )
