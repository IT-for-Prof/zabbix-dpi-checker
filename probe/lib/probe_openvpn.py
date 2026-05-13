"""OpenVPN probe — P_CONTROL_HARD_RESET_CLIENT_V2 for UDP / TCP.

This works for servers WITHOUT tls-auth / tls-crypt. For servers with --tls-auth,
the initial packet needs an HMAC of the auth key, which we don't have in the simple
case. When tls-auth is in play and we don't have the key, the server will simply
drop our packet, so we'll see PORT_FILTERED — which is the same shape as blocking.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from typing import Literal

from probe.lib.resolver import resolve_with_doh_check
from probe.lib.verdict import Verdict, VerdictCode

OvpnMode = Literal["udp", "tcp"]


def _build_hard_reset_v2() -> bytes:
    """Build a minimal P_CONTROL_HARD_RESET_CLIENT_V2 packet.

    Layout (OpenVPN protocol §3):
      1 byte  : opcode<<3 | key_id  = 0x38 (7<<3 | 0)
      8 bytes : session_id (random)
      1 byte  : message_packet_id_array_length = 0
      4 bytes : message_packet_id = 0
    Total: 14 bytes. No HMAC (tls-auth not in use here).
    """
    return struct.pack("!B", 0x38) + os.urandom(8) + b"\x00" + struct.pack("!I", 0)


def probe(*, dns: str, port: int, timeout: float, mode: OvpnMode = "udp") -> Verdict:
    """Probe an OpenVPN endpoint over UDP or TCP."""
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

    payload = _build_hard_reset_v2()

    if mode == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(payload, (ip, port))
            response, _ = sock.recvfrom(2048)
        except TimeoutError:
            sock.close()
            return Verdict(
                code=VerdictCode.PORT_FILTERED,
                reason="no UDP response within timeout (may also be tls-auth without key)",
                latency_ms=(time.monotonic() - t0) * 1000.0,
                resolved_ip=ip,
            )
        except OSError as e:
            sock.close()
            return Verdict(
                code=VerdictCode.ROUTE_BLACKHOLE,
                reason=f"UDP error: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
                resolved_ip=ip,
            )
        finally:
            sock.close()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            framed = struct.pack("!H", len(payload)) + payload
            sock.sendall(framed)
            length_bytes = sock.recv(2)
            if len(length_bytes) < 2:
                sock.close()
                return Verdict(
                    code=VerdictCode.TCP_RST_HANDSHAKE,
                    reason="connection closed before length prefix",
                    latency_ms=(time.monotonic() - t0) * 1000.0,
                    bytes_before_fail=len(length_bytes),
                    resolved_ip=ip,
                )
            (resp_len,) = struct.unpack("!H", length_bytes)
            response = sock.recv(resp_len)
        except ConnectionResetError as e:
            sock.close()
            return Verdict(
                code=VerdictCode.TCP_RST_MID_STREAM,
                reason=f"TCP RST after sending HARD_RESET: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
                resolved_ip=ip,
            )
        except TimeoutError:
            sock.close()
            return Verdict(
                code=VerdictCode.PORT_FILTERED,
                reason="TCP timeout reading response",
                latency_ms=(time.monotonic() - t0) * 1000.0,
                resolved_ip=ip,
            )
        except ConnectionRefusedError:
            sock.close()
            return Verdict(
                code=VerdictCode.REMOTE_DOWN,
                reason="TCP RST on connect",
                latency_ms=(time.monotonic() - t0) * 1000.0,
                resolved_ip=ip,
            )
        except OSError as e:
            sock.close()
            return Verdict(
                code=VerdictCode.ROUTE_BLACKHOLE,
                reason=f"TCP error: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
                resolved_ip=ip,
            )
        finally:
            sock.close()

    latency_ms = (time.monotonic() - t0) * 1000.0
    if response and response[0] == 0x40:
        return Verdict(
            code=VerdictCode.OK,
            reason="OpenVPN HARD_RESET_SERVER_V2 received (opcode 0x40)",
            latency_ms=latency_ms,
            resolved_ip=ip,
            extra={"response_bytes": len(response)},
        )
    return Verdict(
        code=VerdictCode.BANNER_MISMATCH,
        reason=(
            f"response is not OpenVPN HARD_RESET_SERVER_V2: "
            f"first byte = 0x{response[0]:02x}" if response else "empty response"
        ),
        latency_ms=latency_ms,
        bytes_before_fail=len(response),
        resolved_ip=ip,
    )
