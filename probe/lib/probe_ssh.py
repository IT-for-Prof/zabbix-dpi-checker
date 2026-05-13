"""SSH probe — read the server's identification banner and check the SSH- prefix."""

from __future__ import annotations

import socket
import time

from probe.lib.resolver import resolve_with_doh_check
from probe.lib.verdict import Verdict, VerdictCode


def probe(*, dns: str, port: int, timeout: float) -> Verdict:
    """Probe an SSH endpoint: connect, read banner up to CRLF, verify SSH- prefix."""
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

    banner = b""
    try:
        while b"\n" not in banner and len(banner) < 512:
            chunk = sock.recv(512 - len(banner))
            if not chunk:
                break
            banner += chunk
    except (ConnectionResetError, BrokenPipeError) as e:
        return Verdict(
            code=VerdictCode.TCP_RST_MID_STREAM if banner else VerdictCode.TCP_RST_HANDSHAKE,
            reason=f"RST while reading SSH banner: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            bytes_before_fail=len(banner),
            resolved_ip=ip,
        )
    except TimeoutError:
        return Verdict(
            code=VerdictCode.PORT_FILTERED,
            reason="timeout reading SSH banner",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            bytes_before_fail=len(banner),
            resolved_ip=ip,
        )
    except OSError as e:
        return Verdict(
            code=VerdictCode.ROUTE_BLACKHOLE,
            reason=f"socket error reading SSH banner: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            bytes_before_fail=len(banner),
            resolved_ip=ip,
        )
    finally:
        sock.close()

    latency_ms = (time.monotonic() - t0) * 1000.0
    if not banner:
        return Verdict(
            code=VerdictCode.REMOTE_HUNGUP_AFTER_CONNECT,
            reason="peer closed TCP after connect without sending SSH banner",
            latency_ms=latency_ms,
            bytes_before_fail=0,
            resolved_ip=ip,
            extra={"banner": ""},
        )

    text = banner.decode("ascii", errors="replace").rstrip("\r\n")
    if not text.startswith("SSH-"):
        return Verdict(
            code=VerdictCode.BANNER_MISMATCH,
            reason=f"banner does not start with 'SSH-'; got {text[:80]!r}",
            latency_ms=latency_ms,
            bytes_before_fail=len(banner),
            resolved_ip=ip,
            extra={"banner": text[:200]},
        )

    return Verdict(
        code=VerdictCode.OK,
        reason="SSH banner received and starts with 'SSH-'",
        latency_ms=latency_ms,
        resolved_ip=ip,
        extra={"banner": text[:200]},
    )
