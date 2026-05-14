"""HTTPS bytes-counter probe for TSPU-style throttle detection."""

from __future__ import annotations

import socket
import ssl
import time
from contextlib import suppress

from probe.lib.resolver import resolve_with_doh_check
from probe.lib.verdict import Discriminator, Verdict, VerdictCode


def probe(
    *,
    dns: str,
    port: int,
    sni: str,
    timeout: float,
    push_bytes: int = 32 * 1024,
    expect_rst_window: tuple[int, int] = (14_000, 34_000),
) -> Verdict:
    """Push HTTP-shaped TLS bytes and classify a reset by byte position."""
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

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect((ip, port))
    except (TimeoutError, ConnectionRefusedError, OSError) as e:
        raw.close()
        return _connect_error(e, ip=ip, t0=t0)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        tls = ctx.wrap_socket(raw, server_hostname=sni, do_handshake_on_connect=True)
    except ConnectionResetError:
        raw.close()
        return Verdict(
            code=VerdictCode.TLS_RESET_POST_HELLO,
            reason="TCP RST during TLS handshake",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
            discriminator=Discriminator.SNI_BASED,
        )
    except (TimeoutError, ssl.SSLError, OSError) as e:
        raw.close()
        return Verdict(
            code=VerdictCode.TLS_TIMEOUT,
            reason=f"TLS handshake failed: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )

    cumulative = 0
    rst_at: int | None = None
    extra_reason = ""
    try:
        header = (
            "POST /probe HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            "User-Agent: dpi-probe\r\n"
            "Content-Type: application/octet-stream\r\n"
            f"Content-Length: {push_bytes}\r\n"
            "\r\n"
        ).encode("ascii")
        cumulative = _send_and_probe(tls, header, cumulative)
        chunk = b"A" * 1024
        while cumulative < push_bytes:
            n = min(len(chunk), push_bytes - cumulative)
            cumulative = _send_and_probe(tls, chunk[:n], cumulative)
    except (ConnectionResetError, ssl.SSLEOFError):
        rst_at = cumulative
    except (BrokenPipeError, ssl.SSLError, OSError) as e:
        return Verdict(
            code=VerdictCode.TCP_RST_MID_STREAM,
            reason=(
                f"mid-stream failure at {cumulative}B; not a confirmed TCP RST "
                f"({type(e).__name__}: {e})"
            ),
            latency_ms=(time.monotonic() - t0) * 1000.0,
            bytes_before_fail=cumulative,
            resolved_ip=ip,
        )
    finally:
        with suppress(ssl.SSLError, OSError):
            tls.close()
    return _classify(
        rst_at=rst_at,
        push_bytes=push_bytes,
        expect_rst_window=expect_rst_window,
        ip=ip,
        t0=t0,
        extra_reason=extra_reason,
    )


def _send_and_probe(tls: ssl.SSLSocket, payload: bytes, cumulative: int) -> int:
    tls.sendall(payload)
    cumulative += len(payload)
    time.sleep(0.001)
    tls.setblocking(False)
    try:
        tls.recv(4096)
    except (BlockingIOError, ssl.SSLWantReadError):
        pass
    finally:
        tls.setblocking(True)
    return cumulative


def _connect_error(e: BaseException, *, ip: str, t0: float) -> Verdict:
    if isinstance(e, ConnectionRefusedError):
        code = VerdictCode.REMOTE_DOWN
    elif isinstance(e, TimeoutError):
        code = VerdictCode.PORT_FILTERED
    else:
        code = VerdictCode.ROUTE_BLACKHOLE
    return Verdict(
        code=code,
        reason=f"TCP connect failed: {e}",
        latency_ms=(time.monotonic() - t0) * 1000.0,
        resolved_ip=ip,
    )


def _classify(
    *,
    rst_at: int | None,
    push_bytes: int,
    expect_rst_window: tuple[int, int],
    ip: str,
    t0: float,
    extra_reason: str,
) -> Verdict:
    latency_ms = (time.monotonic() - t0) * 1000.0
    if rst_at is None:
        return Verdict(
            code=VerdictCode.OK,
            reason=f"pushed {push_bytes}B without RST",
            latency_ms=latency_ms,
            resolved_ip=ip,
            extra={"pushed_bytes": push_bytes},
        )
    lo, hi = expect_rst_window
    if lo <= rst_at <= hi:
        return Verdict(
            code=VerdictCode.THROTTLE_DETECTED,
            reason=(
                f"TCP RST at {rst_at}B, inside throttle window [{lo}, {hi}]"
                + (f" ({extra_reason})" if extra_reason else "")
            ),
            latency_ms=latency_ms,
            bytes_before_fail=rst_at,
            resolved_ip=ip,
            extra={"window_lo": lo, "window_hi": hi},
        )
    return Verdict(
        code=VerdictCode.TCP_RST_MID_STREAM,
        reason=(
            f"TCP RST at {rst_at}B, outside throttle window [{lo}, {hi}]"
            + (f" ({extra_reason})" if extra_reason else "")
        ),
        latency_ms=latency_ms,
        bytes_before_fail=rst_at,
        resolved_ip=ip,
    )
