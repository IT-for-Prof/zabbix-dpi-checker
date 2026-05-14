"""HTTPS bytes-counter probe — redesigned with interleaved write+read.

Original design used non-blocking recv gated by `cumulative % 4096` which:
(a) Only fires on specific chunk-size/byte-position alignments
(b) Misses RSTs that arrive between writes when TCP buffers absorb data
    without surfacing the error to user-space sendall

Redesign: after the TLS handshake, send small chunks (1 KB) and after EACH
chunk do a short-timeout blocking read to drain any echo or detect RST.
This is the pattern used by rkn-block-checker and hyperion-cs for the
documented TSPU 16-20 K bytes-counter signature.

The probe sends an HTTP POST request that the server is expected to echo
back chunk-by-chunk (typical of TSPU's man-in-the-middle echo behavior on
flagged flows, and easy to simulate with a localhost echo server for tests).
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import time

from probe.lib.resolver import resolve_with_doh_check
from probe.lib.verdict import Discriminator, Verdict, VerdictCode


def _is_rst_error(e: Exception) -> bool:
    """Heuristic: does this exception indicate a TCP RST or hard-close from peer?

    At the TLS layer, a server-side `SO_LINGER 0 + close` (the canonical way to
    force a RST) surfaces as `ssl.SSLEOFError` ("EOF occurred in violation of
    protocol") because the TLS close-notify never arrives. So we count
    SSLEOFError as a RST signature here. SSLZeroReturnError on the other hand
    is a *clean* close (TLS close-notify received) and is NOT a RST.
    """
    if isinstance(e, ConnectionResetError | BrokenPipeError | ssl.SSLEOFError):
        return True
    if isinstance(e, OSError) and e.errno == 104:  # ECONNRESET
        return True
    if isinstance(e, ssl.SSLZeroReturnError):
        return False
    msg = str(e).upper()
    return "RESET" in msg or "ECONNRESET" in msg or "EOF" in msg


def probe(
    *,
    dns: str,
    port: int,
    sni: str,
    timeout: float,
    push_bytes: int = 64 * 1024,
    expect_rst_window: tuple[int, int] = (14_000, 34_000),
    chunk_size: int = 1024,
    interleave_read_timeout: float = 0.05,
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

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect((ip, port))
    except (TimeoutError, ConnectionRefusedError, OSError) as e:
        raw.close()
        code = (
            VerdictCode.REMOTE_DOWN if isinstance(e, ConnectionRefusedError)
            else VerdictCode.PORT_FILTERED if isinstance(e, TimeoutError)
            else VerdictCode.ROUTE_BLACKHOLE
        )
        return Verdict(
            code=code,
            reason=f"TCP connect failed: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )

    try:
        tls = ctx.wrap_socket(raw, server_hostname=sni, do_handshake_on_connect=True)
    except ConnectionResetError:
        raw.close()
        return Verdict(
            code=VerdictCode.TLS_RESET_POST_HELLO,
            reason="TCP RST during TLS handshake (SNI-based block)",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
            discriminator=Discriminator.SNI_BASED,
        )
    except (TimeoutError, ssl.SSLEOFError):
        raw.close()
        return Verdict(
            code=VerdictCode.TLS_TIMEOUT,
            reason="TLS handshake timed out",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )
    except (ssl.SSLError, OSError) as e:
        raw.close()
        return Verdict(
            code=VerdictCode.TLS_TIMEOUT,
            reason=f"TLS error: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
        )

    rst_at: int | None = None
    cumulative = 0
    extra_reason = ""
    try:
        # HTTP-shaped header so middlebox classifies the flow as HTTP/HTTPS
        header = (
            f"POST /probe HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            f"User-Agent: dpi-probe\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {push_bytes}\r\n"
            f"\r\n"
        ).encode()
        try:
            tls.sendall(header)
            cumulative += len(header)
        except ssl.SSLZeroReturnError:
            # Clean TLS close from peer — not a RST
            pass
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError) as e:
            if _is_rst_error(e):
                rst_at = cumulative
            else:
                raise

        # Interleave: send 1 KB, then short-timeout blocking read.
        while rst_at is None and cumulative < push_bytes:
            n = min(chunk_size, push_bytes - cumulative)
            try:
                tls.sendall(b"X" * n)
                cumulative += n
            except ssl.SSLZeroReturnError:
                # Clean TLS close from peer — not a RST
                break
            except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError) as e:
                if _is_rst_error(e):
                    rst_at = cumulative
                    extra_reason = f"send: {type(e).__name__}"
                    break
                raise

            # Drain echo / detect async RST
            try:
                tls.settimeout(interleave_read_timeout)
                data = tls.recv(8192)
                if not data:
                    # Peer sent EOF (either graceful close-notify or TCP RST/hard close).
                    # On a clean TLS close (close-notify), the next recv() will raise
                    # SSLZeroReturnError. On a hard close (SO_LINGER 0), we expect an
                    # RST-like exception. Timeout means we can't tell, so assume clean.
                    # Do NOT set rst_at here; let the exception handler below decide.
                    pass
            except (TimeoutError, ssl.SSLWantReadError, BlockingIOError):
                pass  # Normal: no echo yet, keep pushing
            except ssl.SSLZeroReturnError:
                # Clean TLS close — not a RST signature
                break
            except (ConnectionResetError, ssl.SSLError, OSError) as e:
                if _is_rst_error(e):
                    rst_at = cumulative
                    extra_reason = f"recv: {type(e).__name__}"
                    break
                raise
            finally:
                tls.settimeout(timeout)
    finally:
        with contextlib.suppress(ssl.SSLError, OSError):
            tls.close()
        with contextlib.suppress(OSError):
            raw.close()

    return _classify(
        rst_at=rst_at,
        push_bytes=push_bytes,
        expect_rst_window=expect_rst_window,
        ip=ip,
        t0=t0,
        extra_reason=extra_reason,
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
    suffix = f" ({extra_reason})" if extra_reason else ""
    if lo <= rst_at <= hi:
        return Verdict(
            code=VerdictCode.THROTTLE_DETECTED,
            reason=f"TCP RST at {rst_at}B inside [{lo},{hi}] — TSPU bytes-counter{suffix}",
            latency_ms=latency_ms,
            bytes_before_fail=rst_at,
            resolved_ip=ip,
            extra={"window_lo": lo, "window_hi": hi},
        )
    return Verdict(
        code=VerdictCode.TCP_RST_MID_STREAM,
        reason=f"TCP RST at {rst_at}B outside [{lo},{hi}]{suffix}",
        latency_ms=latency_ms,
        bytes_before_fail=rst_at,
        resolved_ip=ip,
    )
