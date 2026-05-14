"""Fragmented-ClientHello SNI probe."""

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
    frag_size: int = 4,
) -> Verdict:
    """Send the TLS ClientHello in small TCP writes and complete the handshake."""
    if frag_size <= 0:
        return Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=f"frag_size must be > 0, got {frag_size}",
            latency_ms=0.0,
        )
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

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        sock.connect((ip, port))
    except (TimeoutError, ConnectionRefusedError, OSError) as e:
        sock.close()
        return _connect_error(e, ip=ip, t0=t0)

    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ssl_obj = ctx.wrap_bio(incoming, outgoing, server_hostname=sni)

    fragments_sent = 0
    try:
        while True:
            try:
                ssl_obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                pass

            out = outgoing.read()
            if out:
                for i in range(0, len(out), frag_size):
                    sock.sendall(out[i : i + frag_size])
                    fragments_sent += 1
                    time.sleep(0.001)

            remaining = max(0.001, timeout - (time.monotonic() - t0))
            sock.settimeout(remaining)
            try:
                data = sock.recv(8192)
            except TimeoutError:
                return Verdict(
                    code=VerdictCode.TLS_TIMEOUT,
                    reason=f"no TLS response after {fragments_sent} fragments",
                    latency_ms=(time.monotonic() - t0) * 1000.0,
                    resolved_ip=ip,
                    discriminator=Discriminator.SNI_BASED,
                    extra={"fragments_sent": fragments_sent, "frag_size": frag_size},
                )
            except ConnectionResetError:
                return Verdict(
                    code=VerdictCode.TLS_RESET_POST_HELLO,
                    reason="peer RST after fragmented ClientHello",
                    latency_ms=(time.monotonic() - t0) * 1000.0,
                    resolved_ip=ip,
                    discriminator=Discriminator.SNI_BASED,
                    extra={"fragments_sent": fragments_sent, "frag_size": frag_size},
                )
            if not data:
                return Verdict(
                    code=VerdictCode.REMOTE_HUNGUP_AFTER_CONNECT,
                    reason="peer closed cleanly mid-handshake",
                    latency_ms=(time.monotonic() - t0) * 1000.0,
                    resolved_ip=ip,
                    extra={"fragments_sent": fragments_sent, "frag_size": frag_size},
                )
            incoming.write(data)
    except ssl.SSLError as e:
        return Verdict(
            code=VerdictCode.TLS_TIMEOUT,
            reason=f"TLS error after {fragments_sent} fragments: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
            extra={"fragments_sent": fragments_sent, "frag_size": frag_size},
        )
    finally:
        with suppress(OSError):
            sock.close()

    return Verdict(
        code=VerdictCode.OK,
        reason=f"TLS handshake completed after {fragments_sent} fragments",
        latency_ms=(time.monotonic() - t0) * 1000.0,
        resolved_ip=ip,
        extra={"fragments_sent": fragments_sent, "frag_size": frag_size},
    )


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
