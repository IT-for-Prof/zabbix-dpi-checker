"""Single-target sanity probe for vantage health."""

from __future__ import annotations

import socket
import ssl
import time

from probe.lib.verdict import Verdict, VerdictCode

_DEFAULT_HOST = "1.1.1.1"
_DEFAULT_PORT = 443
_DEFAULT_SNI = "one.one.one.one"


def probe_control(
    host: str = _DEFAULT_HOST,
    port: int = _DEFAULT_PORT,
    sni: str = _DEFAULT_SNI,
    timeout: float = 5.0,
) -> Verdict:
    t0 = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect((host, port))
        except (ConnectionResetError, BrokenPipeError) as e:
            return Verdict(
                code=VerdictCode.TCP_RST_HANDSHAKE,
                reason=f"control: TCP reset by {host}:{port}: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
            )
        except TimeoutError:
            return Verdict(
                code=VerdictCode.PORT_FILTERED,
                reason=f"control: TCP connect timeout to {host}:{port}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
            )
        except ConnectionRefusedError as e:
            return Verdict(
                code=VerdictCode.REMOTE_DOWN,
                reason=f"control: TCP refused by {host}:{port}: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
            )
        except OSError as e:
            return Verdict(
                code=VerdictCode.ROUTE_BLACKHOLE,
                reason=f"control: TCP connect failed to {host}:{port}: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
            )

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.wrap_socket(sock, server_hostname=sni).close()
        except (ConnectionResetError, BrokenPipeError) as e:
            return Verdict(
                code=VerdictCode.TLS_RESET_POST_HELLO,
                reason=f"control: TLS reset by {host}:{port}: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
            )
        except TimeoutError:
            return Verdict(
                code=VerdictCode.TLS_TIMEOUT,
                reason=f"control: TLS handshake timeout with {host}:{port}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
            )
        except ssl.SSLError as e:
            code = (
                VerdictCode.TLS_TIMEOUT
                if "timed out" in str(e).lower()
                else VerdictCode.TLS_RESET_POST_HELLO
            )
            return Verdict(
                code=code,
                reason=f"control: TLS error with {host}:{port}: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
            )
        except OSError as e:
            return Verdict(
                code=VerdictCode.ERROR_INTERNAL,
                reason=f"control: unexpected OS error: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
            )

        return Verdict(
            code=VerdictCode.OK,
            reason="control: TLS handshake completed",
            latency_ms=(time.monotonic() - t0) * 1000.0,
        )
    finally:
        sock.close()
