"""SMTP / SMTPS probe — banner check and optional TLS, never sends DATA."""

from __future__ import annotations

import contextlib
import hashlib
import secrets
import socket
import ssl
import time
from typing import Literal

from probe.lib.resolver import resolve_with_doh_check
from probe.lib.verdict import Discriminator, Verdict, VerdictCode

SmtpKind = Literal["smtp", "smtps"]
_FOLLOWUP_TIMEOUT_CAP = 2.0
_MAX_DOH_FOLLOWUPS = 2


def _remaining_followup_timeout(started_at: float, total_timeout: float) -> float | None:
    remaining = total_timeout - (time.monotonic() - started_at)
    if remaining <= 0:
        return None
    return min(_FOLLOWUP_TIMEOUT_CAP, remaining)


def _probe_once(
    *,
    dns: str,
    port: int,
    kind: SmtpKind,
    expect_banner_prefix: str = "220",
    expect_cert_fp: str | None = None,
    sni: str | None = None,
    timeout: float,
) -> Verdict:
    """Probe SMTP (port 25 / 587 plain or with STARTTLS) or SMTPS (port 465 immediate TLS).

    For `kind="smtp"`: read banner only.
    For `kind="smtps"`: wrap immediately with TLS, then read banner.

    Never sends MAIL FROM / RCPT TO / DATA — banner-level check only.
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
    resolve_extra: dict[str, object] = {}
    if res.doh_ips:
        resolve_extra["doh_ips"] = sorted(res.doh_ips)
    if res.mismatch:
        resolve_extra["dns_mismatch"] = True
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
            extra=resolve_extra,
        )
    except ConnectionRefusedError:
        return Verdict(
            code=VerdictCode.REMOTE_DOWN,
            reason="TCP RST on connect (port closed)",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
            extra=resolve_extra,
        )
    except ConnectionResetError as e:
        return Verdict(
            code=VerdictCode.TCP_RST_HANDSHAKE,
            reason=f"TCP RST during connect (port/IP-level block, no app data sent): {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
            extra=resolve_extra,
        )
    except OSError as e:
        return Verdict(
            code=VerdictCode.ROUTE_BLACKHOLE,
            reason=f"connect failed: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
            extra=resolve_extra,
        )

    stream: socket.socket | ssl.SSLSocket = sock
    if kind == "smtps":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            stream = ctx.wrap_socket(sock, server_hostname=sni or dns)
            der = stream.getpeercert(binary_form=True) or b""
            if expect_cert_fp:
                actual_fp = hashlib.sha256(der).hexdigest()
                expected_fp = expect_cert_fp.replace(":", "").strip().lower()
                if actual_fp.lower() != expected_fp:
                    with contextlib.suppress(OSError):
                        stream.close()
                    return Verdict(
                        code=VerdictCode.CERT_MISMATCH,
                        reason=f"cert fingerprint mismatch (got {actual_fp})",
                        latency_ms=(time.monotonic() - t0) * 1000.0,
                        resolved_ip=ip,
                        extra={**resolve_extra, "cert_bytes": len(der)},
                    )
        except (ConnectionResetError, BrokenPipeError) as e:
            sock.close()
            return Verdict(
                code=VerdictCode.TLS_RESET_POST_HELLO,
                reason=f"RST during SMTPS TLS handshake: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
                resolved_ip=ip,
                extra=resolve_extra,
            )
        except TimeoutError as e:
            sock.close()
            return Verdict(
                code=VerdictCode.TLS_TIMEOUT,
                reason=f"timeout during SMTPS TLS handshake: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
                resolved_ip=ip,
                extra=resolve_extra,
            )
        except ssl.SSLError as e:
            sock.close()
            code = (
                VerdictCode.TLS_TIMEOUT
                if "timed out" in str(e).lower()
                else VerdictCode.TLS_RESET_POST_HELLO
            )
            return Verdict(
                code=code,
                reason=f"SSL error during SMTPS TLS handshake: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
                resolved_ip=ip,
                extra=resolve_extra,
            )
        except OSError as e:
            sock.close()
            return Verdict(
                code=VerdictCode.ERROR_INTERNAL,
                reason=f"unexpected OSError during SMTPS TLS handshake: {e}",
                latency_ms=(time.monotonic() - t0) * 1000.0,
                resolved_ip=ip,
                extra=resolve_extra,
            )

    banner = b""
    try:
        stream.settimeout(timeout)
        banner = stream.recv(4096)
    except (ConnectionResetError, BrokenPipeError) as e:
        return Verdict(
            code=VerdictCode.TCP_RST_HANDSHAKE if not banner else VerdictCode.TCP_RST_MID_STREAM,
            reason=f"RST while reading SMTP banner: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            bytes_before_fail=len(banner),
            resolved_ip=ip,
            extra=resolve_extra,
        )
    except TimeoutError:
        return Verdict(
            code=VerdictCode.TLS_TIMEOUT if kind == "smtps" else VerdictCode.PORT_FILTERED,
            reason="timeout reading SMTP banner",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            bytes_before_fail=len(banner),
            resolved_ip=ip,
            extra=resolve_extra,
        )
    finally:
        with contextlib.suppress(OSError):
            stream.close()

    latency_ms = (time.monotonic() - t0) * 1000.0
    if not banner:
        return Verdict(
            code=VerdictCode.REMOTE_HUNGUP_AFTER_CONNECT,
            reason="peer closed TCP after connect without sending SMTP banner",
            latency_ms=latency_ms,
            bytes_before_fail=0,
            resolved_ip=ip,
            extra=resolve_extra,
        )

    banner_text = banner.decode("ascii", errors="replace")
    if not banner_text.startswith(expect_banner_prefix):
        return Verdict(
            code=VerdictCode.BANNER_MISMATCH,
            reason=f"banner does not start with {expect_banner_prefix!r}; got {banner_text[:80]!r}",
            latency_ms=latency_ms,
            bytes_before_fail=len(banner),
            resolved_ip=ip,
            extra={**resolve_extra, "banner": banner_text[:200]},
        )

    return Verdict(
        code=VerdictCode.OK,
        reason="SMTP banner received and matches expected prefix",
        latency_ms=latency_ms,
        resolved_ip=ip,
        extra={**resolve_extra, "banner": banner_text[:200]},
    )


def _run_wrong_sni_followup(ip: str, port: int, original_sni: str, timeout: float) -> Verdict:
    bogus = f"sni-control-{secrets.token_hex(4)}.example"
    if bogus == original_sni:
        bogus = f"sni-control-{secrets.token_hex(4)}.invalid"
    return _probe_once(dns=ip, port=port, kind="smtps", sni=bogus, timeout=timeout)


def probe(
    *,
    dns: str,
    port: int,
    kind: SmtpKind,
    expect_banner_prefix: str = "220",
    expect_cert_fp: str | None = None,
    timeout: float,
    sni: str | None = None,
    _disable_followup: bool = False,
) -> Verdict:
    """Probe SMTP/SMTPS and optionally classify SMTPS block location via follow-ups."""
    started_at = time.monotonic()
    verdict = _probe_once(
        dns=dns,
        port=port,
        kind=kind,
        expect_banner_prefix=expect_banner_prefix,
        expect_cert_fp=expect_cert_fp,
        sni=sni,
        timeout=timeout,
    )
    if _disable_followup or kind != "smtps" or verdict.code == VerdictCode.OK:
        return verdict

    extra = dict(verdict.extra)
    if verdict.resolved_ip:
        followup_timeout = _remaining_followup_timeout(started_at, timeout)
        if followup_timeout is not None:
            wrong_sni = _run_wrong_sni_followup(
                verdict.resolved_ip, port, sni or dns, followup_timeout
            )
            extra["wrong_sni_verdict"] = wrong_sni.code.value
            if wrong_sni.code == VerdictCode.OK:
                verdict.extra = extra
                verdict.discriminator = Discriminator.SNI_BASED
                return verdict

    doh_ips = extra.get("doh_ips")
    if isinstance(doh_ips, list):
        followed = 0
        for doh_ip in doh_ips:
            if not isinstance(doh_ip, str) or doh_ip == verdict.resolved_ip:
                continue
            followup_timeout = _remaining_followup_timeout(started_at, timeout)
            if followup_timeout is None or followed >= _MAX_DOH_FOLLOWUPS:
                break
            followed += 1
            doh_follow = _probe_once(
                dns=doh_ip,
                port=port,
                kind="smtps",
                expect_banner_prefix=expect_banner_prefix,
                sni=sni or dns,
                timeout=followup_timeout,
            )
            if doh_follow.code == VerdictCode.OK:
                extra["doh_ip_works"] = doh_ip
                verdict.extra = extra
                verdict.discriminator = Discriminator.DNS_BASED
                return verdict

    verdict.extra = extra
    verdict.discriminator = Discriminator.INCONCLUSIVE
    return verdict
