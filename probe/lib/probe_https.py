"""HTTPS probe: TCP + TLS handshake, classify failure mode.

After a successful TLS handshake, optionally issues a minimal HTTP/1.1 GET
and scans the response body for RKN-style stub-page markers (e.g.
«доступ ограничен», «решению роскомнадзора»). This catches block patterns
where the TLS handshake itself completes (often via SNI-aware re-routing
to the operator's notice page) and the operator-served content is served
instead of the real site.

Stub-page scanning is enabled by default; disable with `read_body=False`
or by setting the `DPI_PROBE_HTTP_BODY=0` environment variable.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import socket
import ssl
import time
from typing import Any

from probe.lib.resolver import resolve_with_doh_check
from probe.lib.verdict import Discriminator, Verdict, VerdictCode

# Case-insensitive substrings observed in RKN / regulator stub pages served
# in place of blocked content. Match against lowercased response body.
# Sources: rkn-block-checker targets.py, manual review of stub pages
# documented in the dpi-tools-survey memory.
_STUB_MARKERS: tuple[str, ...] = (
    "доступ ограничен",
    "решению роскомнадзора",
    "решению генеральной прокуратуры",
    "blocked by rkn",
    "единый реестр запрещ",  # "единый реестр запрещенной [информации]"
    "запрещенной к распростран",
    "rkn.gov.ru",
    "роскомнадзор",
    "доступ к информационному ресурсу ограничен",
    "белгие",
    "доступ к ресурсу ограничен согласно решению",
    "қол жетімділік шектелген",
    "qamqor.gov.kz",
    "دسترسی به این سایت",
    "access to this website is forbidden",
    "payaam-internet.ir",
)

# Read at most this many response-body bytes when scanning for stub markers.
# A genuine stub page is ~1-3 KB; capping prevents pathological reads.
_BODY_SCAN_BYTES = 4096
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
    sni: str,
    timeout: float,
    expect_cert_fp: str | None = None,
    read_body: bool | None = None,
    stub_markers: tuple[str, ...] | None = None,
) -> Verdict:
    """Probe an HTTPS endpoint and classify the outcome.

    Args:
        dns: hostname or IP to resolve and connect to.
        port: TCP port (typically 443).
        sni: TLS SNI to present (may differ from dns).
        timeout: total budget in seconds for resolve + connect + handshake.
        expect_cert_fp: optional hex sha256 fingerprint; if set and mismatch → CERT_MISMATCH.
        read_body: if True, GET / after handshake and scan response body for
            stub markers. Defaults to env var DPI_PROBE_HTTP_BODY (1 → True,
            0 → False) or True if unset.
        stub_markers: optional override of the marker substring list. Defaults
            to `_STUB_MARKERS` (RU / RKN stub-page patterns). Useful for
            extending coverage to other jurisdictions (Iran, China, etc.) via
            the CLI / external wiring without modifying probe internals.
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
            reason="TCP connect timeout (no SYN-ACK)",
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
            reason=f"TCP RST during connect (port/IP-level block, no ClientHello sent): {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
            extra=resolve_extra,
        )
    except OSError as e:
        return Verdict(
            code=VerdictCode.ROUTE_BLACKHOLE,
            reason=f"TCP connect failed: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
            extra=resolve_extra,
        )

    # CERT_NONE / check_hostname=False: we want to observe whether the handshake
    # *completes* under DPI scrutiny, not whether the cert is trusted. MITM is
    # detected separately via the optional expect_cert_fp fingerprint check.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        tls = ctx.wrap_socket(sock, server_hostname=sni, do_handshake_on_connect=False)
        tls.do_handshake()
    except (ConnectionResetError, BrokenPipeError) as e:
        sock.close()
        return Verdict(
            code=VerdictCode.TLS_RESET_POST_HELLO,
            reason=f"RST during TLS handshake (likely SNI-DPI): {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            bytes_before_fail=0,
            resolved_ip=ip,
            extra=resolve_extra,
        )
    except (TimeoutError, ssl.SSLError) as e:
        sock.close()
        return Verdict(
            code=VerdictCode.TLS_TIMEOUT,
            reason=f"TLS handshake timeout / SSL error: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
            extra=resolve_extra,
        )
    except OSError as e:
        sock.close()
        return Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=f"Unexpected socket error during TLS: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
            resolved_ip=ip,
            extra=resolve_extra,
        )

    try:
        der = tls.getpeercert(binary_form=True) or b""
        cipher_info = tls.cipher()
        cipher_name = cipher_info[0] if cipher_info else None

        # Optional stub-page detection: after a clean TLS handshake some
        # blocking schemes return a regulator notice page over the real
        # connection. We send a minimal GET and scan the first few KB.
        do_read_body = read_body
        if do_read_body is None:
            do_read_body = os.environ.get("DPI_PROBE_HTTP_BODY", "1") != "0"

        stub_marker: str | None = None
        if do_read_body:
            # Body-scan must respect the overall probe budget — a slow
            # target dripping 1 byte/sec could otherwise extend the
            # probe past `timeout` while staying under the per-recv
            # deadline.
            remaining = max(0.5, timeout - (time.monotonic() - t0))
            markers = stub_markers if stub_markers is not None else _STUB_MARKERS
            stub_marker = _scan_for_stub(tls, sni, deadline=remaining, markers=markers)
    finally:
        with contextlib.suppress(OSError, ssl.SSLError):
            tls.unwrap()
        tls.close()

    latency_ms = (time.monotonic() - t0) * 1000.0
    extra: dict[str, object] = {
        **resolve_extra,
        "cipher": cipher_name,
        "cert_bytes": len(der),
    }

    if expect_cert_fp:
        actual_fp = hashlib.sha256(der).hexdigest()
        expected_fp = expect_cert_fp.replace(":", "").strip().lower()
        if actual_fp.lower() != expected_fp:
            return Verdict(
                code=VerdictCode.CERT_MISMATCH,
                reason=f"cert fingerprint mismatch (got {actual_fp})",
                latency_ms=latency_ms,
                resolved_ip=ip,
                extra=extra,
            )

    if stub_marker is not None:
        return Verdict(
            code=VerdictCode.HTTP_STUB,
            reason=f"RKN-style stub page detected (marker {stub_marker!r})",
            latency_ms=latency_ms,
            resolved_ip=ip,
            extra={**extra, "stub_marker": stub_marker},
        )

    return Verdict(
        code=VerdictCode.OK,
        reason="TLS handshake completed",
        latency_ms=latency_ms,
        resolved_ip=ip,
        extra=extra,
    )


def _run_wrong_sni_followup(ip: str, port: int, original_sni: str, timeout: float) -> Verdict:
    bogus = f"sni-control-{secrets.token_hex(4)}.example"
    if bogus == original_sni:
        bogus = f"sni-control-{secrets.token_hex(4)}.invalid"
    return probe(
        dns=ip,
        port=port,
        sni=bogus,
        timeout=timeout,
        read_body=False,
        _disable_followup=True,
    )


def probe(
    *,
    dns: str,
    port: int,
    sni: str,
    timeout: float,
    expect_cert_fp: str | None = None,
    read_body: bool | None = None,
    stub_markers: tuple[str, ...] | None = None,
    _disable_followup: bool = False,
) -> Verdict:
    started_at = time.monotonic()
    verdict = _probe_once(
        dns=dns,
        port=port,
        sni=sni,
        timeout=timeout,
        expect_cert_fp=expect_cert_fp,
        read_body=read_body,
        stub_markers=stub_markers,
    )
    if _disable_followup or verdict.code == VerdictCode.OK:
        return verdict

    extra = dict(verdict.extra)
    if verdict.resolved_ip:
        followup_timeout = _remaining_followup_timeout(started_at, timeout)
        if followup_timeout is not None:
            wrong_sni = _run_wrong_sni_followup(verdict.resolved_ip, port, sni, followup_timeout)
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
            doh_follow = probe(
                dns=doh_ip,
                port=port,
                sni=sni,
                timeout=followup_timeout,
                read_body=False,
                _disable_followup=True,
            )
            if doh_follow.code == VerdictCode.OK:
                extra["doh_ip_works"] = doh_ip
                verdict.extra = extra
                verdict.discriminator = Discriminator.DNS_BASED
                return verdict

    verdict.extra = extra
    verdict.discriminator = Discriminator.INCONCLUSIVE
    return verdict


def _scan_for_stub(
    tls: ssl.SSLSocket | Any,
    host: str,
    deadline: float,
    markers: tuple[str, ...] = _STUB_MARKERS,
) -> str | None:
    """Send a minimal HTTP GET, read first few KB, look for stub markers.

    `deadline` is the remaining wall-clock budget in seconds; the scan
    stops when either ``_BODY_SCAN_BYTES`` have been read OR the deadline
    elapses, whichever comes first.

    `tls` is duck-typed: needs `sendall`, `settimeout`, `recv`. Accepts
    `ssl.SSLSocket` in production and a stub fixture in tests.

    Returns the first matching marker substring, or None if no match. Any
    network or parsing failure returns None — stub detection is opportunistic;
    failure should never override a successful TLS verdict.
    """
    deadline_at = time.monotonic() + deadline
    try:
        request = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dpi-probe/1\r\n"
            "Accept: text/html\r\nConnection: close\r\n\r\n"
        )
        tls.sendall(request.encode("ascii"))
        buf = bytearray()
        while len(buf) < _BODY_SCAN_BYTES:
            remaining = deadline_at - time.monotonic()
            if remaining <= 0:
                break  # ran out of budget; partial scan is still useful
            # Cap each recv timeout at the remaining wall-clock budget.
            tls.settimeout(remaining)
            chunk = tls.recv(_BODY_SCAN_BYTES - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
    except (OSError, ssl.SSLError, ValueError):
        return None

    body_lower = bytes(buf).decode("utf-8", errors="ignore").lower()
    for marker in markers:
        if marker in body_lower:
            return marker
    return None
