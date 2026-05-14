"""Aggregate known-blocked SNI probe for TSPU liveness."""

from __future__ import annotations

import os
import time

from probe.lib import probe_https
from probe.lib.verdict import Verdict, VerdictCode

_DEFAULT_SNIS = ("rutracker.org", "x.com", "www.linkedin.com")
_BLOCKED_CODES = frozenset(
    {
        VerdictCode.TLS_TIMEOUT,
        VerdictCode.TLS_RESET_POST_HELLO,
        VerdictCode.TCP_RST_MID_STREAM,
        VerdictCode.DNS_LIE,
        VerdictCode.HTTP_STUB,
    }
)
_MIN_BLOCKED_FOR_ACTIVE = 2


def _resolve_snis() -> tuple[str, ...]:
    raw = os.environ.get("DPI_TSPU_LIVENESS_SNIS", "")
    if not raw:
        return _DEFAULT_SNIS
    return tuple(sni.strip() for sni in raw.split(",") if sni.strip())


def _probe_one(sni: str, timeout: float) -> Verdict:
    return probe_https.probe(dns=sni, port=443, sni=sni, timeout=timeout, read_body=True)


def probe(
    *,
    sni_list: tuple[str, ...] | None = None,
    timeout: float = 30.0,
) -> Verdict:
    """Probe canary SNIs and return TSPU_ACTIVE when at least two are blocked."""
    t0 = time.monotonic()
    snis = sni_list or _resolve_snis()
    if not snis:
        return Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason="no SNIs configured",
            latency_ms=0.0,
        )

    per_sni_timeout = timeout / len(snis)
    results: list[tuple[str, Verdict]] = []
    blocked = 0
    for sni in snis:
        v = _probe_one(sni, per_sni_timeout)
        results.append((sni, v))
        if v.code in _BLOCKED_CODES:
            blocked += 1

    latency_ms = (time.monotonic() - t0) * 1000.0
    summary = {sni: v.code.value for sni, v in results}
    extra = {
        "blocked_count": blocked,
        "tested_count": len(snis),
        "per_sni": summary,
    }
    if blocked >= _MIN_BLOCKED_FOR_ACTIVE:
        return Verdict(
            code=VerdictCode.TSPU_ACTIVE,
            reason=f"{blocked}/{len(snis)} canary SNIs blocked",
            latency_ms=latency_ms,
            extra=extra,
        )
    return Verdict(
        code=VerdictCode.OK,
        reason=f"{blocked}/{len(snis)} canary SNIs blocked",
        latency_ms=latency_ms,
        extra=extra,
    )
