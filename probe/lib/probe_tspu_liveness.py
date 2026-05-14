"""Aggregate known-blocked SNI probe for TSPU liveness."""

from __future__ import annotations

import math
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
_MIN_BLOCKED_DEFAULT = 2


def _resolve_snis() -> tuple[str, ...]:
    raw = os.environ.get("DPI_TSPU_LIVENESS_SNIS", "")
    if not raw:
        return _DEFAULT_SNIS
    return tuple(sni.strip() for sni in raw.split(",") if sni.strip())


def _quorum(n_snis: int) -> int:
    """How many blocked SNIs constitute TSPU_ACTIVE.

    Override priority: absolute env var > ratio env var > default
    `max(2, ceil(n_snis * 0.5))`. The default scales sensibly when an
    operator configures 5 SNIs (quorum 3) or 2 SNIs (quorum 2 = unanimous).
    """
    abs_q = os.environ.get("DPI_TSPU_LIVENESS_QUORUM", "")
    if abs_q:
        try:
            return max(1, min(n_snis, int(abs_q)))
        except ValueError:
            pass
    ratio_q = os.environ.get("DPI_TSPU_LIVENESS_QUORUM_RATIO", "")
    if ratio_q:
        try:
            r = float(ratio_q)
            if 0.0 < r <= 1.0:
                return max(1, math.ceil(n_snis * r))
        except ValueError:
            pass
    return max(_MIN_BLOCKED_DEFAULT, math.ceil(n_snis * 0.5))


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
    quorum = _quorum(len(snis))
    summary = {sni: v.code.value for sni, v in results}
    extra = {
        "blocked_count": blocked,
        "tested_count": len(snis),
        "quorum": quorum,
        "per_sni": summary,
    }
    if blocked >= quorum:
        return Verdict(
            code=VerdictCode.TSPU_ACTIVE,
            reason=f"{blocked}/{len(snis)} canary SNIs blocked (quorum={quorum})",
            latency_ms=latency_ms,
            extra=extra,
        )
    return Verdict(
        code=VerdictCode.OK,
        reason=f"{blocked}/{len(snis)} canary SNIs blocked (below quorum={quorum})",
        latency_ms=latency_ms,
        extra=extra,
    )
