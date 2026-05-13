"""DNS resolution wrapper that records latency and passes raw IPs through.

The timeout is enforced via threading: `getaddrinfo` runs in a worker thread
and we abandon it after `timeout` seconds. Mutating `socket.setdefaulttimeout`
would race with concurrent probes, so we avoid it.

`resolve_with_doh_check` additionally runs a DoH lookup in parallel and
returns a `mismatch` flag when the system resolver returns an IP that does
not appear in the DoH answer set — a strong indicator of DNS-level
interception (RKN-style poisoning) rather than connectivity failure.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import socket
import threading
import time

from probe.lib.doh_resolver import resolve_doh


class ResolveError(RuntimeError):
    """DNS lookup failed within the given timeout."""


def resolve_a(host: str, timeout: float) -> tuple[str, float]:
    """Resolve `host` to one IPv4 (or IPv6) address using the system resolver.

    If `host` is already an IP, returns it unchanged with latency=0.0.
    Raises ResolveError if the lookup fails or times out.

    Returns:
        (ip, latency_ms)
    """
    try:
        ipaddress.ip_address(host)
        return host, 0.0
    except ValueError:
        pass

    result: dict[str, object] = {}

    def _lookup() -> None:
        try:
            # Constrain to IPv4 (AF_INET): probes always create AF_INET sockets,
            # and the DoH cross-check only queries type=A. Without this hint,
            # `getaddrinfo` on IPv6-preferring hosts (`::1` for localhost on
            # GitHub-hosted runners, modern dual-stack RU/CIS networks) can
            # return an AAAA first, which (a) the probe can't connect to via
            # AF_INET, and (b) would never match the IPv4-only DoH set —
            # producing a guaranteed false-positive DNS_LIE.
            result["infos"] = socket.getaddrinfo(
                host, None, family=socket.AF_INET, proto=socket.IPPROTO_TCP
            )
        except OSError as e:
            result["error"] = e

    t0 = time.monotonic()
    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(timeout=timeout)
    latency_ms = (time.monotonic() - t0) * 1000.0

    if t.is_alive():
        raise ResolveError(f"DNS resolution timed out after {timeout}s for {host!r}")
    if "error" in result:
        err = result["error"]
        raise ResolveError(f"DNS resolution failed for {host!r}: {err}") from err  # type: ignore[misc]
    infos = result.get("infos") or []
    if not infos:
        raise ResolveError(f"DNS resolution returned no answers for {host!r}")
    ip = str(infos[0][4][0])  # type: ignore[index]
    return ip, latency_ms


@dataclasses.dataclass(frozen=True)
class DohCheckResult:
    """Outcome of `resolve_with_doh_check`.

    `ip`           — system-resolver IPv4 or None if it failed
    `latency_ms`   — system-resolver wall time
    `doh_ips`      — DoH (Cloudflare) A-record set; empty if DoH unreachable
    `mismatch`     — True iff system IP exists and isn't in doh_ips and doh_ips
                     is non-empty. **Informational signal only** — CDN-fronted
                     services routinely produce mismatch through edge variance,
                     so callers MUST NOT treat this alone as evidence of DNS
                     interception. Treat as forensic context for `extra`.
    `system_error` — explanation when `ip` is None; None on success.
    """

    ip: str | None
    latency_ms: float
    doh_ips: frozenset[str]
    mismatch: bool
    system_error: ResolveError | None


def resolve_with_doh_check(host: str, timeout: float) -> DohCheckResult:
    """Run system getaddrinfo and Cloudflare DoH in parallel.

    Does NOT raise: a system-resolver failure is reported via `system_error`
    on the result object so the caller can correlate with `doh_ips` (e.g.
    "system fails AND DoH succeeds → likely state-level DNS sinkhole").

    For IP literals returns the IP unchanged with empty DoH set.
    """
    if _is_ip_literal(host):
        return DohCheckResult(host, 0.0, frozenset(), False, None)

    system_result: dict[str, object] = {}

    def _system() -> None:
        try:
            ip_, ms_ = resolve_a(host, timeout=timeout)
            system_result["ip"] = ip_
            system_result["ms"] = ms_
        except ResolveError as exc:
            system_result["err"] = exc

    doh_result: dict[str, frozenset[str]] = {"ips": frozenset()}

    def _doh() -> None:
        # DoH timeout capped at 5s — we'd rather miss the DoH signal than
        # slow down the probe to the system resolver's full timeout budget.
        doh_result["ips"] = resolve_doh(host, timeout=min(timeout, 5.0))

    t_sys = threading.Thread(target=_system, daemon=True)
    t_doh = threading.Thread(target=_doh, daemon=True)
    t_sys.start()
    t_doh.start()
    t_sys.join(timeout=timeout)
    t_doh.join(timeout=min(timeout, 5.0))

    doh_ips = doh_result["ips"]

    if "err" in system_result:
        return DohCheckResult(None, 0.0, doh_ips, False, system_result["err"])  # type: ignore[arg-type]
    if "ip" not in system_result:
        err = ResolveError(f"System DNS for {host!r} did not complete in {timeout}s")
        return DohCheckResult(None, 0.0, doh_ips, False, err)

    ip = str(system_result["ip"])
    ms = float(system_result["ms"])  # type: ignore[arg-type]
    mismatch = bool(doh_ips) and ip not in doh_ips
    return DohCheckResult(ip, ms, doh_ips, mismatch, None)


def _is_ip_literal(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
