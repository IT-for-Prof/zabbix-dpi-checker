from __future__ import annotations

from unittest.mock import patch

import pytest

from probe.lib.resolver import (
    DohCheckResult,
    ResolveError,
    resolve_a,
    resolve_with_doh_check,
)

# silence unused-import warnings — DohCheckResult is part of the public API
_ = DohCheckResult


def test_resolve_a_returns_ip_for_localhost() -> None:
    ip, latency_ms = resolve_a("localhost", timeout=2.0)
    assert ip in {"127.0.0.1", "::1"}
    assert latency_ms >= 0.0


def test_resolve_a_raises_on_unresolvable() -> None:
    with pytest.raises(ResolveError):
        resolve_a("nonexistent.invalid", timeout=2.0)


def test_resolve_a_passes_ip_through_unchanged() -> None:
    ip, latency_ms = resolve_a("203.0.113.42", timeout=2.0)
    assert ip == "203.0.113.42"
    assert latency_ms == 0.0


def test_resolve_a_socket_gaierror_raises_resolveerror() -> None:
    with (
        patch("probe.lib.resolver.socket.getaddrinfo", side_effect=OSError("simulated")),
        pytest.raises(ResolveError),
    ):
        resolve_a("example.com", timeout=2.0)


def test_resolve_with_doh_check_passes_ip_literal_through() -> None:
    """IP literals skip DNS entirely → empty DoH set, no mismatch claim."""
    res = resolve_with_doh_check("203.0.113.42", timeout=2.0)
    assert res.ip == "203.0.113.42"
    assert res.latency_ms == 0.0
    assert res.doh_ips == frozenset()
    assert res.mismatch is False
    assert res.system_error is None


def test_resolve_with_doh_check_no_mismatch_when_doh_returns_empty() -> None:
    """DoH blocked / unreachable → no mismatch claim even if system returns an IP."""
    with patch("probe.lib.resolver.resolve_doh", return_value=frozenset()):
        res = resolve_with_doh_check("localhost", timeout=2.0)
    assert res.ip == "127.0.0.1"  # AF_INET hint forces IPv4
    assert res.doh_ips == frozenset()
    assert res.mismatch is False


def test_resolve_with_doh_check_no_mismatch_when_system_ip_in_doh_set() -> None:
    """System IP matches one of the DoH-returned IPs → no mismatch."""
    with patch(
        "probe.lib.resolver.resolve_doh",
        return_value=frozenset({"127.0.0.1", "1.2.3.4"}),
    ):
        res = resolve_with_doh_check("localhost", timeout=2.0)
    assert res.ip == "127.0.0.1"
    assert "127.0.0.1" in res.doh_ips
    assert res.mismatch is False


def test_resolve_with_doh_check_flags_mismatch_when_system_ip_not_in_doh_set() -> None:
    """system IP ∉ DoH set → mismatch=True. NOTE: mismatch is informational
    only; CDN edge variance routinely produces this. Callers (probes) MUST
    NOT auto-fire DNS_LIE on mismatch alone — see resolver.py docstring."""
    with patch(
        "probe.lib.resolver.resolve_doh",
        return_value=frozenset({"1.2.3.4", "5.6.7.8"}),
    ):
        res = resolve_with_doh_check("localhost", timeout=2.0)
    assert res.ip == "127.0.0.1"
    assert res.ip not in res.doh_ips
    assert res.mismatch is True


def test_resolve_with_doh_check_returns_system_error_instead_of_raising() -> None:
    """When system getaddrinfo fails, return DohCheckResult with ip=None and
    system_error populated. DoH lookup still runs in parallel — the caller
    can detect the "system fails + DoH succeeds" pattern (genuine DNS_LIE)
    vs "both fail" (likely NXDOMAIN / typo)."""
    with (
        patch("probe.lib.resolver.socket.getaddrinfo", side_effect=OSError("sim")),
        patch("probe.lib.resolver.resolve_doh", return_value=frozenset({"1.2.3.4"})),
    ):
        res = resolve_with_doh_check("blocked.example.com", timeout=1.0)
    assert res.ip is None
    assert res.system_error is not None
    assert isinstance(res.system_error, ResolveError)
    assert res.doh_ips == frozenset({"1.2.3.4"})
    assert res.mismatch is False  # mismatch meaningless when ip is None


def test_resolve_a_requests_ipv4_only() -> None:
    """getaddrinfo MUST be called with family=AF_INET so the system resolver
    never returns an IPv6 address that:
      (a) probes can't connect to (sockets are AF_INET), and
      (b) the IPv4-only DoH cross-check would treat as a guaranteed mismatch,
          producing a false-positive DNS_LIE.
    """
    import socket as socket_mod

    captured_kwargs: dict[str, object] = {}

    def fake_getaddrinfo(host, port, **kwargs):  # type: ignore[no-untyped-def]
        captured_kwargs.update(kwargs)
        return [(socket_mod.AF_INET, socket_mod.SOCK_STREAM, 0, "", ("127.0.0.1", 0))]

    with patch("probe.lib.resolver.socket.getaddrinfo", side_effect=fake_getaddrinfo):
        ip, _ = resolve_a("example.com", timeout=2.0)
    assert ip == "127.0.0.1"
    assert captured_kwargs.get("family") == socket_mod.AF_INET, (
        f"resolve_a must hint AF_INET; got kwargs={captured_kwargs}"
    )
