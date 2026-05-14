"""Tests for probe_tspu_liveness: aggregate known-blocked-SNI probe."""

from __future__ import annotations

import pytest

from probe.lib import probe_https, probe_tspu_liveness
from probe.lib.verdict import Verdict, VerdictCode


def test_aggregate_all_blocked_returns_tspu_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_results = iter(
        [
            Verdict(VerdictCode.TLS_TIMEOUT, "timeout", 6000.0),
            Verdict(VerdictCode.TLS_RESET_POST_HELLO, "RST", 50.0),
            Verdict(VerdictCode.TLS_TIMEOUT, "timeout", 6000.0),
        ]
    )
    monkeypatch.setattr(
        probe_tspu_liveness,
        "_probe_one",
        lambda sni, timeout: next(fake_results),
    )
    v = probe_tspu_liveness.probe(
        sni_list=("rutracker.org", "x.com", "linkedin.com"),
        timeout=10.0,
    )
    assert v.code == VerdictCode.TSPU_ACTIVE
    assert v.extra["blocked_count"] == 3
    assert v.extra["tested_count"] == 3


def test_aggregate_all_clear_returns_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_results = iter([Verdict(VerdictCode.OK, "ok", 50.0) for _ in range(3)])
    monkeypatch.setattr(
        probe_tspu_liveness,
        "_probe_one",
        lambda sni, timeout: next(fake_results),
    )
    v = probe_tspu_liveness.probe(
        sni_list=("rutracker.org", "x.com", "linkedin.com"),
        timeout=10.0,
    )
    assert v.code == VerdictCode.OK
    assert v.extra["blocked_count"] == 0


def test_aggregate_one_blocked_is_insufficient(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_results = iter(
        [
            Verdict(VerdictCode.TLS_TIMEOUT, "timeout", 6000.0),
            Verdict(VerdictCode.OK, "ok", 30.0),
            Verdict(VerdictCode.OK, "ok", 40.0),
        ]
    )
    monkeypatch.setattr(
        probe_tspu_liveness,
        "_probe_one",
        lambda sni, timeout: next(fake_results),
    )
    v = probe_tspu_liveness.probe(
        sni_list=("rutracker.org", "x.com", "linkedin.com"),
        timeout=10.0,
    )
    assert v.code == VerdictCode.OK
    assert v.extra["blocked_count"] == 1


def test_probe_one_enables_body_scan_for_http_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_https_probe(**kwargs: object) -> Verdict:
        calls.append(kwargs)
        return Verdict(VerdictCode.HTTP_STUB, "stub", 10.0)

    monkeypatch.setattr(probe_https, "probe", fake_https_probe)
    v = probe_tspu_liveness._probe_one("blocked.example", 3.0)
    assert v.code == VerdictCode.HTTP_STUB
    assert calls[0]["read_body"] is True


def test_quorum_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """DPI_TSPU_LIVENESS_QUORUM=1 → single blocked SNI is enough."""
    fake = iter(
        [
            Verdict(VerdictCode.TLS_TIMEOUT, "timeout", 6000.0),
            Verdict(VerdictCode.OK, "ok", 30.0),
            Verdict(VerdictCode.OK, "ok", 40.0),
        ]
    )
    monkeypatch.setattr(
        probe_tspu_liveness, "_probe_one", lambda sni, timeout: next(fake)
    )
    monkeypatch.setenv("DPI_TSPU_LIVENESS_QUORUM", "1")
    v = probe_tspu_liveness.probe(
        sni_list=("rutracker.org", "x.com", "www.linkedin.com"), timeout=10.0
    )
    assert v.code == VerdictCode.TSPU_ACTIVE
    assert v.extra["quorum"] == 1


def test_quorum_ratio_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """DPI_TSPU_LIVENESS_QUORUM_RATIO=0.6 over 5 SNIs → quorum=3."""
    fake = iter(
        [
            Verdict(VerdictCode.TLS_TIMEOUT, "timeout", 6000.0),
            Verdict(VerdictCode.TLS_TIMEOUT, "timeout", 6000.0),
            Verdict(VerdictCode.OK, "ok", 30.0),
            Verdict(VerdictCode.OK, "ok", 40.0),
            Verdict(VerdictCode.OK, "ok", 50.0),
        ]
    )
    monkeypatch.setattr(
        probe_tspu_liveness, "_probe_one", lambda sni, timeout: next(fake)
    )
    monkeypatch.setenv("DPI_TSPU_LIVENESS_QUORUM_RATIO", "0.6")
    v = probe_tspu_liveness.probe(
        sni_list=("a", "b", "c", "d", "e"), timeout=20.0
    )
    # 2 blocked < quorum 3 → OK
    assert v.code == VerdictCode.OK
    assert v.extra["quorum"] == 3
