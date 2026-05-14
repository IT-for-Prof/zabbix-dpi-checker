"""Tests for probe_tspu_liveness: aggregate known-blocked-SNI probe."""

from __future__ import annotations

import pytest

from probe.lib import probe_tspu_liveness
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
