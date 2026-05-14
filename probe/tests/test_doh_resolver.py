"""Tests for the DoH-over-HTTPS resolver helper.

We do not hit a real DoH endpoint; urllib.request.urlopen is monkeypatched
to return canned JSON responses (success, empty answer, malformed JSON,
URL error). The cross-checking logic that compares DoH vs system resolver
lives in test_resolver.py.
"""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from probe.lib import doh_resolver


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._buf = io.BytesIO(payload)

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_: Any) -> None:
        self._buf.close()

    def read(self) -> bytes:
        return self._buf.read()


def _patch_urlopen(monkeypatch: pytest.MonkeyPatch, payload: bytes | Exception) -> None:
    def _fake_urlopen(req, timeout, context):  # type: ignore[no-untyped-def]
        if isinstance(payload, Exception):
            raise payload
        return _FakeResponse(payload)

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)


def _doh_payload(a_records: list[str]) -> bytes:
    return json.dumps(
        {"Answer": [{"name": "x", "type": 1, "TTL": 60, "data": ip} for ip in a_records]}
    ).encode("ascii")


def test_resolve_doh_returns_ips_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_urlopen(monkeypatch, _doh_payload(["1.2.3.4", "5.6.7.8"]))
    ips = doh_resolver.resolve_doh("example.com")
    assert ips == frozenset({"1.2.3.4", "5.6.7.8"})


def test_resolve_doh_returns_empty_when_no_a_records(monkeypatch: pytest.MonkeyPatch) -> None:
    """If DoH responds with an Answer array that has no type=1 (A) entries — empty."""
    payload = json.dumps(
        {"Answer": [{"name": "x", "type": 28, "TTL": 60, "data": "::1"}]}  # AAAA only
    ).encode("ascii")
    _patch_urlopen(monkeypatch, payload)
    assert doh_resolver.resolve_doh("example.com") == frozenset()


def test_resolve_doh_returns_empty_on_url_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """DoH endpoint unreachable (blocked / network failure) → empty set, never raises."""
    _patch_urlopen(monkeypatch, urllib.error.URLError("connection refused"))
    assert doh_resolver.resolve_doh("example.com") == frozenset()


def test_resolve_doh_returns_empty_on_malformed_json(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_urlopen(monkeypatch, b"<html>not json</html>")
    assert doh_resolver.resolve_doh("example.com") == frozenset()


def test_resolve_doh_returns_empty_when_answer_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """DoH responses with no Answer key (NXDOMAIN-like) → empty, not an error."""
    _patch_urlopen(monkeypatch, b'{"Status": 3}')
    assert doh_resolver.resolve_doh("example.com") == frozenset()


def test_resolve_doh_skips_malformed_answer_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer entries lacking required fields are silently dropped."""
    payload = json.dumps(
        {
            "Answer": [
                {"name": "x", "type": 1, "data": "1.2.3.4"},  # good
                {"name": "x", "type": 1},  # missing data
                "not a dict",  # wrong shape
                {"name": "x", "type": 5, "data": "alias.com"},  # CNAME, not A
            ]
        }
    ).encode("ascii")
    _patch_urlopen(monkeypatch, payload)
    assert doh_resolver.resolve_doh("example.com") == frozenset({"1.2.3.4"})
