from __future__ import annotations

import json

from probe.lib.verdict import (
    _DEFAULT_CONFIDENCE,
    Confidence,
    Discriminator,
    Verdict,
    VerdictCode,
)


def test_verdict_serializes_all_fields_to_json() -> None:
    v = Verdict(
        code=VerdictCode.OK,
        reason="handshake completed",
        latency_ms=12.3,
        bytes_before_fail=None,
        resolved_ip="1.2.3.4",
        extra={"cipher": "TLS_AES_128_GCM_SHA256"},
    )
    blob = v.to_json()
    parsed = json.loads(blob)
    # bytes_before_fail and resolved_ip get sanitized for Zabbix-friendly types:
    # null → 0 (UNSIGNED items) / "" (CHAR items).
    # confidence is auto-derived from code (OK → HIGH).
    assert parsed == {
        "verdict": "OK",
        "reason": "handshake completed",
        "latency_ms": 12.3,
        "bytes_before_fail": 0,
        "resolved_ip": "1.2.3.4",
        "confidence": "HIGH",
        "extra": {"cipher": "TLS_AES_128_GCM_SHA256"},
    }


def test_verdict_null_resolved_ip_becomes_empty_string() -> None:
    v = Verdict(code=VerdictCode.DNS_LIE, reason="x", latency_ms=1.0)
    parsed = json.loads(v.to_json())
    assert parsed["resolved_ip"] == ""
    assert parsed["bytes_before_fail"] == 0


def test_verdict_code_is_str_enum_with_expected_values() -> None:
    expected = {
        "OK",
        "TCP_RST_HANDSHAKE",
        "TCP_RST_MID_STREAM",
        "TLS_RESET_POST_HELLO",
        "TLS_TIMEOUT",
        "CERT_MISMATCH",
        "BANNER_MISMATCH",
        "REMOTE_HUNGUP_AFTER_CONNECT",
        "VANTAGE_UNAVAILABLE",
        "DNS_LIE",
        "HTTP_STUB",
        "ROUTE_BLACKHOLE",
        "PORT_FILTERED",
        "REMOTE_DOWN",
        "UDP_BLIND",
        "ERROR_INTERNAL",
        "TSPU_ACTIVE",
        "TSPU_BYPASS_OK",
        "THROTTLE_DETECTED",
        "WG_HANDSHAKE_PASS",
        "WG_HANDSHAKE_BLOCKED",
    }
    assert {c.value for c in VerdictCode} == expected


def test_verdict_default_extra_is_empty_dict_not_shared() -> None:
    a = Verdict(code=VerdictCode.OK, reason="x", latency_ms=1.0)
    b = Verdict(code=VerdictCode.OK, reason="y", latency_ms=2.0)
    a.extra["k"] = 1
    assert "k" not in b.extra


def test_verdict_confidence_auto_derived_from_code() -> None:
    """Each verdict code maps to a default confidence; OK/DNS_LIE/HTTP_STUB → HIGH,
    PORT_FILTERED/REMOTE_DOWN → LOW, BANNER_MISMATCH/TLS_TIMEOUT → MEDIUM.
    """
    high = {
        VerdictCode.OK,
        VerdictCode.DNS_LIE,
        VerdictCode.HTTP_STUB,
        VerdictCode.TCP_RST_MID_STREAM,
        VerdictCode.TLS_RESET_POST_HELLO,
        VerdictCode.CERT_MISMATCH,
    }
    low = {
        VerdictCode.PORT_FILTERED,
        VerdictCode.REMOTE_DOWN,
        VerdictCode.UDP_BLIND,
        VerdictCode.ERROR_INTERNAL,
    }
    for code in high:
        v = Verdict(code=code, reason="x", latency_ms=0.0)
        assert v.confidence == Confidence.HIGH, f"{code} should default HIGH"
    for code in low:
        v = Verdict(code=code, reason="x", latency_ms=0.0)
        assert v.confidence == Confidence.LOW, f"{code} should default LOW"
    # MEDIUM bucket includes TCP_RST_HANDSHAKE, TLS_TIMEOUT, BANNER_MISMATCH, ROUTE_BLACKHOLE
    for code in (
        VerdictCode.TCP_RST_HANDSHAKE,
        VerdictCode.TLS_TIMEOUT,
        VerdictCode.BANNER_MISMATCH,
        VerdictCode.ROUTE_BLACKHOLE,
    ):
        v = Verdict(code=code, reason="x", latency_ms=0.0)
        assert v.confidence == Confidence.MEDIUM, f"{code} should default MEDIUM"


def test_verdict_explicit_confidence_overrides_default() -> None:
    """Probes can override the default mapping when context warrants."""
    v = Verdict(
        code=VerdictCode.TCP_RST_HANDSHAKE,  # default MEDIUM
        reason="known-blocked target",
        latency_ms=1.0,
        confidence=Confidence.HIGH,
    )
    assert v.confidence == Confidence.HIGH
    parsed = json.loads(v.to_json())
    assert parsed["confidence"] == "HIGH"


def test_remote_hungup_after_connect_is_a_verdict_code() -> None:
    assert "REMOTE_HUNGUP_AFTER_CONNECT" in {c.value for c in VerdictCode}
    assert _DEFAULT_CONFIDENCE[VerdictCode.REMOTE_HUNGUP_AFTER_CONNECT] == Confidence.LOW


def test_vantage_unavailable_is_a_verdict_code() -> None:
    assert "VANTAGE_UNAVAILABLE" in {c.value for c in VerdictCode}
    assert _DEFAULT_CONFIDENCE[VerdictCode.VANTAGE_UNAVAILABLE] == Confidence.LOW


def test_verdict_has_optional_discriminator_field() -> None:
    v = Verdict(code=VerdictCode.TLS_TIMEOUT, reason="x", latency_ms=1.0)
    assert v.discriminator is None

    v2 = Verdict(
        code=VerdictCode.TLS_TIMEOUT,
        reason="x",
        latency_ms=1.0,
        discriminator=Discriminator.SNI_BASED,
    )
    assert v2.discriminator == Discriminator.SNI_BASED
    payload = json.loads(v2.to_json())
    assert payload["discriminator"] == "sni_based"


def test_discriminator_values() -> None:
    assert {d.value for d in Discriminator} == {
        "sni_based",
        "ip_based",
        "dns_based",
        "inconclusive",
    }


def test_new_verdict_codes_have_default_confidence() -> None:
    expected = {
        VerdictCode.TSPU_ACTIVE: Confidence.HIGH,
        VerdictCode.TSPU_BYPASS_OK: Confidence.HIGH,
        VerdictCode.THROTTLE_DETECTED: Confidence.HIGH,
        VerdictCode.WG_HANDSHAKE_PASS: Confidence.HIGH,
        VerdictCode.WG_HANDSHAKE_BLOCKED: Confidence.MEDIUM,
    }
    for code, conf in expected.items():
        v = Verdict(code=code, reason="x", latency_ms=1.0)
        assert v.confidence == conf, f"{code}: expected {conf}, got {v.confidence}"


def test_new_verdict_codes_serialize_to_string_name() -> None:
    payload = json.loads(
        Verdict(
            code=VerdictCode.TSPU_ACTIVE,
            reason="r",
            latency_ms=2.0,
        ).to_json()
    )
    assert payload["verdict"] == "TSPU_ACTIVE"
    assert payload["confidence"] == "HIGH"
