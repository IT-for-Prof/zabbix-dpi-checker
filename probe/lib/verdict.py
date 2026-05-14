"""Verdict — the single shape every probe returns."""

from __future__ import annotations

import dataclasses
import json
from enum import StrEnum
from typing import Any


class VerdictCode(StrEnum):
    """Classification of probe outcome. Stable identifiers — referenced by Zabbix value maps."""

    OK = "OK"
    TCP_RST_HANDSHAKE = "TCP_RST_HANDSHAKE"  # RST during 3-way handshake — port/IP block
    TCP_RST_MID_STREAM = "TCP_RST_MID_STREAM"  # RST after some bytes — DPI mid-stream
    TLS_RESET_POST_HELLO = "TLS_RESET_POST_HELLO"  # RST after ClientHello — SNI-based DPI
    TLS_TIMEOUT = "TLS_TIMEOUT"  # mid-TLS hang — scrubber stalled
    CERT_MISMATCH = "CERT_MISMATCH"  # unexpected cert fingerprint — MITM suspicion
    BANNER_MISMATCH = "BANNER_MISMATCH"  # SMTP/SSH banner doesn't match expected pattern
    # Peer accepted TCP then closed cleanly without protocol response.
    REMOTE_HUNGUP_AFTER_CONNECT = "REMOTE_HUNGUP_AFTER_CONNECT"
    VANTAGE_UNAVAILABLE = "VANTAGE_UNAVAILABLE"  # control probe failed; measurement absent
    DNS_LIE = "DNS_LIE"  # system DNS disagrees with DoH for the target
    HTTP_STUB = "HTTP_STUB"  # RKN-style stub page served instead of real
    ROUTE_BLACKHOLE = "ROUTE_BLACKHOLE"  # ICMP admin-prohibited or no route
    PORT_FILTERED = "PORT_FILTERED"  # connect timeout on TCP, no RST — silent drop
    REMOTE_DOWN = "REMOTE_DOWN"  # connection refused — service down on host
    UDP_BLIND = "UDP_BLIND"  # UDP probe couldn't classify (no key etc.)
    ERROR_INTERNAL = "ERROR_INTERNAL"  # probe itself failed — bug or env issue


class Confidence(StrEnum):
    """Diagnostic confidence of a verdict.

    HIGH — smoking-gun signature with low false-positive rate (DNS mismatch,
       RST mid-stream, SNI reset, cert fingerprint mismatch, stub page).
    MEDIUM — typical block pattern but other causes possible (slow network,
       overloaded target firewall).
    LOW — weak or ambiguous (silent drop could be a flaky network).
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Discriminator(StrEnum):
    """Follow-up probe classification for where a block appears to live."""

    SNI_BASED = "sni_based"
    IP_BASED = "ip_based"
    DNS_BASED = "dns_based"
    INCONCLUSIVE = "inconclusive"


# Default confidence per verdict code. Probes generally accept this default
# but may override at construction time when context warrants it (e.g. a
# TCP_RST_HANDSHAKE from a target known to RST on policy is HIGH, not MEDIUM).
_DEFAULT_CONFIDENCE: dict[VerdictCode, Confidence] = {
    VerdictCode.OK: Confidence.HIGH,
    VerdictCode.DNS_LIE: Confidence.HIGH,
    VerdictCode.TCP_RST_MID_STREAM: Confidence.HIGH,
    VerdictCode.TLS_RESET_POST_HELLO: Confidence.HIGH,
    VerdictCode.CERT_MISMATCH: Confidence.HIGH,
    VerdictCode.HTTP_STUB: Confidence.HIGH,
    VerdictCode.TCP_RST_HANDSHAKE: Confidence.MEDIUM,
    VerdictCode.TLS_TIMEOUT: Confidence.MEDIUM,
    VerdictCode.BANNER_MISMATCH: Confidence.MEDIUM,
    VerdictCode.ROUTE_BLACKHOLE: Confidence.MEDIUM,
    VerdictCode.REMOTE_HUNGUP_AFTER_CONNECT: Confidence.LOW,
    VerdictCode.VANTAGE_UNAVAILABLE: Confidence.LOW,
    VerdictCode.PORT_FILTERED: Confidence.LOW,
    VerdictCode.REMOTE_DOWN: Confidence.LOW,
    VerdictCode.UDP_BLIND: Confidence.LOW,
    VerdictCode.ERROR_INTERNAL: Confidence.LOW,
}


@dataclasses.dataclass
class Verdict:
    """Probe result.

    Fields:
        code: classification (see VerdictCode docstrings).
        reason: human-readable explanation, shown in alerts.
        latency_ms: wall time from start of probe to terminal event, ms.
        bytes_before_fail: bytes read from peer before the failure (None if N/A or OK).
        resolved_ip: IP the probe actually connected to (after DNS resolution).
        extra: protocol-specific extras (TLS cipher, RDP version, etc.).
        confidence: diagnostic confidence; auto-derived from `code` if omitted.
    """

    code: VerdictCode
    reason: str
    latency_ms: float
    bytes_before_fail: int | None = None
    resolved_ip: str | None = None
    extra: dict[str, Any] = dataclasses.field(default_factory=dict)
    confidence: Confidence | None = None
    discriminator: Discriminator | None = None

    def __post_init__(self) -> None:
        if self.confidence is None:
            self.confidence = _DEFAULT_CONFIDENCE.get(self.code, Confidence.MEDIUM)

    def to_json(self) -> str:
        # bytes_before_fail emitted as 0 (not null) so Zabbix UNSIGNED dependent
        # items don't fail JSON-to-int conversion on OK verdicts.
        bytes_n = self.bytes_before_fail if self.bytes_before_fail is not None else 0
        ip = self.resolved_ip if self.resolved_ip is not None else ""
        payload: dict[str, Any] = {
            "verdict": self.code.value,
            "reason": self.reason,
            "latency_ms": self.latency_ms,
            "bytes_before_fail": bytes_n,
            "resolved_ip": ip,
            "confidence": (self.confidence or Confidence.MEDIUM).value,
            "extra": self.extra,
        }
        if self.discriminator is not None:
            payload["discriminator"] = self.discriminator.value
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
