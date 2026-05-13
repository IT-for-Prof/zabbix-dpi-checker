"""RD Gateway probe — structurally a TLS handshake (port 443 + RDGW path).

RDGW carries RDP over HTTPS; the censorship-visible surface is identical to HTTPS.
"""

from __future__ import annotations

from probe.lib import probe_https
from probe.lib.verdict import Verdict


def probe(*, dns: str, port: int, sni: str | None, timeout: float) -> Verdict:
    """Probe an RD Gateway endpoint. Default SNI = dns if not supplied."""
    return probe_https.probe(
        dns=dns,
        port=port,
        sni=sni or dns,
        timeout=timeout,
    )
