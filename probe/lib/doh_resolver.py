"""DNS-over-HTTPS resolver for cross-checking the system resolver.

Used to detect DNS poisoning / state-level DNS interception: when the system
resolver and a public DoH endpoint disagree on a hostname's A records, that's
strong evidence of upstream DNS manipulation rather than network failure.

Empty result is ambiguous (DoH endpoint itself may be blocked) — callers MUST
NOT treat empty-set as evidence of poisoning. Mismatch evidence is only
actionable when the DoH set is non-empty AND differs from the system IP.

Cloudflare DoH (1.1.1.1) is used as the reference resolver. It is widely
available and accepts the simple `application/dns-json` GET form, which keeps
this module stdlib-only.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

# Public Cloudflare DoH endpoint. JSON API per RFC 8484 §6 / Cloudflare docs.
_DOH_URL = "https://1.1.1.1/dns-query"

# DNS record type for A (IPv4) — see RFC 1035 §3.2.2.
_RR_TYPE_A = 1


def resolve_doh(host: str, *, timeout: float = 5.0) -> frozenset[str]:
    """Resolve A records for ``host`` via DNS-over-HTTPS.

    Returns a frozenset of IPv4 address strings. On any failure — network
    error, blocked DoH endpoint, malformed response, no A answers — returns
    an empty frozenset. Callers should treat empty-set as "no evidence
    available", not as poisoning evidence.
    """
    req = urllib.request.Request(
        f"{_DOH_URL}?name={host}&type=A",
        headers={"Accept": "application/dns-json"},
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return frozenset()
    answers = data.get("Answer") or []
    return frozenset(
        a["data"]
        for a in answers
        if isinstance(a, dict) and a.get("type") == _RR_TYPE_A and "data" in a
    )
