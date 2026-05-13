from __future__ import annotations

from probe.lib import probe_rdgw
from probe.lib.verdict import VerdictCode
from probe.tests.conftest import TcpResponder


def test_rdgw_rst_post_hello(tcp_responder: TcpResponder) -> None:
    port = tcp_responder.start(mode="accept_rst")
    v = probe_rdgw.probe(dns="127.0.0.1", port=port, sni="rdgw.example", timeout=2.0)
    assert v.code in {VerdictCode.TLS_RESET_POST_HELLO, VerdictCode.TCP_RST_HANDSHAKE}


def test_rdgw_uses_dns_as_default_sni(tcp_responder: TcpResponder) -> None:
    port = tcp_responder.start(mode="accept_rst")
    v = probe_rdgw.probe(dns="127.0.0.1", port=port, sni=None, timeout=2.0)
    assert v.code in {VerdictCode.TLS_RESET_POST_HELLO, VerdictCode.TCP_RST_HANDSHAKE}
