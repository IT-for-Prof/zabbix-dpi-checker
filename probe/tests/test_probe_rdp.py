from __future__ import annotations

import socket
import threading

from probe.lib import probe_rdp
from probe.lib.verdict import VerdictCode
from probe.tests.conftest import TcpResponder

# A valid X.224 Connection Confirm — TPKT v3, length 11, CC PDU type 0xD0
X224_CC_OK = bytes.fromhex("0300000b06d00000123400")


def test_rdp_x224_confirm_ok(tcp_responder: TcpResponder) -> None:
    port = tcp_responder.start(mode="accept_read_send", read_bytes=11, response=X224_CC_OK)
    v = probe_rdp.probe(dns="127.0.0.1", port=port, cookie="testuser", timeout=2.0)
    assert v.code == VerdictCode.OK


def test_rdp_rst_after_x224_request(tcp_responder: TcpResponder) -> None:
    """DPI signature for RDP: RST after the X.224 Request is sent."""
    port = tcp_responder.start(mode="accept_rst")
    v = probe_rdp.probe(dns="127.0.0.1", port=port, cookie="testuser", timeout=2.0)
    assert v.code in {VerdictCode.TCP_RST_HANDSHAKE, VerdictCode.TCP_RST_MID_STREAM}


def test_rdp_garbage_response_is_banner_mismatch(tcp_responder: TcpResponder) -> None:
    garbage = b"HTTP/1.0 200 OK\r\n\r\n"
    port = tcp_responder.start(mode="accept_read_send", read_bytes=11, response=garbage)
    v = probe_rdp.probe(dns="127.0.0.1", port=port, cookie="testuser", timeout=2.0)
    assert v.code == VerdictCode.BANNER_MISMATCH


def test_rdp_empty_response_classifies_as_remote_hungup() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept_then_close() -> None:
        conn, _ = server.accept()
        conn.recv(4096)
        conn.close()

    threading.Thread(target=accept_then_close, daemon=True).start()

    verdict = probe_rdp.probe(dns="127.0.0.1", port=port, timeout=2.0)
    server.close()

    assert verdict.code == VerdictCode.REMOTE_HUNGUP_AFTER_CONNECT
