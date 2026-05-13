from __future__ import annotations

import socket
import threading

from probe.lib import probe_ssh
from probe.lib.verdict import VerdictCode
from probe.tests.conftest import TcpResponder


def test_ssh_banner_ok(tcp_responder: TcpResponder) -> None:
    port = tcp_responder.start(
        mode="accept_read_send", read_bytes=0, response=b"SSH-2.0-OpenSSH_8.7\r\n"
    )
    v = probe_ssh.probe(dns="127.0.0.1", port=port, timeout=2.0)
    assert v.code == VerdictCode.OK
    assert v.extra.get("banner", "").startswith("SSH-2.0-OpenSSH_8.7")


def test_ssh_wrong_banner_is_mismatch(tcp_responder: TcpResponder) -> None:
    port = tcp_responder.start(
        mode="accept_read_send", read_bytes=0, response=b"HTTP/1.1 400 Bad Request\r\n"
    )
    v = probe_ssh.probe(dns="127.0.0.1", port=port, timeout=2.0)
    assert v.code == VerdictCode.BANNER_MISMATCH


def test_ssh_rst_on_connect(tcp_responder: TcpResponder) -> None:
    port = tcp_responder.start(mode="accept_rst")
    v = probe_ssh.probe(dns="127.0.0.1", port=port, timeout=2.0)
    assert v.code in {VerdictCode.TCP_RST_HANDSHAKE, VerdictCode.TCP_RST_MID_STREAM}


def test_ssh_empty_banner_classifies_as_remote_hungup() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept_then_close() -> None:
        conn, _ = server.accept()
        conn.close()

    threading.Thread(target=accept_then_close, daemon=True).start()
    v = probe_ssh.probe(dns="127.0.0.1", port=port, timeout=2.0)
    server.close()

    assert v.code == VerdictCode.REMOTE_HUNGUP_AFTER_CONNECT
