from __future__ import annotations

import socket
import threading

from probe.lib import probe_openvpn
from probe.lib.verdict import VerdictCode


def _udp_echo(sock: socket.socket, response: bytes) -> None:
    sock.settimeout(2.0)
    try:
        _, addr = sock.recvfrom(2048)
        sock.sendto(response, addr)
    except OSError:
        pass


def test_openvpn_udp_hard_reset_response_is_ok() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    response = b"\x40" + b"\x00" * 31  # opcode 8 (HARD_RESET_SERVER_V2) << 3
    t = threading.Thread(target=_udp_echo, args=(s, response), daemon=True)
    t.start()
    v = probe_openvpn.probe(dns="127.0.0.1", port=port, mode="udp", timeout=2.0)
    t.join(timeout=2.0)
    s.close()
    assert v.code == VerdictCode.OK


def test_openvpn_udp_no_response_is_port_filtered() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    v = probe_openvpn.probe(dns="127.0.0.1", port=port, mode="udp", timeout=0.8)
    s.close()
    assert v.code == VerdictCode.PORT_FILTERED


def test_openvpn_tcp_rst_is_dpi_signature() -> None:
    from probe.tests.conftest import TcpResponder

    r = TcpResponder()
    port = r.start(mode="accept_rst")
    v = probe_openvpn.probe(dns="127.0.0.1", port=port, mode="tcp", timeout=2.0)
    r.stop()
    assert v.code in {VerdictCode.TCP_RST_HANDSHAKE, VerdictCode.TCP_RST_MID_STREAM}
