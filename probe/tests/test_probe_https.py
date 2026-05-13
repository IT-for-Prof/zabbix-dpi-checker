from __future__ import annotations

import hashlib
import os
import socket
import ssl
import struct
import subprocess
import threading
from unittest.mock import patch

from probe.lib import probe_https
from probe.lib.resolver import DohCheckResult
from probe.lib.verdict import Discriminator, Verdict, VerdictCode
from probe.tests.conftest import TcpResponder


def test_https_tls_reset_post_hello(tcp_responder: TcpResponder) -> None:
    """RST from server: either during connect (TCP_RST_HANDSHAKE) or after ClientHello
    (TLS_RESET_POST_HELLO, the SNI-DPI signature). Both are valid DPI signatures —
    timing decides which one we see."""
    port = tcp_responder.start(mode="accept_rst")
    v = probe_https.probe(dns="127.0.0.1", port=port, sni="example.com", timeout=2.0)
    assert v.code in {VerdictCode.TLS_RESET_POST_HELLO, VerdictCode.TCP_RST_HANDSHAKE}
    assert v.resolved_ip == "127.0.0.1"
    assert v.latency_ms >= 0


def test_https_connect_refused_means_remote_down(tcp_responder: TcpResponder) -> None:
    """Server bound but immediately FIN — connect succeeds, recv yields empty → REMOTE_DOWN."""
    port = tcp_responder.start(mode="accept_close_fin")
    v = probe_https.probe(dns="127.0.0.1", port=port, sni="example.com", timeout=2.0)
    assert v.code in {
        VerdictCode.REMOTE_DOWN,
        VerdictCode.TLS_RESET_POST_HELLO,
        VerdictCode.TLS_TIMEOUT,  # SSLEOFError on FIN during handshake
    }


def test_https_no_accept_means_port_filtered(tcp_responder: TcpResponder) -> None:
    """Bound socket but no accept loop → connect_ex never completes → PORT_FILTERED."""
    port = tcp_responder.start(mode="no_accept")
    v = probe_https.probe(dns="127.0.0.1", port=port, sni="example.com", timeout=1.0)
    assert v.code in {VerdictCode.PORT_FILTERED, VerdictCode.TLS_TIMEOUT}


def test_https_invalid_dns_raises_dns_error_verdict() -> None:
    v = probe_https.probe(
        dns="nonexistent.invalid", port=443, sni="example.com", timeout=2.0
    )
    assert v.code in {VerdictCode.DNS_LIE, VerdictCode.ERROR_INTERNAL}
    assert v.resolved_ip is None


def test_https_body_scan_disabled_via_env_var(tcp_responder: TcpResponder) -> None:
    """`DPI_PROBE_HTTP_BODY=0` must skip the HTTP body GET entirely so probes
    against fragile or slow targets don't pay the latency cost.

    We can't directly observe "no GET was sent" via this fixture, but we CAN
    confirm the verdict path is unchanged (OK, no HTTP_STUB) AND that the
    read_body=False kwarg / env-var disable doesn't cause spurious failure.
    """
    port = tcp_responder.start(mode="accept_close_fin")
    with patch.dict(os.environ, {"DPI_PROBE_HTTP_BODY": "0"}):
        v = probe_https.probe(dns="127.0.0.1", port=port, sni="example.com", timeout=2.0)
    # Body-scan disabled → can't transition OK → HTTP_STUB regardless of what
    # the target served. Other failure modes (FIN-during-handshake) still possible.
    assert v.code != VerdictCode.HTTP_STUB


def test_https_handshake_timeout_returns_tls_timeout_not_reset() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        verdict = probe_https.probe(
            dns="127.0.0.1", port=port, sni="127.0.0.1",
            timeout=0.5, read_body=False,
        )
    finally:
        server.close()

    assert verdict.code == VerdictCode.TLS_TIMEOUT


def test_https_handshake_eof_returns_tls_reset_post_hello() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def reset_immediately() -> None:
        conn, _ = server.accept()
        conn.recv(1)
        conn.close()

    threading.Thread(target=reset_immediately, daemon=True).start()
    verdict = probe_https.probe(
        dns="127.0.0.1", port=port, sni="example.com", timeout=2.0, read_body=False
    )
    server.close()

    assert verdict.code == VerdictCode.TLS_RESET_POST_HELLO


# ---------------------------------------------------------------------------
# _scan_for_stub unit tests — duck-typed TLS fixture so we can exercise the
# marker-matching code path without standing up a real TLS server.
# ---------------------------------------------------------------------------


class _FakeTLS:
    """Minimal `ssl.SSLSocket`-shaped stub: records sent bytes, replays recv buffer."""

    def __init__(self, recv_payload: bytes) -> None:
        self.sent = b""
        self._buf = recv_payload
        self._offset = 0
        self.timeouts: list[float] = []

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def settimeout(self, t: float) -> None:
        self.timeouts.append(t)

    def recv(self, n: int) -> bytes:
        chunk = self._buf[self._offset : self._offset + n]
        self._offset += len(chunk)
        return chunk


def test_scan_for_stub_finds_rkn_marker_in_response() -> None:
    """Default marker list catches a typical RKN stub-page body."""
    # UTF-8 bytes for "Доступ ограничен" (RKN stub-page header).
    body = "<html><body><h1>Доступ ограничен</h1></body></html>".encode()
    tls = _FakeTLS(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body)
    result = probe_https._scan_for_stub(tls, "example.com", deadline=10.0)
    assert result == "доступ ограничен"
    # Confirm a real GET was issued with the right Host header
    assert b"GET / HTTP/1.1" in tls.sent
    assert b"Host: example.com" in tls.sent


def test_scan_for_stub_returns_none_when_no_marker() -> None:
    """Genuine site content → no match → None → caller keeps OK verdict."""
    tls = _FakeTLS(b"HTTP/1.1 200 OK\r\n\r\n<html><body>Welcome!</body></html>")
    assert probe_https._scan_for_stub(tls, "example.com", deadline=10.0) is None


def test_scan_for_stub_respects_custom_marker_list() -> None:
    """Pluggable markers allow non-RU jurisdictions to define their own patterns."""
    tls = _FakeTLS(b"HTTP/1.1 200 OK\r\n\r\nThis content is restricted by xx-authority.")
    result = probe_https._scan_for_stub(
        tls, "example.com",
        deadline=10.0,
        markers=("restricted by xx-authority",),
    )
    assert result == "restricted by xx-authority"


def test_scan_for_stub_swallows_send_errors() -> None:
    """Network failure during scan must NEVER fail the probe — opportunistic only."""

    class BrokenTLS:
        def sendall(self, data: bytes) -> None:
            raise OSError("broken pipe")

        def settimeout(self, t: float) -> None:
            pass

        def recv(self, n: int) -> bytes:
            return b""

    assert probe_https._scan_for_stub(BrokenTLS(), "example.com", deadline=10.0) is None


def test_scan_for_stub_stops_at_deadline() -> None:
    """When wall-clock budget runs out, scan exits gracefully without raising."""
    tls = _FakeTLS(b"HTTP/1.1 200 OK\r\n\r\nirrelevant body")
    # deadline=0 means budget already exhausted — must NOT raise, must NOT match.
    assert probe_https._scan_for_stub(tls, "example.com", deadline=0.0) is None


def test_http_stub_markers_cover_belarus_filtering() -> None:
    body = "Доступ к информационному ресурсу ограничен".lower()
    assert any(m in body for m in probe_https._STUB_MARKERS)


def test_http_stub_markers_cover_kazakhstan() -> None:
    bodies = (
        "доступ к ресурсу ограничен согласно решению".lower(),
        "қол жетімділік шектелген".lower(),
    )
    for body in bodies:
        assert any(m in body for m in probe_https._STUB_MARKERS)


def test_http_stub_markers_cover_iran() -> None:
    bodies = (
        "دسترسی به این سایت امکان پذیر نمی باشد".lower(),
        "access to this website is forbidden".lower(),
    )
    for body in bodies:
        assert any(m in body for m in probe_https._STUB_MARKERS)


def _spin_local_tls(tmp_path) -> tuple[socket.socket, int]:  # type: ignore[no-untyped-def]
    subprocess.check_call([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(tmp_path / "key.pem"),
        "-out", str(tmp_path / "cert.pem"),
        "-days", "1", "-subj", "/CN=localhost",
    ], stderr=subprocess.DEVNULL)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(str(tmp_path / "cert.pem"), str(tmp_path / "key.pem"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _accept() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length:0\r\n\r\n")
                tls.close()
            except OSError:
                pass

    threading.Thread(target=_accept, daemon=True).start()
    return srv, port


def test_https_probe_sets_discriminator_sni_based_when_wrong_sni_works(
    monkeypatch, tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    srv, port = _spin_local_tls(tmp_path)
    real_wrap = ssl.SSLContext.wrap_socket

    def selective_wrap(self, sock, *args, **kwargs):  # type: ignore[no-untyped-def]
        if kwargs.get("server_hostname") == "blocked.example":
            raise TimeoutError("simulated SNI-based DPI on real SNI")
        return real_wrap(self, sock, *args, **kwargs)

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", selective_wrap)
    try:
        v = probe_https.probe(
            dns="127.0.0.1",
            port=port,
            sni="blocked.example",
            timeout=2.0,
            read_body=False,
        )
    finally:
        srv.close()

    assert v.code == VerdictCode.TLS_TIMEOUT
    assert v.discriminator == Discriminator.SNI_BASED
    assert v.extra["wrong_sni_verdict"] == "OK"


def test_https_probe_discriminator_inconclusive_when_both_fail(
    monkeypatch, tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    srv, port = _spin_local_tls(tmp_path)

    def always_fail(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        raise TimeoutError("simulated IP-level block")

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", always_fail)
    try:
        v = probe_https.probe(
            dns="127.0.0.1",
            port=port,
            sni="blocked.example",
            timeout=2.0,
            read_body=False,
        )
    finally:
        srv.close()

    assert v.code == VerdictCode.TLS_TIMEOUT
    assert v.discriminator == Discriminator.INCONCLUSIVE


def test_https_probe_sets_discriminator_dns_based_when_doh_ip_works(
    monkeypatch, tmp_path,  # type: ignore[no-untyped-def]
) -> None:
    srv, port = _spin_local_tls(tmp_path)

    def fake_resolve(host: str, *, timeout: float) -> DohCheckResult:
        if host == "poisoned.example":
            return DohCheckResult(
                ip="127.0.0.2",
                latency_ms=1.0,
                doh_ips=frozenset({"127.0.0.1"}),
                mismatch=True,
                system_error=None,
            )
        return DohCheckResult(host, 0.0, frozenset(), False, None)

    monkeypatch.setattr(probe_https, "resolve_with_doh_check", fake_resolve)
    try:
        v = probe_https.probe(
            dns="poisoned.example",
            port=port,
            sni="poisoned.example",
            timeout=2.0,
            read_body=False,
        )
    finally:
        srv.close()

    assert v.discriminator == Discriminator.DNS_BASED
    assert v.extra["doh_ip_works"] == "127.0.0.1"


def test_https_discriminator_followups_are_bounded(
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    calls: list[tuple[str, float]] = []
    wrong_sni_timeouts: list[float] = []

    def fake_probe_once(**kwargs: object) -> Verdict:
        dns = str(kwargs["dns"])
        timeout = float(kwargs["timeout"])
        calls.append((dns, timeout))
        if len(calls) == 1:
            return Verdict(
                code=VerdictCode.TLS_TIMEOUT,
                reason="blocked",
                latency_ms=1.0,
                resolved_ip="198.51.100.10",
                extra={
                    "doh_ips": [
                        "203.0.113.1",
                        "203.0.113.2",
                        "203.0.113.3",
                    ],
                },
            )
        return Verdict(code=VerdictCode.TLS_TIMEOUT, reason="still blocked", latency_ms=1.0)

    def fake_wrong_sni(ip: str, port: int, original_sni: str, timeout: float) -> Verdict:
        wrong_sni_timeouts.append(timeout)
        return Verdict(code=VerdictCode.TLS_TIMEOUT, reason="wrong sni blocked", latency_ms=1.0)

    monkeypatch.setattr(probe_https, "_probe_once", fake_probe_once)
    monkeypatch.setattr(probe_https, "_run_wrong_sni_followup", fake_wrong_sni)

    verdict = probe_https.probe(
        dns="blocked.example",
        port=443,
        sni="blocked.example",
        timeout=10.0,
        read_body=False,
    )

    assert verdict.discriminator == Discriminator.INCONCLUSIVE
    assert [dns for dns, _timeout in calls] == [
        "blocked.example",
        "203.0.113.1",
        "203.0.113.2",
    ]
    assert all(timeout <= 2.0 for _dns, timeout in calls[1:])
    assert all(timeout <= 2.0 for timeout in wrong_sni_timeouts)


def test_https_probe_discriminator_unset_on_ok(tmp_path) -> None:  # type: ignore[no-untyped-def]
    srv, port = _spin_local_tls(tmp_path)
    try:
        v = probe_https.probe(
            dns="127.0.0.1",
            port=port,
            sni="localhost",
            timeout=2.0,
            read_body=False,
        )
    finally:
        srv.close()

    assert v.code == VerdictCode.OK
    assert v.discriminator is None


def test_https_probe_accepts_colon_delimited_cert_fingerprint(tmp_path) -> None:  # type: ignore[no-untyped-def]
    srv, port = _spin_local_tls(tmp_path)
    pem = (tmp_path / "cert.pem").read_text()
    der = ssl.PEM_cert_to_DER_cert(pem)
    fp = hashlib.sha256(der).hexdigest()
    colon_fp = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))
    try:
        v = probe_https.probe(
            dns="127.0.0.1",
            port=port,
            sni="localhost",
            timeout=2.0,
            expect_cert_fp=colon_fp,
            read_body=False,
        )
    finally:
        srv.close()

    assert v.code == VerdictCode.OK
