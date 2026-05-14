from __future__ import annotations

import socket
import ssl
import struct
import subprocess
import threading
from typing import cast

import pytest

from probe.lib import probe_smtp
from probe.lib.verdict import Discriminator, Verdict, VerdictCode
from probe.tests.conftest import TcpResponder


def test_smtp_banner_ok_then_ehlo(tcp_responder: TcpResponder) -> None:
    """Plain SMTP: read banner, expect 220 response, then quit. No STARTTLS attempt here."""
    banner = b"220 mail.example.com ESMTP Postfix\r\n250-mail.example.com\r\n250 SIZE 10485760\r\n"
    port = tcp_responder.start(mode="accept_read_send", read_bytes=0, response=banner)
    v = probe_smtp.probe(
        dns="127.0.0.1", port=port, kind="smtp", expect_banner_prefix="220", timeout=2.0
    )
    assert v.code == VerdictCode.OK


def test_smtp_banner_mismatch(tcp_responder: TcpResponder) -> None:
    bad_banner = b"500 NOT AN SMTP SERVER\r\n"
    port = tcp_responder.start(mode="accept_read_send", read_bytes=0, response=bad_banner)
    v = probe_smtp.probe(
        dns="127.0.0.1", port=port, kind="smtp", expect_banner_prefix="220", timeout=2.0
    )
    assert v.code == VerdictCode.BANNER_MISMATCH


def test_smtp_rst_during_banner(tcp_responder: TcpResponder) -> None:
    port = tcp_responder.start(mode="accept_rst")
    v = probe_smtp.probe(
        dns="127.0.0.1", port=port, kind="smtp", expect_banner_prefix="220", timeout=2.0
    )
    assert v.code in {VerdictCode.TCP_RST_HANDSHAKE, VerdictCode.TCP_RST_MID_STREAM}


def test_smtps_tls_reset(tcp_responder: TcpResponder) -> None:
    """SMTPS (465) attempts immediate TLS. RST either during connect (TCP_RST_HANDSHAKE)
    or during TLS handshake (TLS_RESET_POST_HELLO) — both are valid DPI signatures."""
    port = tcp_responder.start(mode="accept_rst")
    v = probe_smtp.probe(
        dns="127.0.0.1", port=port, kind="smtps", expect_banner_prefix="220", timeout=2.0
    )
    assert v.code in {VerdictCode.TLS_RESET_POST_HELLO, VerdictCode.TCP_RST_HANDSHAKE}


def test_smtps_handshake_timeout_returns_tls_timeout_not_reset() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    try:
        verdict = probe_smtp.probe(
            dns="127.0.0.1",
            port=port,
            kind="smtps",
            timeout=0.5,
        )
    finally:
        server.close()

    assert verdict.code == VerdictCode.TLS_TIMEOUT
    assert "timeout" in verdict.reason.lower()


def test_smtps_handshake_rst_returns_tls_reset_post_hello() -> None:
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
    verdict = probe_smtp.probe(
        dns="127.0.0.1",
        port=port,
        kind="smtps",
        timeout=2.0,
    )
    server.close()

    assert verdict.code == VerdictCode.TLS_RESET_POST_HELLO


def test_smtp_empty_banner_classifies_as_remote_hungup() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept_then_close() -> None:
        conn, _ = server.accept()
        conn.close()

    threading.Thread(target=accept_then_close, daemon=True).start()
    verdict = probe_smtp.probe(dns="127.0.0.1", port=port, kind="smtp", timeout=2.0)
    server.close()

    assert verdict.code == VerdictCode.REMOTE_HUNGUP_AFTER_CONNECT


def test_smtps_probe_fires_cert_mismatch_on_fingerprint_diff(tmp_path) -> None:  # type: ignore[no-untyped-def]
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(tmp_path / "key.pem"),
            "-out",
            str(tmp_path / "cert.pem"),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ],
        stderr=subprocess.DEVNULL,
    )
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(str(tmp_path / "cert.pem"), str(tmp_path / "key.pem"))
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def accept() -> None:
        conn, _ = server.accept()
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
            tls.sendall(b"220 mock.smtp ESMTP\r\n")
            tls.close()
        except OSError:
            pass

    threading.Thread(target=accept, daemon=True).start()
    verdict = probe_smtp.probe(
        dns="127.0.0.1",
        port=port,
        kind="smtps",
        timeout=2.0,
        expect_cert_fp="0" * 64,
    )
    server.close()

    assert verdict.code == VerdictCode.CERT_MISMATCH


def test_smtps_probe_sets_discriminator_sni_based_when_wrong_sni_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_probe_once(**kwargs: object) -> Verdict:
        calls.append(str(kwargs["dns"]))
        if len(calls) == 1:
            return Verdict(
                code=VerdictCode.TLS_TIMEOUT,
                reason="blocked",
                latency_ms=1.0,
                resolved_ip="198.51.100.10",
            )
        return Verdict(code=VerdictCode.OK, reason="wrong sni ok", latency_ms=1.0)

    monkeypatch.setattr(probe_smtp, "_probe_once", fake_probe_once)

    verdict = probe_smtp.probe(
        dns="mail.example",
        port=465,
        kind="smtps",
        timeout=1.0,
    )

    assert verdict.code == VerdictCode.TLS_TIMEOUT
    assert verdict.discriminator == Discriminator.SNI_BASED
    assert verdict.extra["wrong_sni_verdict"] == "OK"


def test_smtps_probe_sets_discriminator_dns_based_when_doh_ip_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_probe_once(**kwargs: object) -> Verdict:
        dns = str(kwargs["dns"])
        calls.append(dns)
        if len(calls) == 1:
            return Verdict(
                code=VerdictCode.TLS_TIMEOUT,
                reason="blocked",
                latency_ms=1.0,
                resolved_ip="198.51.100.10",
                extra={"doh_ips": ["198.51.100.10", "203.0.113.20"]},
            )
        if dns == "203.0.113.20":
            return Verdict(code=VerdictCode.OK, reason="doh ip ok", latency_ms=1.0)
        return Verdict(code=VerdictCode.TLS_TIMEOUT, reason="still blocked", latency_ms=1.0)

    monkeypatch.setattr(probe_smtp, "_probe_once", fake_probe_once)

    verdict = probe_smtp.probe(
        dns="mail.example",
        port=465,
        kind="smtps",
        timeout=1.0,
    )

    assert verdict.discriminator == Discriminator.DNS_BASED
    assert verdict.extra["doh_ip_works"] == "203.0.113.20"


def test_smtp_probe_does_not_run_discriminator_for_plain_smtp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_probe_once(**kwargs: object) -> Verdict:
        return Verdict(
            code=VerdictCode.PORT_FILTERED,
            reason="blocked",
            latency_ms=1.0,
            resolved_ip="198.51.100.10",
        )

    monkeypatch.setattr(probe_smtp, "_probe_once", fake_probe_once)
    monkeypatch.setattr(
        probe_smtp,
        "_run_wrong_sni_followup",
        lambda *args, **kwargs: pytest.fail("plain SMTP must not run SNI follow-up"),
    )

    verdict = probe_smtp.probe(
        dns="mail.example",
        port=25,
        kind="smtp",
        timeout=1.0,
    )

    assert verdict.code == VerdictCode.PORT_FILTERED
    assert verdict.discriminator is None


def test_smtps_discriminator_followups_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, float]] = []
    wrong_sni_timeouts: list[float] = []

    def fake_probe_once(**kwargs: object) -> Verdict:
        dns = str(kwargs["dns"])
        timeout = cast(float, kwargs["timeout"])
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

    monkeypatch.setattr(probe_smtp, "_probe_once", fake_probe_once)
    monkeypatch.setattr(probe_smtp, "_run_wrong_sni_followup", fake_wrong_sni)

    verdict = probe_smtp.probe(
        dns="mail.example",
        port=465,
        kind="smtps",
        timeout=10.0,
    )

    assert verdict.discriminator == Discriminator.INCONCLUSIVE
    assert [dns for dns, _timeout in calls] == [
        "mail.example",
        "203.0.113.1",
        "203.0.113.2",
    ]
    assert all(timeout <= 2.0 for _dns, timeout in calls[1:])
    assert all(timeout <= 2.0 for timeout in wrong_sni_timeouts)
