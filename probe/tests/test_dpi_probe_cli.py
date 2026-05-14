from __future__ import annotations

import contextlib
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

CLI = Path(__file__).resolve().parents[1] / "dpi_probe.py"


def _run(*args: str) -> tuple[int, str, str]:
    # subprocess timeout > probe default timeout (10s) so we don't race the
    # default-timeout test against TEST-NET-1 stalls.
    p = subprocess.run(
        [sys.executable, str(CLI), *args],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return p.returncode, p.stdout, p.stderr


def test_cli_positional_unknown_kind_returns_error_internal_verdict() -> None:
    # Zabbix-style call: target kind port dns sni timeout
    rc, out, _err = _run("zbx-host", "bogus", "1", "example.com", "example.com", "1")
    assert rc == 0  # always exit 0 — never non-zero
    payload = json.loads(out)
    assert payload["verdict"] == "ERROR_INTERNAL"
    assert "bogus" in payload["reason"].lower() or "unknown kind" in payload["reason"].lower()


def test_cli_positional_https_against_blackhole_ip_returns_some_failure_verdict() -> None:
    # 192.0.2.0/24 is TEST-NET-1 — never routable.
    rc, out, _ = _run("zbx-host", "https", "443", "192.0.2.1", "example.com", "2")
    assert rc == 0
    payload = json.loads(out)
    assert payload["verdict"] in {"PORT_FILTERED", "ROUTE_BLACKHOLE", "ERROR_INTERNAL"}


def test_cli_help_lists_all_kinds() -> None:
    rc, out, _ = _run("--help")
    assert rc == 0
    for kind in ("https", "smtp", "smtps", "rdp", "rdgw", "ssh", "wireguard", "openvpn"):
        assert kind in out


def test_cli_missing_positional_emits_error_internal_not_argparse_exit_2() -> None:
    # Zabbix contract: always exit 0 with a valid JSON verdict, even on bad input.
    # argparse defaults to sys.exit(2) on missing required arg — we must override.
    rc, out, _err = _run("zbx-host")  # missing kind/port/dns
    assert rc == 0, f"expected exit 0 (Zabbix-friendly), got {rc}; stderr was: {_err}"
    payload = json.loads(out)
    assert payload["verdict"] == "ERROR_INTERNAL"


def test_cli_sni_defaults_to_dns_when_omitted() -> None:
    # Omit both SNI and timeout — verify argparse defaults kick in and the CLI
    # runs to completion. _run's 15s subprocess budget exceeds the probe's 10s
    # default to avoid a race.
    rc, out, _err = _run("zbx-host", "https", "443", "192.0.2.1")
    assert rc == 0, f"stderr was: {_err}"
    payload = json.loads(out)
    # Any verdict is fine — we're testing the CLI accepted the call without crashing.
    assert "verdict" in payload


def _spin_local_tls_server(tmpdir: str) -> tuple[socket.socket, int]:
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            f"{tmpdir}/key.pem",
            "-out",
            f"{tmpdir}/cert.pem",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ],
        stderr=subprocess.DEVNULL,
    )
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(f"{tmpdir}/cert.pem", f"{tmpdir}/key.pem")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def _accept() -> None:
        conn, _ = server.accept()
        with contextlib.suppress(OSError):
            ctx.wrap_socket(conn, server_side=True).close()

    threading.Thread(target=_accept, daemon=True).start()
    return server, port


def test_cli_control_only_mode_emits_ok_verdict(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from probe.dpi_probe import main

    with tempfile.TemporaryDirectory() as d:
        server, port = _spin_local_tls_server(d)
        monkeypatch.setenv("DPI_CONTROL_HOST", "127.0.0.1")
        monkeypatch.setenv("DPI_CONTROL_PORT", str(port))
        monkeypatch.setattr("sys.argv", ["dpi_probe", "--control-only"])
        try:
            with pytest.raises(SystemExit) as exc_info:
                main()
        finally:
            server.close()
    assert exc_info.value.code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["verdict"] == "OK"


def test_cli_with_control_returns_vantage_unavailable_when_control_fails(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from probe.dpi_probe import main
    from probe.lib import probe_control as pc_mod
    from probe.lib.verdict import Verdict, VerdictCode

    monkeypatch.setattr(
        pc_mod,
        "probe_control",
        lambda **kw: Verdict(
            code=VerdictCode.PORT_FILTERED,
            reason="control simulated fail",
            latency_ms=999.0,
        ),
    )
    from probe.lib import probe_https

    monkeypatch.setattr(
        probe_https,
        "probe",
        lambda **kw: pytest.fail("target probe must not run when control fails"),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "dpi_probe",
            "example.com",
            "https",
            "443",
            "example.com",
            "example.com",
            "5",
            "--with-control",
        ],
    )
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["verdict"] == "VANTAGE_UNAVAILABLE"
    assert "control simulated fail" in payload["reason"]
    assert payload["extra"]["control_verdict"] == "PORT_FILTERED"


def test_cli_with_control_proceeds_when_control_passes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from probe.dpi_probe import main
    from probe.lib import probe_control as pc_mod
    from probe.lib import probe_https
    from probe.lib.verdict import Verdict, VerdictCode

    monkeypatch.setattr(
        pc_mod,
        "probe_control",
        lambda **kw: Verdict(
            code=VerdictCode.OK,
            reason="control ok",
            latency_ms=42.0,
        ),
    )
    monkeypatch.setattr(
        probe_https,
        "probe",
        lambda **kw: Verdict(
            code=VerdictCode.TLS_TIMEOUT,
            reason="simulated target timeout",
            latency_ms=5000.0,
            resolved_ip="93.184.216.34",
        ),
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "dpi_probe",
            "example.com",
            "https",
            "443",
            "example.com",
            "example.com",
            "5",
            "--with-control",
        ],
    )
    with pytest.raises(SystemExit):
        main()
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["verdict"] == "TLS_TIMEOUT"


def test_cli_control_only_bad_env_emits_error_internal(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from probe.dpi_probe import main

    monkeypatch.setenv("DPI_CONTROL_PORT", "not-an-int")
    monkeypatch.setattr("sys.argv", ["dpi_probe", "--control-only"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["verdict"] == "ERROR_INTERNAL"
    assert "DPI_CONTROL_PORT" in payload["reason"]


@pytest.mark.parametrize(
    ("env_name", "env_value"),
    [
        ("DPI_CONTROL_PORT", "99999"),
        ("DPI_CONTROL_TIMEOUT", "-1"),
        ("DPI_CONTROL_TIMEOUT", "nan"),
    ],
)
def test_cli_control_only_invalid_parsed_env_emits_error_internal(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    env_name: str,
    env_value: str,
) -> None:
    from probe.dpi_probe import main

    monkeypatch.setenv(env_name, env_value)
    monkeypatch.setattr("sys.argv", ["dpi_probe", "--control-only"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["verdict"] == "ERROR_INTERNAL"
    assert env_name in payload["reason"]


def test_cli_with_control_uses_same_env_config_as_control_only(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from probe.dpi_probe import main
    from probe.lib import probe_control as pc_mod
    from probe.lib import probe_https
    from probe.lib.verdict import Verdict, VerdictCode

    captured_kwargs: dict[str, object] = {}

    def fake_control(**kw: object) -> Verdict:
        captured_kwargs.update(kw)
        return Verdict(code=VerdictCode.OK, reason="control ok", latency_ms=1.0)

    monkeypatch.setattr(pc_mod, "probe_control", fake_control)
    monkeypatch.setattr(
        probe_https,
        "probe",
        lambda **kw: Verdict(
            code=VerdictCode.OK,
            reason="ok",
            latency_ms=5.0,
            resolved_ip="127.0.0.1",
        ),
    )
    monkeypatch.setenv("DPI_CONTROL_HOST", "203.0.113.10")
    monkeypatch.setenv("DPI_CONTROL_PORT", "9443")
    monkeypatch.setenv("DPI_CONTROL_TIMEOUT", "7")
    monkeypatch.setattr(
        "sys.argv",
        [
            "dpi_probe",
            "example.com",
            "https",
            "443",
            "example.com",
            "example.com",
            "5",
            "--with-control",
        ],
    )
    with pytest.raises(SystemExit):
        main()
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["verdict"] == "OK"
    assert captured_kwargs == {"host": "203.0.113.10", "port": 9443, "timeout": 7.0}


def test_cli_forwards_cert_fp_to_probe_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from probe.dpi_probe import main
    from probe.lib import probe_https
    from probe.lib.verdict import Verdict, VerdictCode

    captured_kwargs: dict[str, object] = {}

    def fake_probe(**kw: object) -> Verdict:
        captured_kwargs.update(kw)
        return Verdict(code=VerdictCode.OK, reason="x", latency_ms=1.0)

    monkeypatch.setattr(probe_https, "probe", fake_probe)
    monkeypatch.setattr(
        "sys.argv",
        [
            "dpi_probe",
            "example.com",
            "https",
            "443",
            "example.com",
            "example.com",
            "5",
            "abc123deadbeef",
        ],
    )
    with pytest.raises(SystemExit):
        main()

    assert captured_kwargs["expect_cert_fp"] == "abc123deadbeef"


def test_cli_forwards_sni_and_cert_fp_to_probe_smtps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from probe.dpi_probe import main
    from probe.lib import probe_smtp
    from probe.lib.verdict import Verdict, VerdictCode

    captured_kwargs: dict[str, object] = {}

    def fake_probe(**kw: object) -> Verdict:
        captured_kwargs.update(kw)
        return Verdict(code=VerdictCode.OK, reason="x", latency_ms=1.0)

    monkeypatch.setattr(probe_smtp, "probe", fake_probe)
    monkeypatch.setattr(
        "sys.argv",
        [
            "dpi_probe",
            "example.com",
            "smtps",
            "465",
            "203.0.113.10",
            "mail.example.com",
            "5",
            "abc123deadbeef",
        ],
    )
    with pytest.raises(SystemExit):
        main()

    assert captured_kwargs["sni"] == "mail.example.com"
    assert captured_kwargs["expect_cert_fp"] == "abc123deadbeef"


def test_cli_accepts_template_arg_order_with_cert_fp_and_control(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from probe.dpi_probe import main
    from probe.lib import probe_control as pc_mod
    from probe.lib import probe_https
    from probe.lib.verdict import Verdict, VerdictCode

    captured_kwargs: dict[str, object] = {}

    monkeypatch.setattr(
        pc_mod,
        "probe_control",
        lambda **kw: Verdict(
            code=VerdictCode.OK,
            reason="control ok",
            latency_ms=1.0,
        ),
    )

    def fake_probe(**kw: object) -> Verdict:
        captured_kwargs.update(kw)
        return Verdict(code=VerdictCode.OK, reason="x", latency_ms=1.0)

    monkeypatch.setattr(probe_https, "probe", fake_probe)
    monkeypatch.setattr(
        "sys.argv",
        [
            "dpi_probe",
            "target",
            "https",
            "443",
            "example.com",
            "example.com",
            "5",
            "",
            "--with-control",
        ],
    )
    with pytest.raises(SystemExit):
        main()

    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["verdict"] == "OK"
    assert captured_kwargs["expect_cert_fp"] is None


def test_cli_https_bytes_kind_dispatches(monkeypatch: pytest.MonkeyPatch) -> None:
    from probe import dpi_probe
    from probe.lib import probe_https_bytes
    from probe.lib.verdict import Verdict, VerdictCode

    calls: list[dict[str, object]] = []

    def fake_probe(**kwargs: object) -> Verdict:
        calls.append(kwargs)
        return Verdict(code=VerdictCode.OK, reason="stub", latency_ms=1.0)

    monkeypatch.setattr(probe_https_bytes, "probe", fake_probe)
    monkeypatch.setattr(
        "sys.argv",
        [
            "dpi_probe",
            "target.example.com",
            "https-bytes",
            "443",
            "1.2.3.4",
            "target.example.com",
            "10",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        dpi_probe.main()
    assert exc.value.code == 0
    assert calls, "probe_https_bytes.probe was not called"
    assert calls[0]["dns"] == "1.2.3.4"
    assert calls[0]["port"] == 443
    assert calls[0]["sni"] == "target.example.com"


def test_cli_tls_frag_kind_dispatches(monkeypatch: pytest.MonkeyPatch) -> None:
    from probe import dpi_probe
    from probe.lib import probe_tls_frag
    from probe.lib.verdict import Verdict, VerdictCode

    calls: list[dict[str, object]] = []

    def fake_probe(**kwargs: object) -> Verdict:
        calls.append(kwargs)
        return Verdict(code=VerdictCode.OK, reason="stub", latency_ms=1.0)

    monkeypatch.setattr(probe_tls_frag, "probe", fake_probe)
    monkeypatch.setattr(
        "sys.argv",
        [
            "dpi_probe",
            "rutracker.org",
            "tls-frag",
            "443",
            "104.21.32.39",
            "rutracker.org",
            "10",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        dpi_probe.main()
    assert exc.value.code == 0
    assert calls
    assert calls[0]["sni"] == "rutracker.org"
