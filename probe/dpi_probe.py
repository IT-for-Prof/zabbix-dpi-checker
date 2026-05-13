#!/opt/dpi-probe/venv/bin/python
"""dpi_probe — single-shot DPI probe.

Invoked by Zabbix External check as: dpi_probe TARGET KIND PORT DNS [SNI] [TIMEOUT]
Prints one JSON line to stdout. Always exits 0 to satisfy Zabbix's "item not
supported on non-zero exit" rule — failures are encoded in the JSON verdict.
"""

from __future__ import annotations

import argparse
import dataclasses
import math
import os
import sys
import traceback
from pathlib import Path
from typing import NoReturn

# sys.path bootstrap supports both layouts without polluting /opt:
#   dev:  /opt/dpi-checker/probe/dpi_probe.py  — repo root /opt/dpi-checker holds `probe/`
#   prod: /opt/dpi-probe/dpi_probe             — package root /opt/dpi-probe holds `probe/`
# Pick the directory that contains a `probe/` subtree on disk. If `_here/probe`
# exists, this is the prod layout (script lives at package root). Otherwise
# `_here.parent` is the repo root (dev layout, script lives in repo/probe/).
_here = Path(__file__).resolve().parent
_pkg_root = _here if (_here / "probe").is_dir() else _here.parent
_pkg_root_str = str(_pkg_root)
if _pkg_root_str not in sys.path:
    sys.path.insert(0, _pkg_root_str)

from probe.lib import logger as _syslog  # noqa: E402
from probe.lib import (  # noqa: E402
    probe_https,
    probe_openvpn,
    probe_rdgw,
    probe_rdp,
    probe_smtp,
    probe_ssh,
    probe_wireguard,
)
from probe.lib.verdict import Verdict, VerdictCode  # noqa: E402

KINDS = ("https", "smtp", "smtps", "rdp", "rdgw", "ssh", "wireguard", "openvpn")


@dataclasses.dataclass(frozen=True)
class _ControlConfig:
    host: str
    port: int
    timeout: float


def _emit(verdict: Verdict) -> NoReturn:
    # Suppress any I/O failure (BrokenPipeError on closed stdout, OSError under
    # memory pressure). Exiting 0 silently is preferable to a non-zero exit with
    # a traceback — Zabbix would mark the item NOTSUPPORTED otherwise.
    try:
        sys.stdout.write(verdict.to_json() + "\n")
        sys.stdout.flush()
    except Exception:
        pass
    raise SystemExit(0)


class _ZabbixSafeArgParser(argparse.ArgumentParser):
    """ArgumentParser that emits a valid JSON verdict and exits 0 on parse errors,
    instead of argparse's default sys.exit(2). Required because Zabbix marks any
    non-zero-exit External-check item as NOTSUPPORTED.

    Scope note: we override `error()` only. argparse's `--help` path already
    exits 0 via _HelpAction, so it is safe. If anyone adds `--version`,
    subparsers, or `parse_intermixed_args`, audit those paths too — they call
    `self.exit()` directly, bypassing `error()`.
    """

    def error(self, message: str) -> NoReturn:
        v = Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=f"argparse: {message}",
            latency_ms=0.0,
        )
        _emit(v)


def _load_control_config() -> tuple[_ControlConfig | None, Verdict | None]:
    host = os.environ.get("DPI_CONTROL_HOST", "1.1.1.1")
    try:
        port = int(os.environ.get("DPI_CONTROL_PORT", "443"))
    except ValueError as e:
        return None, Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=f"invalid DPI_CONTROL_PORT: {e}",
            latency_ms=0.0,
        )
    if not 1 <= port <= 65535:
        return None, Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=f"invalid DPI_CONTROL_PORT: expected 1..65535, got {port}",
            latency_ms=0.0,
        )
    try:
        timeout = float(os.environ.get("DPI_CONTROL_TIMEOUT", "5"))
    except ValueError as e:
        return None, Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=f"invalid DPI_CONTROL_TIMEOUT: {e}",
            latency_ms=0.0,
        )
    if not math.isfinite(timeout) or timeout <= 0.0:
        return None, Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=f"invalid DPI_CONTROL_TIMEOUT: expected finite value > 0, got {timeout}",
            latency_ms=0.0,
        )
    return _ControlConfig(host=host, port=port, timeout=timeout), None


def main() -> NoReturn:
    parser = _ZabbixSafeArgParser(
        prog="dpi_probe",
        description=(
            "Single-shot DPI-aware probe. Emits one JSON verdict on stdout. "
            f"Supported kinds: {', '.join(KINDS)}."
        ),
    )
    parser.add_argument("--control-only", action="store_true", dest="control_only")
    parser.add_argument("--with-control", action="store_true", dest="with_control")
    # Positional args match Zabbix External-check key order:
    #   key: dpi_probe[{#TARGET},{#KIND},{#PORT},{#DNS},{#SNI},{$DPI.PROBE_TIMEOUT}]
    parser.add_argument("target", nargs="?", help="target host identifier (used in logs only)")
    parser.add_argument("kind", nargs="?", help=f"protocol kind; one of: {', '.join(KINDS)}")
    parser.add_argument("port", nargs="?", type=int, help="TCP/UDP port")
    parser.add_argument("dns", nargs="?", help="hostname or IP of target")
    parser.add_argument("sni", nargs="?", default=None, help="TLS SNI; defaults to <dns>")
    parser.add_argument(
        "timeout", nargs="?", type=float, default=10.0, help="total budget in seconds"
    )
    parser.add_argument("cert_fp", nargs="?", default=None, help="expected leaf cert SHA-256")

    args = parser.parse_args()
    control_config, control_config_error = _load_control_config()

    if args.control_only:
        from probe.lib.probe_control import probe_control

        if control_config_error is not None:
            _emit(control_config_error)
        if control_config is None:
            _emit(Verdict(
                code=VerdictCode.ERROR_INTERNAL,
                reason="invalid control configuration",
                latency_ms=0.0,
            ))
        _emit(probe_control(
            host=control_config.host,
            port=control_config.port,
            timeout=control_config.timeout,
        ))

    if not all([args.target, args.kind, args.port, args.dns]):
        parser.error("target, kind, port, dns are required unless --control-only is set")

    try:
        if args.with_control:
            from probe.lib.probe_control import probe_control

            if control_config_error is not None:
                _emit(control_config_error)
            if control_config is None:
                _emit(Verdict(
                    code=VerdictCode.ERROR_INTERNAL,
                    reason="invalid control configuration",
                    latency_ms=0.0,
                ))
            ctrl = probe_control(
                host=control_config.host,
                port=control_config.port,
                timeout=control_config.timeout,
            )
            if ctrl.code != VerdictCode.OK:
                _emit(Verdict(
                    code=VerdictCode.VANTAGE_UNAVAILABLE,
                    reason=f"vantage control failed: {ctrl.reason}",
                    latency_ms=ctrl.latency_ms,
                    extra={"control_verdict": ctrl.code.value},
                ))
        if args.kind == "https":
            v = probe_https.probe(
                dns=args.dns,
                port=args.port,
                sni=args.sni or args.dns,
                timeout=args.timeout,
                expect_cert_fp=args.cert_fp or None,
            )
        elif args.kind == "smtp":
            v = probe_smtp.probe(
                dns=args.dns,
                port=args.port,
                kind="smtp",
                timeout=args.timeout,
            )
        elif args.kind == "smtps":
            v = probe_smtp.probe(
                dns=args.dns,
                port=args.port,
                kind="smtps",
                timeout=args.timeout,
                expect_cert_fp=args.cert_fp or None,
                sni=args.sni or args.dns,
            )
        elif args.kind == "rdp":
            v = probe_rdp.probe(
                dns=args.dns,
                port=args.port,
                timeout=args.timeout,
            )
        elif args.kind == "rdgw":
            v = probe_rdgw.probe(
                dns=args.dns,
                port=args.port,
                sni=args.sni,
                timeout=args.timeout,
            )
        elif args.kind == "ssh":
            v = probe_ssh.probe(
                dns=args.dns,
                port=args.port,
                timeout=args.timeout,
            )
        elif args.kind == "wireguard":
            v = probe_wireguard.probe(
                dns=args.dns,
                port=args.port,
                timeout=args.timeout,
            )
        elif args.kind == "openvpn":
            v = probe_openvpn.probe(
                dns=args.dns,
                port=args.port,
                timeout=args.timeout,
            )
        else:
            v = Verdict(
                code=VerdictCode.ERROR_INTERNAL,
                reason=f"unknown kind {args.kind!r}",
                latency_ms=0.0,
            )
    except Exception as e:
        v = Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=f"probe crashed: {type(e).__name__}: {e}",
            latency_ms=0.0,
            extra={"traceback": traceback.format_exc().splitlines()[-5:]},
        )

    # Best-effort syslog (opt-in via DPI_PROBE_SYSLOG=1) — never fatal.
    _syslog.log_verdict(args.target, args.kind, args.port, args.dns, v)
    _emit(v)


if __name__ == "__main__":
    main()
