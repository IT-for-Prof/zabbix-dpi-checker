"""WireGuard real-fresh-handshake probe."""

from __future__ import annotations

import subprocess
import time
from contextlib import suppress

from probe.lib.verdict import Verdict, VerdictCode

_WG_CMD = ["sudo", "wg"]
_POLL_INTERVAL_S = 0.25
_POLL_WINDOW_S = 5.0


class WgCommandError(RuntimeError):
    def __init__(self, args: list[str], returncode: int, stderr: str) -> None:
        self.args_list = args
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"wg {' '.join(args)} failed rc={returncode}: {stderr.strip()}")


def _wg(args: list[str], timeout: float) -> str:
    proc = subprocess.run(
        _WG_CMD + args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise WgCommandError(args, proc.returncode, proc.stderr)
    return proc.stdout


def _get_epoch(iface: str, peer_pubkey: str, timeout: float) -> int:
    out = _wg(["show", iface, "latest-handshakes"], timeout=timeout)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == peer_pubkey:
            try:
                return int(parts[1])
            except ValueError:
                return 0
    return 0


def _set_peer(
    iface: str,
    peer_pubkey: str,
    endpoint: str,
    allowed_ips: str,
    keepalive: int,
    timeout: float,
) -> None:
    _wg(["set", iface, "peer", peer_pubkey, "remove"], timeout=timeout)
    _wg(
        [
            "set",
            iface,
            "peer",
            peer_pubkey,
            "endpoint",
            endpoint,
            "allowed-ips",
            allowed_ips,
            "persistent-keepalive",
            str(keepalive),
        ],
        timeout=timeout,
    )


def _ping(target: str, timeout: float) -> None:
    with suppress(subprocess.TimeoutExpired, FileNotFoundError, OSError):
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", target],
            capture_output=True,
            timeout=max(timeout, 2.0),
        )


def probe(
    *,
    iface: str,
    peer_pubkey: str,
    test_endpoint: str,
    orig_endpoint: str,
    allowed_ips: str,
    keepalive: int = 25,
    timeout: float = 10.0,
    ping_target: str | None = None,
) -> Verdict:
    """Force a fresh WG handshake against test_endpoint and observe epoch advance."""
    t0 = time.monotonic()
    try:
        pre_epoch = _get_epoch(iface, peer_pubkey, timeout=2.0)
    except (FileNotFoundError, WgCommandError, subprocess.SubprocessError, OSError) as e:
        return Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=f"wg binary not available: {type(e).__name__}: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
        )

    post_epoch = pre_epoch
    mutated_peer = False
    test_verdict: Verdict | None = None
    try:
        mutated_peer = True
        _set_peer(iface, peer_pubkey, test_endpoint, allowed_ips, keepalive, timeout=2.0)
        if ping_target:
            _ping(ping_target, timeout=2.0)

        deadline = time.monotonic() + min(_POLL_WINDOW_S, timeout)
        while time.monotonic() < deadline:
            post_epoch = _get_epoch(iface, peer_pubkey, timeout=1.5)
            if post_epoch > pre_epoch:
                break
            time.sleep(_POLL_INTERVAL_S)
    except (FileNotFoundError, WgCommandError, subprocess.SubprocessError, OSError) as e:
        test_verdict = Verdict(
            code=VerdictCode.ERROR_INTERNAL,
            reason=f"wg probe failed: {type(e).__name__}: {e}",
            latency_ms=(time.monotonic() - t0) * 1000.0,
        )
    finally:
        if mutated_peer:
            try:
                _set_peer(iface, peer_pubkey, orig_endpoint, allowed_ips, keepalive, timeout=2.0)
                if ping_target:
                    _ping(ping_target, timeout=1.0)
            except (FileNotFoundError, WgCommandError, subprocess.SubprocessError, OSError) as e:
                previous = test_verdict.code.value if test_verdict is not None else "UNKNOWN"
                test_verdict = Verdict(
                    code=VerdictCode.ERROR_INTERNAL,
                    reason=f"wg restore failed after {previous}: {type(e).__name__}: {e}",
                    latency_ms=(time.monotonic() - t0) * 1000.0,
                    extra={
                        "previous_verdict": previous,
                        "iface": iface,
                        "orig_endpoint": orig_endpoint,
                    },
                )

    if test_verdict is not None:
        return test_verdict

    latency_ms = (time.monotonic() - t0) * 1000.0
    extra = {
        "epoch_pre": pre_epoch,
        "epoch_post": post_epoch,
        "iface": iface,
        "test_endpoint": test_endpoint,
    }
    if post_epoch > pre_epoch:
        return Verdict(
            code=VerdictCode.WG_REKEY_PASS,
            reason=f"fresh WG handshake against {test_endpoint} completed",
            latency_ms=latency_ms,
            extra=extra,
        )
    return Verdict(
        code=VerdictCode.WG_REKEY_BLOCKED,
        reason=f"no fresh WG handshake against {test_endpoint} within {_POLL_WINDOW_S:.0f}s",
        latency_ms=latency_ms,
        extra=extra,
    )
