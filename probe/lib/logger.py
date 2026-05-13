"""Optional syslog logger — one line per probe invocation.

Operators can grep /var/log/syslog (or journalctl -t dpi_probe) without
opening Zabbix. Off by default; enable with env var DPI_PROBE_SYSLOG=1.

Failure to log is never fatal — syslog may be unreachable in a container,
on macOS dev boxes, etc. We swallow errors silently.
"""

from __future__ import annotations

import contextlib
import logging
import logging.handlers
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from probe.lib.verdict import Verdict


_LOGGER: logging.Logger | None = None


def _init() -> logging.Logger | None:
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER
    if os.environ.get("DPI_PROBE_SYSLOG", "") != "1":
        return None
    try:
        handler = logging.handlers.SysLogHandler(address="/dev/log")
    except OSError:
        return None
    handler.ident = "dpi_probe: "
    log = logging.getLogger("dpi_probe")
    log.setLevel(logging.INFO)
    log.addHandler(handler)
    log.propagate = False
    _LOGGER = log
    return log


def log_verdict(target: str, kind: str, port: int, dns: str, v: Verdict) -> None:
    """Emit one syslog line per probe invocation. Silent on failure."""
    log = _init()
    if log is None:
        return
    # syslog daemon may have died between _init and now — never fatal.
    with contextlib.suppress(Exception):
        log.info(
            "target=%s kind=%s port=%d dns=%s verdict=%s latency_ms=%.1f reason=%s",
            target,
            kind,
            port,
            dns,
            v.code.value,
            v.latency_ms,
            v.reason,
        )
