"""Tests for probe_wg_rekey: kernel-`wg` fresh-handshake probe."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from unittest import mock

import pytest

from probe.lib import probe_wg_rekey
from probe.lib.verdict import VerdictCode


def _mock_wg_runner(scripted_outputs: list[tuple[str, str]]) -> Callable[..., mock.Mock]:
    it = iter(scripted_outputs)

    def runner(cmd: list[str], **kwargs: object) -> mock.Mock:
        try:
            out, err = next(it)
        except StopIteration:
            out, err = "", ""
        return mock.Mock(returncode=0, stdout=out, stderr=err)

    return runner


def test_wg_rekey_pass_when_epoch_advances(monkeypatch: pytest.MonkeyPatch) -> None:
    pre_epoch = int(time.time()) - 60
    post_epoch = int(time.time())
    scripted = [
        (f"PEERPUB\t{pre_epoch}\n", ""),
        ("", ""),
        ("", ""),
        (f"PEERPUB\t{post_epoch}\n", ""),
        ("", ""),
        ("", ""),
    ]
    monkeypatch.setattr(subprocess, "run", _mock_wg_runner(scripted))
    monkeypatch.setattr(time, "sleep", lambda s: None)

    v = probe_wg_rekey.probe(
        iface="wg_ifp",
        peer_pubkey="PEERPUB",
        test_endpoint="65.21.40.204:5599",
        orig_endpoint="127.0.0.1:5599",
        allowed_ips="192.168.255.1/32",
        keepalive=25,
        timeout=10.0,
        ping_target=None,
    )
    assert v.code == VerdictCode.WG_REKEY_PASS, f"got {v.code}: {v.reason}"
    assert v.extra["epoch_pre"] == pre_epoch
    assert v.extra["epoch_post"] == post_epoch


def test_wg_rekey_blocked_when_epoch_stays(monkeypatch: pytest.MonkeyPatch) -> None:
    pre_epoch = int(time.time()) - 60
    scripted = [
        (f"PEERPUB\t{pre_epoch}\n", ""),
        ("", ""),
        ("", ""),
        *[(f"PEERPUB\t{pre_epoch}\n", "") for _ in range(15)],
        ("", ""),
        ("", ""),
    ]
    monkeypatch.setattr(subprocess, "run", _mock_wg_runner(scripted))
    monkeypatch.setattr(time, "sleep", lambda s: None)
    monkeypatch.setattr(probe_wg_rekey, "_POLL_WINDOW_S", 0.1)

    v = probe_wg_rekey.probe(
        iface="wg_ifp",
        peer_pubkey="PEERPUB",
        test_endpoint="65.21.40.204:5599",
        orig_endpoint="127.0.0.1:5599",
        allowed_ips="192.168.255.1/32",
        keepalive=25,
        timeout=5.0,
        ping_target=None,
    )
    assert v.code == VerdictCode.WG_REKEY_BLOCKED, f"got {v.code}: {v.reason}"


def test_wg_rekey_internal_error_when_wg_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError("no wg binary")

    monkeypatch.setattr(subprocess, "run", boom)
    v = probe_wg_rekey.probe(
        iface="wg_ifp",
        peer_pubkey="PEERPUB",
        test_endpoint="65.21.40.204:5599",
        orig_endpoint="127.0.0.1:5599",
        allowed_ips="192.168.255.1/32",
        keepalive=25,
        timeout=2.0,
        ping_target=None,
    )
    assert v.code == VerdictCode.ERROR_INTERNAL
    assert "no wg binary" in v.reason or "FileNotFoundError" in v.reason


def test_wg_rekey_restore_runs_even_if_test_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pre_epoch = int(time.time()) - 60
    calls: list[list[str]] = []

    def tracking_runner(cmd: list[str], **kwargs: object) -> mock.Mock:
        calls.append(list(cmd))
        if cmd[:3] == ["sudo", "wg", "show"]:
            return mock.Mock(returncode=0, stdout=f"PEERPUB\t{pre_epoch}\n", stderr="")
        return mock.Mock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", tracking_runner)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    monkeypatch.setattr(probe_wg_rekey, "_POLL_WINDOW_S", 0.1)

    probe_wg_rekey.probe(
        iface="wg_ifp",
        peer_pubkey="PEERPUB",
        test_endpoint="65.21.40.204:5599",
        orig_endpoint="127.0.0.1:5599",
        allowed_ips="192.168.255.1/32",
        keepalive=25,
        timeout=2.0,
        ping_target=None,
    )
    restore_call = next((c for c in calls if "127.0.0.1:5599" in c), None)
    assert restore_call is not None, f"no restore call to orig endpoint found in {calls}"
