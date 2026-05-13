"""Shared pytest fixtures for probe tests.

`tcp_responder` spawns a tiny socket server that can:
  - accept and read N bytes, then send a canned response;
  - accept and immediately close (clean FIN);
  - accept and reset (RST via SO_LINGER 0);
  - refuse (bind but don't listen — emulated by closing the socket post-accept);
  - never accept (port bound but no accept loop — emulates DROP / timeout).

Usage in a test:
    def test_xxx(tcp_responder):
        port = tcp_responder.start(mode="accept_read_send", read_bytes=5, response=b"HELLO")
        ... call probe ...
"""

from __future__ import annotations

import contextlib
import socket
import struct
import threading
from collections.abc import Iterator

import pytest


class TcpResponder:
    """Programmable TCP server bound to 127.0.0.1 on a random port."""

    def __init__(self) -> None:
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0
        self._mode: str = ""
        self._read_bytes: int = 0
        self._response: bytes = b""
        self._stop = threading.Event()

    def start(
        self,
        mode: str,
        *,
        read_bytes: int = 0,
        response: bytes = b"",
    ) -> int:
        """Start the responder. Returns the bound port.

        Modes:
          "accept_read_send": read N bytes then send `response`, then close.
          "accept_close_fin": accept and immediately close (FIN).
          "accept_rst":       accept and send RST via SO_LINGER(on=1, linger=0).
          "no_accept":        bind but never accept — clients see timeout.
          "accept_send_then_rst": accept, send `response`, then RST.
        """
        self._mode = mode
        self._read_bytes = read_bytes
        self._response = response
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        if mode == "no_accept":
            return self.port
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self.port

    def _serve(self) -> None:
        assert self._sock is not None
        try:
            self._sock.settimeout(5.0)
            client, _ = self._sock.accept()
        except OSError:
            return
        try:
            if self._mode == "accept_close_fin":
                client.close()
                return
            if self._mode == "accept_rst":
                linger = struct.pack("ii", 1, 0)  # on=1, linger=0 → RST on close
                client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                client.close()
                return
            if self._mode == "accept_read_send":
                if self._read_bytes:
                    client.settimeout(2.0)
                    with contextlib.suppress(OSError):
                        client.recv(self._read_bytes)
                if self._response:
                    with contextlib.suppress(OSError):
                        client.sendall(self._response)
                client.close()
                return
            if self._mode == "accept_send_then_rst":
                if self._response:
                    with contextlib.suppress(OSError):
                        client.sendall(self._response)
                linger = struct.pack("ii", 1, 0)
                client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                client.close()
                return
        finally:
            client.close()

    def stop(self) -> None:
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


@pytest.fixture
def tcp_responder() -> Iterator[TcpResponder]:
    r = TcpResponder()
    try:
        yield r
    finally:
        r.stop()
