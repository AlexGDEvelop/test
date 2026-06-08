"""Базовый carrier без обфускации: Noise-фреймы поверх TCP с префиксом длины.

Это эталон «голого» ядра (см. компромиссы Этапа 2): узнаваемая структура, по
которой детектор Этапа 4 меряет, СКОЛЬКО даёт каждый обфускация-модуль
относительно немаскированного транспорта.
"""
from __future__ import annotations

import socket
import threading
from typing import Callable, Optional

from tunnel.framing import recv_frame as _recv_frame
from tunnel.framing import send_frame as _send_frame

from .base import Carrier, CarrierClient, CarrierServer, CostStats


def _addr(value):
    host, port = value.rsplit(":", 1)
    return (host, int(port))


class TcpFrameCarrier(Carrier):
    """Carrier поверх установленного TCP-сокета (2-байтовый префикс длины)."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.cost = CostStats()

    def send_frame(self, frame: bytes) -> None:
        _send_frame(self._sock, frame)
        self.cost.payload_bytes += len(frame)
        self.cost.payload_frames += 1
        self.cost.wire_bytes += len(frame) + 2  # +2 префикс длины
        self.cost.wire_segments += 1

    def recv_frame(self) -> Optional[bytes]:
        return _recv_frame(self._sock)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


class PlainTcpClient(CarrierClient):
    def __init__(self, server_addr: str):
        self._server = _addr(server_addr)

    def connect(self) -> Carrier:
        sock = socket.create_connection(self._server)
        return TcpFrameCarrier(sock)


class PlainTcpServer(CarrierServer):
    def __init__(self, bind: str, on_carrier: Callable[[Carrier], None]):
        self._bind = _addr(bind)
        self._on_carrier = on_carrier
        self._sock: Optional[socket.socket] = None
        self._running = False

    @property
    def address(self):
        return self._sock.getsockname() if self._sock else self._bind

    def start(self) -> "PlainTcpServer":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self._bind)
        self._sock.listen(16)
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self

    def _accept_loop(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            carrier = TcpFrameCarrier(conn)
            threading.Thread(target=self._on_carrier, args=(carrier,),
                             daemon=True).start()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
