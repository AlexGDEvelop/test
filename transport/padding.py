"""Модуль (c): random-padding + fragmentation поверх TCP-ядра.

Цель — размыть статистику размеров/таймингов (векторы V1/V2 Этапа 1). Каждый
логический Noise-фрейм может:
  - дробиться на фрагменты (knob: max_fragment_payload),
  - паддиться случайными байтами до целевого размера (knobs: min/max_size),
  - отправляться с искусственной задержкой (knobs: min/max_delay_s).

Каждая крутилка СРАЗУ логирует свою цену в CostStats (overhead полосы, число
сегментов, внесённая задержка) — без оси стоимости кривую «детектируемость vs
цена» на Этапе 4 не построить (договорённость Этапа 1).

Честное ограничение: точная форма пакетов на проводе зависит от TCP
(сегментация/коалесценция). Мы ставим TCP_NODELAY и шлём каждый фрагмент
отдельным вызовом, но идеальный контроль размеров пакета на потоке недостижим —
это аргумент в пользу датаграммных модулей (b) для строгого шейпинга.

Формат фрагмента (внутри внешнего 2-байтового префикса длины):
    flags(1) | payload_len(2, BE) | payload[payload_len] | pad[...]
flags bit0 = последний фрагмент логического фрейма.
"""
from __future__ import annotations

import random
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from tunnel.framing import MAX_FRAME, recv_frame as _recv_frame
from tunnel.framing import send_frame as _send_frame

from .base import Carrier, CarrierClient, CarrierServer, CostStats

_HDR = 3            # flags(1) + payload_len(2)
_OUTER = 2          # внешний префикс длины (framing.send_frame)
_FLAG_LAST = 0x01
_MAX_PAYLOAD = MAX_FRAME - _HDR  # макс. полезного в одном фрагменте


@dataclass
class PaddingPolicy:
    """Параметры обёртки. Любой набор = переключаемая конфигурация для Этапа 4."""
    max_fragment_payload: Optional[int] = None  # None = без фрагментации
    min_size: int = 0            # целевой ВНЕШНИЙ размер фрагмента (вкл. префикс)
    max_size: int = 0            # 0/0 = без паддинга
    min_delay_s: float = 0.0
    max_delay_s: float = 0.0     # 0/0 = без задержек
    seed: Optional[int] = None
    rng: random.Random = field(init=False, repr=False)

    def __post_init__(self):
        self.rng = random.Random(self.seed)
        if self.max_fragment_payload is not None:
            self.max_fragment_payload = max(1, min(self.max_fragment_payload, _MAX_PAYLOAD))

    def target_size(self) -> int:
        return self.rng.randint(self.min_size, self.max_size) if self.max_size else 0

    def delay(self) -> float:
        if self.max_delay_s <= 0:
            return 0.0
        return self.rng.uniform(self.min_delay_s, self.max_delay_s)

    def pad(self, n: int) -> bytes:
        return self.rng.randbytes(n)


def _split(data: bytes, n: Optional[int]) -> List[bytes]:
    if not n or len(data) <= n:
        return [data]
    return [data[i:i + n] for i in range(0, len(data), n)]


class PaddedCarrier(Carrier):
    """Carrier с паддингом/фрагментацией/джиттером поверх TCP-сокета."""

    def __init__(self, sock: socket.socket, policy: PaddingPolicy):
        self._sock = sock
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._policy = policy
        self.cost = CostStats()

    def send_frame(self, frame: bytes) -> None:
        p = self._policy
        chunks = _split(frame, p.max_fragment_payload)
        for i, chunk in enumerate(chunks):
            delay = p.delay()
            if delay > 0:
                time.sleep(delay)
                self.cost.injected_delay_s += delay
            flags = _FLAG_LAST if i == len(chunks) - 1 else 0
            body = bytes([flags]) + len(chunk).to_bytes(2, "big") + chunk
            target = p.target_size()
            pad_len = target - (_OUTER + len(body))
            if pad_len > 0 and (_OUTER + len(body) + pad_len) <= MAX_FRAME:
                body += p.pad(pad_len)
            _send_frame(self._sock, body)
            self.cost.wire_bytes += _OUTER + len(body)
            self.cost.wire_segments += 1
        self.cost.payload_bytes += len(frame)
        self.cost.payload_frames += 1

    def recv_frame(self) -> Optional[bytes]:
        parts: List[bytes] = []
        while True:
            body = _recv_frame(self._sock)
            if body is None:
                return None  # пир закрыл (частичный фрейм отбрасываем)
            if len(body) < _HDR:
                return None
            flags = body[0]
            length = int.from_bytes(body[1:3], "big")
            parts.append(body[_HDR:_HDR + length])  # хвост-pad отбрасывается
            if flags & _FLAG_LAST:
                return b"".join(parts)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def _addr(value):
    host, port = value.rsplit(":", 1)
    return (host, int(port))


class PaddedTcpClient(CarrierClient):
    def __init__(self, server_addr: str, policy: PaddingPolicy):
        self._server = _addr(server_addr)
        self._policy = policy

    def connect(self) -> Carrier:
        sock = socket.create_connection(self._server)
        return PaddedCarrier(sock, self._policy)


class PaddedTcpServer(CarrierServer):
    def __init__(self, bind: str, on_carrier: Callable[[Carrier], None],
                 policy: PaddingPolicy):
        self._bind = _addr(bind)
        self._on_carrier = on_carrier
        self._policy = policy
        self._sock: Optional[socket.socket] = None
        self._running = False

    @property
    def address(self):
        return self._sock.getsockname() if self._sock else self._bind

    def start(self) -> "PaddedTcpServer":
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
            carrier = PaddedCarrier(conn, self._policy)
            threading.Thread(target=self._on_carrier, args=(carrier,),
                             daemon=True).start()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
