"""Помощники кадрирования для TCP-потока.

TCP — это байтовый поток, поэтому каждое Noise-сообщение предваряется
2-байтовым префиксом длины (big-endian). Noise-сообщение и так не превышает
65535 байт, что укладывается в 2 байта.
"""
from __future__ import annotations

import socket

LEN_PREFIX = 2
MAX_FRAME = (1 << (8 * LEN_PREFIX)) - 1  # 65535


def recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Прочитать ровно n байт; None при закрытии соединения."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock: socket.socket, data: bytes) -> None:
    if len(data) > MAX_FRAME:
        raise ValueError(f"кадр {len(data)} > {MAX_FRAME}")
    sock.sendall(len(data).to_bytes(LEN_PREFIX, "big") + data)


def recv_frame(sock: socket.socket) -> bytes | None:
    header = recv_exact(sock, LEN_PREFIX)
    if header is None:
        return None
    return recv_exact(sock, int.from_bytes(header, "big"))
