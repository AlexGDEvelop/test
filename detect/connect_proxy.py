"""Минимальный HTTP CONNECT-прокси — upstream туннеля для генерации датасета.

Зачем: чтобы positive-класс нёс ТОТ ЖЕ реальный веб-ворклоад, что и negative.
Клиент ходит через локальный порт туннеля как через HTTPS-прокси (CONNECT
host:443), туннель доставляет байты на сервер, сервер форвардит в этот прокси,
прокси набирает реальный сайт. Итог: и через туннель, и напрямую тянется один и
тот же URL — различается ТОЛЬКО транспорт. Без этого детектор делит классы по
приложению (echo vs браузинг), а не по обёртке (блокер ревью Этапа 4).
"""
from __future__ import annotations

import socket
import threading
from itertools import count
from typing import Optional

from logconf import get_logger

log = get_logger("connect")
_counter = count(1)


class ConnectProxy:
    def __init__(self, bind=("127.0.0.1", 0)):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(bind)
        self._sock.listen(32)
        self.addr = self._sock.getsockname()
        self._running = False

    def start(self) -> "ConnectProxy":
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()
        return self

    def _loop(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket):
        cid = f"P{next(_counter):04d}"
        try:
            req = self._read_headers(conn)
            if req is None or not req.upper().startswith("CONNECT"):
                log.warning("conn %s не CONNECT-запрос (CONNECT-прокси только HTTPS)", cid)
                conn.close(); return
            target = req.split()[1]  # host:port
            host, _, port = target.partition(":")
            upstream = socket.create_connection((host, int(port or 443)), timeout=15)
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            log.info("conn %s CONNECT %s ok", cid, target)
        except (OSError, ValueError, IndexError) as exc:
            log.warning("conn %s CONNECT отказ: %s", cid, exc)
            conn.close(); return
        _relay(conn, upstream)

    @staticmethod
    def _read_headers(conn: socket.socket) -> Optional[str]:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(1024)
            if not chunk:
                return None
            buf += chunk
            if len(buf) > 16384:
                return None
        return buf.split(b"\r\n", 1)[0].decode("latin1")

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass


def _relay(a: socket.socket, b: socket.socket):
    stop = threading.Event()

    def pump(src, dst):
        try:
            while not stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            stop.set()
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()
    a.close(); b.close()
