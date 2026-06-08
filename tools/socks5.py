"""Минимальный SOCKS5-сервер — upstream туннеля для FoxyProxy и браузинга.

Зачем SOCKS5, а не CONNECT-прокси: FoxyProxy/браузер через SOCKS5 гонят ВЕСЬ
трафик (и http://, и https://), резолвят DNS на стороне прокси (без утечки) и
корректно проходят встроенный Test/Ping. CONNECT-прокси умеет только HTTPS.

Ставится как target туннеля (на хосте-«выходе»):
    python tools/socks5.py --port 8888
затем в конфиге server.target = 127.0.0.1:8888, а в FoxyProxy — тип SOCKS5,
127.0.0.1:1080, и галка «Proxy DNS when using SOCKS v5».

Без аутентификации, только CMD=CONNECT — достаточно для стенда. Не выставляй
наружу: это открытый прокси, держи на 127.0.0.1.
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
import threading
import time
from itertools import count

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logconf import get_logger, setup_logging  # noqa: E402

log = get_logger("socks5")
_counter = count(1)

VER = 0x05
NO_AUTH = 0x00
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REP_OK = 0x00
REP_GENERAL_FAIL = 0x01
REP_CMD_NOT_SUPPORTED = 0x07


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


class Socks5Proxy:
    def __init__(self, bind=("127.0.0.1", 1081)):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(bind)
        self._sock.listen(64)
        self.addr = self._sock.getsockname()
        self._running = False

    def start(self) -> "Socks5Proxy":
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
        cid = f"X{next(_counter):04d}"
        try:
            if not self._greeting(conn):
                conn.close(); return
            upstream = self._request(conn, cid)
            if upstream is None:
                conn.close(); return
        except OSError:
            conn.close(); return
        _relay(conn, upstream)

    def _greeting(self, conn: socket.socket) -> bool:
        head = _recv_exact(conn, 2)
        if not head or head[0] != VER:
            return False
        nmethods = head[1]
        if _recv_exact(conn, nmethods) is None:
            return False
        conn.sendall(bytes([VER, NO_AUTH]))  # без аутентификации
        return True

    def _request(self, conn: socket.socket, cid: str):
        head = _recv_exact(conn, 4)
        if not head or head[0] != VER:
            return None
        cmd, _, atyp = head[1], head[2], head[3]
        if cmd != CMD_CONNECT:
            log.warning("%s неподдерживаемая команда %d", cid, cmd)
            self._reply(conn, REP_CMD_NOT_SUPPORTED)
            return None
        if atyp == ATYP_IPV4:
            raw = _recv_exact(conn, 4)
            host = socket.inet_ntoa(raw) if raw else None
        elif atyp == ATYP_DOMAIN:
            ln = _recv_exact(conn, 1)
            # домен в SOCKS5 — ASCII (IDN приходит как punycode A-label)
            host = _recv_exact(conn, ln[0]).decode("ascii", "replace") if ln else None
        elif atyp == ATYP_IPV6:
            raw = _recv_exact(conn, 16)
            host = socket.inet_ntop(socket.AF_INET6, raw) if raw else None
        else:
            self._reply(conn, REP_CMD_NOT_SUPPORTED)
            return None
        port_raw = _recv_exact(conn, 2)
        if host is None or port_raw is None:
            self._reply(conn, REP_GENERAL_FAIL)
            return None
        port = struct.unpack(">H", port_raw)[0]
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except OSError as exc:
            log.warning("%s CONNECT %s:%d — отказ: %s", cid, host, port, exc)
            self._reply(conn, REP_GENERAL_FAIL)
            return None
        log.info("%s CONNECT %s:%d ok", cid, host, port)
        self._reply(conn, REP_OK)
        return upstream

    @staticmethod
    def _reply(conn: socket.socket, rep: int):
        # VER REP RSV ATYP=IPv4 BND.ADDR=0.0.0.0 BND.PORT=0
        conn.sendall(bytes([VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]))

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


def main():
    p = argparse.ArgumentParser(description="Минимальный SOCKS5 для стенда (без auth, только 127.0.0.1)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=1081)
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = p.parse_args()
    setup_logging(args.log_level)
    proxy = Socks5Proxy((args.host, args.port)).start()
    log.info("SOCKS5 на %s:%d — Ctrl+C для остановки", proxy.addr[0], proxy.addr[1])
    # time.sleep прерывается Ctrl+C на Windows, а Event.wait() без таймаута — нет.
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        proxy.stop()
        log.info("остановлено")


if __name__ == "__main__":
    main()
