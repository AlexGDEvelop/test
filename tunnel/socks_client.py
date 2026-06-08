"""Локальный SOCKS5-сервер внутри клиента: браузер/FoxyProxy -> сюда -> туннель.

Правильная схема (как shadowsocks): SOCKS5 терминируется ЛОКАЛЬНО (127.0.0.1),
по сети идёт только Noise. Адрес назначения из SOCKS5-CONNECT передаётся серверу
ПЕРВЫМ зашифрованным кадром после хендшейка; сервер должен быть в ДИНАМИЧЕСКОМ
режиме (target=None в конфиге). SOCKS5 на проводе не появляется, поэтому его
сетевые блокировки нас не касаются.
"""
from __future__ import annotations

import socket
import threading
from itertools import count
from typing import Optional, Tuple

from logconf import get_logger

from . import DEFAULT_PROLOGUE
from .framing import recv_exact, recv_frame, send_frame
from .noise_session import new_initiator
from .tcp_tunnel import _addr, _splice

log = get_logger("socks")
_counter = count(1)
_SOCKS_OK = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # succeeded, BND 0.0.0.0:0


def _socks5_accept(conn: socket.socket) -> Optional[Tuple[str, int]]:
    """Принять SOCKS5 greeting+CONNECT, вернуть (host, port). None при ошибке."""
    head = recv_exact(conn, 2)
    if not head or head[0] != 0x05:
        return None
    if recv_exact(conn, head[1]) is None:   # methods
        return None
    conn.sendall(b"\x05\x00")               # выбираем no-auth
    req = recv_exact(conn, 4)
    if not req or req[0] != 0x05:
        return None
    cmd, atyp = req[1], req[3]
    if cmd != 0x01:                         # только CONNECT
        conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        return None
    if atyp == 0x01:                        # IPv4
        raw = recv_exact(conn, 4)
        host = socket.inet_ntoa(raw) if raw else None
    elif atyp == 0x03:                      # domain
        ln = recv_exact(conn, 1)
        host = recv_exact(conn, ln[0]).decode("ascii", "replace") if ln else None
    elif atyp == 0x04:                      # IPv6
        raw = recv_exact(conn, 16)
        host = socket.inet_ntop(socket.AF_INET6, raw) if raw else None
    else:
        conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
        return None
    pr = recv_exact(conn, 2)
    if host is None or pr is None:
        return None
    return host, int.from_bytes(pr, "big")


class Socks5TunnelClient:
    """Локальный SOCKS5; каждый CONNECT уводит в Noise-туннель к серверу."""

    def __init__(self, local_bind: str, server_addr: str, static_private: bytes,
                 server_public: bytes, prologue: bytes = DEFAULT_PROLOGUE):
        self._local = _addr(local_bind)
        self._server = _addr(server_addr)
        self._priv = static_private
        self._server_pub = server_public
        self._prologue = prologue
        self._sock: Optional[socket.socket] = None
        self._running = False

    @property
    def address(self):
        return self._sock.getsockname() if self._sock else self._local

    def start(self) -> "Socks5TunnelClient":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self._local)
        self._sock.listen(64)
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self

    def _accept_loop(self):
        while self._running:
            try:
                browser, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(browser,), daemon=True).start()

    def _handle(self, browser: socket.socket):
        cid = f"K{next(_counter):04d}"
        dest = _socks5_accept(browser)
        if dest is None:
            log.warning("conn %s неверный SOCKS5-запрос", cid)
            browser.close(); return
        host, port = dest
        try:
            server = socket.create_connection(self._server)
            conn = new_initiator(self._priv, self._server_pub, self._prologue)
            send_frame(server, conn.write_message())                 # msg1
            msg2 = recv_frame(server)
            if msg2 is None:
                log.warning("conn %s сервер не ответил (handshake)", cid)
                browser.close(); return
            conn.read_message(msg2)
            if not conn.handshake_finished:
                log.warning("conn %s handshake failed", cid)
                browser.close(); server.close(); return
            # первый кадр после хендшейка = адрес назначения (динамический target)
            send_frame(server, conn.encrypt(f"{host}:{port}".encode("ascii")))
            browser.sendall(_SOCKS_OK)
            log.info("conn %s SOCKS5 -> %s:%d через туннель", cid, host, port)
        except Exception as exc:  # noqa: BLE001
            log.warning("conn %s setup error: %s", cid, exc)
            browser.close(); return
        _splice(browser, server, conn, cid)

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
