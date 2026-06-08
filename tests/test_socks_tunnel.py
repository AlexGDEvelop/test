"""Тест локального SOCKS5-клиента + динамического сервера (браузинг через FoxyProxy).

Цепочка: SOCKS5-клиент (ручной) -> Socks5TunnelClient (локальный SOCKS5) ->
Noise-туннель -> TcpTunnelServer (динамический target) -> эхо «сайт».
Проверяем, что адрес назначения долетает от клиента до сервера и трафик ходит.

Запуск: python tests/test_socks_tunnel.py
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tunnel import keys
from tunnel.socks_client import Socks5TunnelClient
from tunnel.tcp_tunnel import TcpTunnelServer


def _astr(addr):
    return f"{addr[0]}:{addr[1]}"


class TcpEcho:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.addr = self.sock.getsockname()
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.running:
            try:
                c, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._h, args=(c,), daemon=True).start()

    def _h(self, c):
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()

    def stop(self):
        self.running = False
        self.sock.close()


def _socks5_connect(proxy_addr, target_host, target_port):
    """Минимальный SOCKS5-клиент: вернуть установленный сокет к target через proxy."""
    s = socket.create_connection(proxy_addr, timeout=5)
    s.sendall(bytes([5, 1, 0]))                     # greeting: no-auth
    assert s.recv(2) == bytes([5, 0]), "greeting"
    host = target_host.encode("ascii")
    s.sendall(bytes([5, 1, 0, 3, len(host)]) + host + struct.pack(">H", target_port))
    rep = s.recv(10)
    assert rep[1] == 0, f"socks reply code {rep[1]}"
    return s


def test_socks_tunnel_dynamic_dial():
    echo = TcpEcho()
    s, c = keys.generate(), keys.generate()
    # сервер в ДИНАМИЧЕСКОМ режиме (target=None) — адрес придёт от клиента
    server = TcpTunnelServer(bind="127.0.0.1:0", target=None,
                             static_private=s.private).start()
    socks = Socks5TunnelClient(local_bind="127.0.0.1:0",
                               server_addr=_astr(server.address),
                               static_private=c.private, server_public=s.public).start()
    time.sleep(0.2)
    try:
        # SOCKS5 CONNECT на эхо «сайт» через локальный SOCKS5-клиент
        sk = _socks5_connect(socks.address, echo.addr[0], echo.addr[1])
        payload = b"HELLO-VIA-SOCKS-" + os.urandom(64)
        sk.sendall(payload)
        buf = b""
        sk.settimeout(5)
        while len(buf) < len(payload):
            chunk = sk.recv(65536)
            if not chunk:
                break
            buf += chunk
        sk.close()
        assert buf == payload, f"эхо через SOCKS-туннель сломано ({len(buf)}/{len(payload)})"
        print("OK test_socks_tunnel_dynamic_dial "
              "(SOCKS5 локально -> туннель -> динамический dial на сервере)")
    finally:
        socks.stop(); server.stop(); echo.stop()


def _run_all():
    failed = 0
    for t in (test_socks_tunnel_dynamic_dial,):
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}: {exc!r}")
    print(f"\n{1 - failed}/1 прошло")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
