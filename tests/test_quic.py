"""Тест модуля (b): Noise-туннель внутри настоящего QUIC (aioquic, ALPN h3).

Запуск: python tests/test_quic.py
"""
from __future__ import annotations

import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tunnel import keys
from transport.carrier_tunnel import CarrierTunnelClient, CarrierTunnelServer
from transport.quic_h3 import QuicClient, QuicServer
from transport.tls_util import generate_self_signed

MARKER = b"PLAINTEXT-MARKER-0xDEADBEEF"


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


def test_tunnel_over_quic():
    echo = TcpEcho()
    cert, key = generate_self_signed("quic.local")
    s, c = keys.generate(), keys.generate()

    server = CarrierTunnelServer(
        make_server=lambda h: QuicServer("127.0.0.1:0", h, cert=cert, key=key),
        target=_astr(echo.addr), static_private=s.private).start()
    client_factory = QuicClient(_astr(server.address), server_cert=cert,
                                server_name="quic.local")
    client = CarrierTunnelClient(local_bind="127.0.0.1:0",
                                 carrier_client=client_factory,
                                 static_private=c.private, server_public=s.public).start()
    try:
        conn = socket.create_connection(client.address, timeout=10)
        payload = MARKER + os.urandom(1500)
        conn.sendall(payload)
        buf = b""
        conn.settimeout(10)
        while len(buf) < len(payload):
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
        conn.close()
        assert buf == payload, f"echo через QUIC-туннель сломан ({len(buf)}/{len(payload)})"
        print("OK test_tunnel_over_quic (Noise внутри настоящего QUIC/h3)")
    finally:
        client.stop(); server.stop(); echo.stop()


def _run_all():
    tests = [test_tunnel_over_quic]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}: {exc!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} прошло")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
