"""Тесты модуля (a) Reality-lite.

Центральная проверка (критерий ревью №1): зонд на порт сервера видит НАСТОЯЩИЙ
донор (его сертификат и его страницу), а не наш TLS/оборванное соединение.

Запуск: python tests/test_reality.py
"""
from __future__ import annotations

import os
import socket
import ssl
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tunnel import keys
from transport.carrier_tunnel import CarrierTunnelClient, CarrierTunnelServer
from transport.reality import ControlTlsDonor, RealityClient, RealityServer
from transport.tls_util import generate_self_signed, parse_sni

MARKER = b"PLAINTEXT-MARKER-0xDEADBEEF"
TUNNEL_SNI = "s3cr3t.tunnel.invalid"


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


def test_clienthello_sni_parser():
    """Парсер SNI на НАСТОЯЩЕМ ClientHello от OpenSSL (а не на ручной подделке)."""
    lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lst.bind(("127.0.0.1", 0)); lst.listen(1)
    addr = lst.getsockname()

    def client():
        try:
            ctx = ssl._create_unverified_context()
            s = socket.create_connection(addr, timeout=2)
            s.settimeout(1)
            ctx.wrap_socket(s, server_hostname="example.parser.test")
        except Exception:
            pass  # хендшейк не завершится (сервер не отвечает) — нам нужен лишь ClientHello

    threading.Thread(target=client, daemon=True).start()
    conn, _ = lst.accept()
    data = conn.recv(4096, socket.MSG_PEEK)
    sni = parse_sni(data)
    conn.close(); lst.close()
    assert sni == "example.parser.test", f"SNI распознан неверно: {sni!r}"
    print("OK test_clienthello_sni_parser")


def test_probe_sees_real_donor():
    """Зонд с обычным SNI получает сертификат И страницу донора, не нашего сервера."""
    donor_cert, donor_key = generate_self_signed("donor.local")
    srv_cert, srv_key = generate_self_signed("reality.local")
    donor = ControlTlsDonor("127.0.0.1:0", donor_cert, donor_key,
                            body=b"REAL-DONOR-CONTENT").start()
    reality = RealityServer("127.0.0.1:0", on_carrier=lambda c: c.close(),
                            donor=_astr(donor.address), cert=srv_cert, key=srv_key,
                            tunnel_sni=TUNNEL_SNI).start()
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(donor_cert)  # доверяем ТОЛЬКО донору
        ctx.check_hostname = True               # имя обязано совпасть с cert донора
        raw = socket.create_connection(reality.address, timeout=5)
        # SNI != tunnel_sni -> сервер обязан проксировать на донор
        tls = ctx.wrap_socket(raw, server_hostname="donor.local")
        # Хендшейк прошёл проверку против сертификата ДОНОРА => это его cert,
        # а не reality.local (тот бы не прошёл verify как donor.local).
        assert tls.version() == "TLSv1.3"
        tls.sendall(b"GET / HTTP/1.1\r\nHost: donor.local\r\nConnection: close\r\n\r\n")
        resp = b""
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            resp += chunk
        tls.close()
        assert b"REAL-DONOR-CONTENT" in resp, "зонд не увидел страницу донора"
        print("OK test_probe_sees_real_donor (зонд получил cert+страницу донора через TLS 1.3)")
    finally:
        reality.stop(); donor.stop()


def test_tunnel_through_reality_tls13():
    """Полный Noise-туннель внутри настоящего TLS 1.3 (наш клиент по tunnel_sni)."""
    echo = TcpEcho()
    donor_cert, donor_key = generate_self_signed("donor.local")
    srv_cert, srv_key = generate_self_signed("reality.local")
    donor = ControlTlsDonor("127.0.0.1:0", donor_cert, donor_key).start()
    s, c = keys.generate(), keys.generate()

    server = CarrierTunnelServer(
        make_server=lambda h: RealityServer(
            "127.0.0.1:0", h, donor=_astr(donor.address),
            cert=srv_cert, key=srv_key, tunnel_sni=TUNNEL_SNI),
        target=_astr(echo.addr), static_private=s.private).start()
    client_factory = RealityClient(_astr(server.address), tunnel_sni=TUNNEL_SNI,
                                   server_cert=srv_cert)
    client = CarrierTunnelClient("127.0.0.1:0", carrier_client=client_factory,
                                 static_private=c.private, server_public=s.public).start()
    try:
        conn = socket.create_connection(client.address, timeout=5)
        payload = MARKER + os.urandom(1500)
        conn.sendall(payload)
        buf = b""
        conn.settimeout(5)
        while len(buf) < len(payload):
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
        conn.close()
        assert buf == payload, f"echo через Reality-туннель сломан ({len(buf)}/{len(payload)})"
        assert client_factory.last_tls_version == "TLSv1.3", \
            f"внешний слой не TLS 1.3: {client_factory.last_tls_version}"
        print("OK test_tunnel_through_reality_tls13 (Noise внутри настоящего TLS 1.3)")
    finally:
        client.stop(); server.stop(); donor.stop(); echo.stop()


def _run_all():
    tests = [
        test_clienthello_sni_parser,
        test_probe_sees_real_donor,
        test_tunnel_through_reality_tls13,
    ]
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
