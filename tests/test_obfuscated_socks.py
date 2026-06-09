"""Тест боевого пути: обфусцированный SOCKS-туннель (padded/reality/quic).

Цепочка как в CLI: ручной SOCKS5 -> CarrierTunnelClient (обёртка) -> Noise ->
CarrierTunnelServer -> Socks5Proxy (выход) -> эхо «сайт». Carrier строится
через ту же фабрику transports.*, что и tunnel.cli. Проверяем, что трафик ходит
сквозь каждую обёртку.

Запуск: python tests/test_obfuscated_socks.py
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.socks5 import Socks5Proxy
from transport.carrier_tunnel import CarrierTunnelClient, CarrierTunnelServer
from transport.reality import ControlTlsDonor
from transport.tls_util import generate_self_signed
from transports import TransportSpec, make_client, make_server
from tunnel import keys


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


def _socks5_connect(proxy_addr, host, port):
    s = socket.create_connection(proxy_addr, timeout=10)
    s.sendall(bytes([5, 1, 0]))
    assert s.recv(2) == bytes([5, 0]), "greeting"
    hb = host.encode("ascii")
    s.sendall(bytes([5, 1, 0, 3, len(hb)]) + hb + struct.pack(">H", port))
    rep = s.recv(10)
    assert rep[1] == 0, f"socks reply {rep[1]}"
    return s


def _spec_padded():
    return TransportSpec(name="padded"), []


def _spec_reality():
    d_cert, d_key = generate_self_signed("donor.local")
    r_cert, r_key = generate_self_signed("reality.local")
    donor = ControlTlsDonor("127.0.0.1:0", d_cert, d_key).start()
    spec = TransportSpec(name="reality", reality_donor=_astr(donor.address),
                         reality_cert=r_cert, reality_key=r_key,
                         reality_server_cert=r_cert)
    return spec, [donor]


def _spec_quic():
    q_cert, q_key = generate_self_signed("quic.local")
    spec = TransportSpec(name="quic", quic_cert=q_cert, quic_key=q_key,
                         quic_server_cert=q_cert)
    return spec, []


def _run_obfuscated(name, spec_builder):
    echo = TcpEcho()
    proxy = Socks5Proxy(("127.0.0.1", 0)).start()       # выход на «сервере»
    s, c = keys.generate(), keys.generate()
    spec, extra = spec_builder()
    server = CarrierTunnelServer(
        make_server=lambda h: make_server(spec, "127.0.0.1:0", h),
        target=_astr(proxy.addr), static_private=s.private).start()
    client = CarrierTunnelClient(
        "127.0.0.1:0", make_client(spec, _astr(server.address)),
        static_private=c.private, server_public=s.public).start()
    time.sleep(0.2)
    try:
        sk = _socks5_connect(client.address, echo.addr[0], echo.addr[1])
        payload = b"OBF-" + os.urandom(96)
        sk.sendall(payload)
        buf = b""
        sk.settimeout(10)
        while len(buf) < len(payload):
            chunk = sk.recv(65536)
            if not chunk:
                break
            buf += chunk
        sk.close()
        assert buf == payload, f"[{name}] эхо через обёртку сломано ({len(buf)}/{len(payload)})"
        print(f"  OK [{name}] SOCKS5 через обёртку -> эхо")
    finally:
        client.stop(); server.stop(); proxy.stop(); echo.stop()
        for e in extra:
            e.stop()


def test_obfuscated_socks_all_transports():
    for name, builder in (("padded", _spec_padded),
                          ("reality", _spec_reality),
                          ("quic", _spec_quic)):
        _run_obfuscated(name, builder)
    print("OK test_obfuscated_socks_all_transports "
          "(SOCKS-путь работает через padded/reality/quic из общей фабрики)")


def _run_all():
    failed = 0
    for t in (test_obfuscated_socks_all_transports,):
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}: {exc!r}")
    print(f"\n{1 - failed}/1 прошло")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
