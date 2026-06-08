"""Тесты Этапа 3: общий интерфейс carrier + модуль (c) padding/fragmentation.

Проверяем: (1) фрагментация/паддинг корректно реассемблируются; (2) ось
стоимости считается (overhead, сегменты, задержка); (3) Noise-туннель работает
поверх ЛЮБОГО carrier одинаково (plain и padded) — это и есть переключаемость.

Запуск: python tests/test_transport.py
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tunnel import keys
from transport.carrier_tunnel import CarrierTunnelClient, CarrierTunnelServer
from transport.padding import PaddedCarrier, PaddedTcpClient, PaddedTcpServer, PaddingPolicy
from transport.plain_tcp import PlainTcpClient, PlainTcpServer

MARKER = b"PLAINTEXT-MARKER-0xDEADBEEF"


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


def _astr(addr):
    return f"{addr[0]}:{addr[1]}"


def _carrier_pair(params: dict):
    a, b = socket.socketpair()
    return PaddedCarrier(a, PaddingPolicy(**params)), PaddedCarrier(b, PaddingPolicy(**params))


def _send_join(carrier, msg):
    """Отправить в потоке и дождаться завершения, чтобы cost был дописан до чтения."""
    t = threading.Thread(target=carrier.send_frame, args=(msg,), daemon=True)
    t.start()
    return t


# ------------------------------- модуль (c) -----------------------------------

def test_fragmentation_reassembly():
    ca, cb = _carrier_pair(dict(max_fragment_payload=4, seed=1))
    msg = b"abcdefghij"  # 10 байт -> 3 фрагмента по <=4
    t = _send_join(ca, msg)
    got = cb.recv_frame()
    t.join()
    assert got == msg, f"реассембли сломан: {got!r}"
    assert ca.cost.payload_frames == 1
    assert ca.cost.wire_segments == 3, f"ожидалось 3 фрагмента, было {ca.cost.wire_segments}"
    ca.close(); cb.close()
    print("OK test_fragmentation_reassembly")


def test_padding_overhead_costed():
    ca, cb = _carrier_pair(dict(min_size=300, max_size=300, seed=2))  # цель 300 байт
    payload = b"x" * 50
    t = _send_join(ca, payload)
    got = cb.recv_frame()
    t.join()
    assert got == payload
    assert ca.cost.wire_bytes == 300, f"паддинг до цели не сработал: {ca.cost.wire_bytes}"
    assert ca.cost.overhead_ratio > 1.0, "overhead не учтён"
    ca.close(); cb.close()
    print(f"OK test_padding_overhead_costed (overhead {ca.cost.overhead_ratio:.1f}x)")


def test_timing_jitter_costed():
    ca, cb = _carrier_pair(dict(max_fragment_payload=4, min_delay_s=0.01,
                                max_delay_s=0.01, seed=3))
    t0 = time.time()
    t = _send_join(ca, b"abcdefghij")
    assert cb.recv_frame() == b"abcdefghij"
    t.join()
    # 3 фрагмента * ~0.01с задержки = заметная внесённая задержка
    assert ca.cost.injected_delay_s >= 0.02, f"джиттер не учтён: {ca.cost.injected_delay_s}"
    assert time.time() - t0 >= 0.02
    ca.close(); cb.close()
    print(f"OK test_timing_jitter_costed (injected {ca.cost.injected_delay_s*1000:.0f} ms)")


def test_padding_changes_wire_sizes_vs_plain():
    """Санити по V1: паддинг реально меняет размеры на проводе относительно plain."""
    plain_a, plain_b = _carrier_pair(dict(seed=4))  # без паддинга/фрагментации
    pad_a, pad_b = _carrier_pair(dict(min_size=512, max_size=512, seed=4))
    payload = b"y" * 40
    for snd, rcv in ((plain_a, plain_b), (pad_a, pad_b)):
        t = _send_join(snd, payload)
        rcv.recv_frame()
        t.join()
    assert plain_a.cost.wire_bytes < pad_a.cost.wire_bytes
    assert pad_a.cost.wire_bytes == 512
    for c in (plain_a, plain_b, pad_a, pad_b):
        c.close()
    print(f"OK test_padding_changes_wire_sizes_vs_plain "
          f"(plain={plain_a.cost.wire_bytes}B vs padded={pad_a.cost.wire_bytes}B на 40B payload)")


# --------------------- переключаемость: туннель поверх carrier ------------------

def _run_tunnel_echo(make_server, make_client, policy_note=""):
    echo = TcpEcho()
    s, c = keys.generate(), keys.generate()
    server = CarrierTunnelServer(make_server=make_server, target=_astr(echo.addr),
                                 static_private=s.private).start()
    client = CarrierTunnelClient(local_bind="127.0.0.1:0",
                                 carrier_client=make_client(server.address),
                                 static_private=c.private,
                                 server_public=s.public).start()
    try:
        conn = socket.create_connection(client.address, timeout=5)
        payload = MARKER + os.urandom(2000)  # >1 фрагмент при мелкой фрагментации
        conn.sendall(payload)
        buf = b""
        conn.settimeout(5)
        while len(buf) < len(payload):
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
        assert buf == payload, f"echo через туннель{policy_note} сломан ({len(buf)}/{len(payload)})"
        conn.close()
    finally:
        client.stop(); server.stop(); echo.stop()


def test_tunnel_over_plain_carrier():
    _run_tunnel_echo(
        make_server=lambda h: PlainTcpServer("127.0.0.1:0", h),
        make_client=lambda addr: PlainTcpClient(_astr(addr)),
    )
    print("OK test_tunnel_over_plain_carrier")


def test_tunnel_over_padded_carrier():
    # фрагментация + паддинг + джиттер одновременно — туннель должен пережить
    def policy():
        return PaddingPolicy(max_fragment_payload=200, min_size=400, max_size=600,
                             min_delay_s=0.0, max_delay_s=0.001)
    _run_tunnel_echo(
        make_server=lambda h: PaddedTcpServer("127.0.0.1:0", h, policy()),
        make_client=lambda addr: PaddedTcpClient(_astr(addr), policy()),
        policy_note=" (padded)",
    )
    print("OK test_tunnel_over_padded_carrier")


def _run_all():
    tests = [
        test_fragmentation_reassembly,
        test_padding_overhead_costed,
        test_timing_jitter_costed,
        test_padding_changes_wire_sizes_vs_plain,
        test_tunnel_over_plain_carrier,
        test_tunnel_over_padded_carrier,
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
