"""Тесты крипто-ядра (Этап 2).

Проверяем НЕ только работоспособность, но и базовое свойство скрытности на
уровне записи: на проводе нет плейнтекста. Полноценные тесты обнаружимости
(статистика потока, классификатор) — это Этап 4; здесь — санити-минимум.

Запуск: pytest tests/  ИЛИ  python tests/test_tunnel.py
"""
from __future__ import annotations

import math
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from tunnel import keys
from tunnel.noise_session import new_initiator, new_responder, transport_keys
from tunnel.record import RecordOpener, RecordSealer, ReplayError
from tunnel.tcp_tunnel import TcpTunnelClient, TcpTunnelServer
from tunnel.udp_tunnel import UdpTunnelClient, UdpTunnelServer

MARKER = b"PLAINTEXT-MARKER-should-not-appear-on-wire-0xDEADBEEF"


# --------------------------- вспомогательные сервера ---------------------------

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
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        try:
            while True:
                data = c.recv(65536)
                if not data:
                    break
                c.sendall(data)
        except OSError:
            pass
        finally:
            c.close()

    def stop(self):
        self.running = False
        self.sock.close()


class UdpEcho:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.addr = self.sock.getsockname()
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65536)
            except OSError:
                break
            try:
                self.sock.sendto(data, addr)
            except OSError:
                break

    def stop(self):
        self.running = False
        self.sock.close()


class TcpSniffer:
    """Релей, записывающий все байты в обе стороны (для проверки шифрования)."""

    def __init__(self, upstream):
        self.upstream = upstream
        self.captured = bytearray()
        self.lock = threading.Lock()
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
            u = socket.create_connection(self.upstream)
            threading.Thread(target=self._pump, args=(c, u), daemon=True).start()
            threading.Thread(target=self._pump, args=(u, c), daemon=True).start()

    def _pump(self, src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                with self.lock:
                    self.captured.extend(data)
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def stop(self):
        self.running = False
        self.sock.close()


def _addr_str(addr):
    return f"{addr[0]}:{addr[1]}"


def _shannon_entropy(data: bytes) -> float:
    """Энтропия Шеннона, бит/байт (0..8). Переиспользуется как фича V4."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


# ------------------------------- unit-тесты ------------------------------------

def test_record_roundtrip_and_replay():
    key = os.urandom(32)
    sealer = RecordSealer(key)
    opener = RecordOpener(key)
    p1 = sealer.seal(b"first")
    p2 = sealer.seal(MARKER)
    assert MARKER not in p2, "record не должен содержать плейнтекст"
    assert opener.open(p1) == b"first"
    assert opener.open(p2) == MARKER
    # повтор того же record должен отвергаться
    try:
        opener.open(p1)
        assert False, "повтор должен был быть отвергнут"
    except ReplayError:
        pass
    # порядок вне очереди в пределах окна — допустим
    p3 = sealer.seal(b"third")
    p4 = sealer.seal(b"fourth")
    assert opener.open(p4) == b"fourth"
    assert opener.open(p3) == b"third"
    print("OK test_record_roundtrip_and_replay")


def test_record_rejects_tamper():
    key = os.urandom(32)
    sealer, opener = RecordSealer(key), RecordOpener(key)
    wire = bytearray(sealer.seal(b"payload"))
    wire[-1] ^= 0x01  # порча тега
    try:
        opener.open(bytes(wire))
        assert False, "испорченный тег должен отвергаться"
    except Exception:
        pass
    print("OK test_record_rejects_tamper")


def test_window_not_advanced_on_tamper():
    """П.1: форсированный пакет с высоким counter и битым тегом НЕ двигает окно.

    Иначе атакующий мусором сдвигает окно и валит валидные пакеты (DoS).
    Проверяем напрямую: после отказа форсированного counter=1000 легитимный
    counter=0 обязан пройти (если бы окно прыгнуло на 1000, он стал бы 'too old').
    """
    key = os.urandom(32)
    sealer, opener = RecordSealer(key), RecordOpener(key)
    forged = (1000).to_bytes(8, "big") + os.urandom(40)  # высокий counter, мусор-тег
    try:
        opener.open(forged)
        assert False, "форсированный пакет с битым тегом должен отвергаться"
    except Exception:
        pass
    p0 = sealer.seal(b"legit")  # counter = 0
    assert opener.open(p0) == b"legit", "окно сдвинулось до верификации (DoS-дыра)"
    print("OK test_window_not_advanced_on_tamper")


def test_window_rejects_mid_window_duplicate():
    """П.2: повтор counter из СЕРЕДИНЫ окна (после сдвигов) режется битмаской."""
    key = os.urandom(32)
    sealer, opener = RecordSealer(key), RecordOpener(key)
    pkts = [sealer.seal(f"m{i}".encode()) for i in range(5)]  # counters 0..4
    for p in pkts:
        opener.open(p)  # принять по порядку, highest=4
    try:
        opener.open(pkts[2])  # повтор середины
        assert False, "mid-window дубликат должен резаться"
    except ReplayError:
        pass
    print("OK test_window_rejects_mid_window_duplicate")


def test_record_nonce_layout_kat():
    """П.3: KAT, прибивающий раскладку nonce (4 нуля || counter LE) и big-endian
    counter на проводе. Эталонный nonce задан ЛИТЕРАЛОМ, не выведен из record.py,
    поэтому ловит расхождение по endianness/паддингу, которое roundtrip не видит.
    """
    key = bytes(32)  # фиксированный нулевой ключ — это KAT, не секрет
    plaintext = b"known answer test"
    counter = 5
    # 12-байтовый nonce целиком литералом: 4 нуля + counter=5 в LE на 8 байт
    nonce = bytes.fromhex("000000000500000000000000")
    expected_ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, b"")

    sealer = RecordSealer(key)
    for _ in range(counter):  # докрутить внутренний счётчик до 5
        sealer.seal(b"x")
    wire = sealer.seal(plaintext)

    assert wire[:8] == counter.to_bytes(8, "big"), "counter на проводе должен быть big-endian"
    assert wire[8:] == expected_ct, "раскладка nonce разошлась с эталоном (ждём 4 нуля || counter LE)"
    # и обратная сторона: эталонный nonce расшифровывает то, что записал record
    assert ChaCha20Poly1305(key).decrypt(nonce, wire[8:], b"") == plaintext
    print("OK test_record_nonce_layout_kat")


def test_noise_handshake_keys_align():
    s, c = keys.generate(), keys.generate()
    ini = new_initiator(c.private, s.public)
    res = new_responder(s.private)
    res.read_message(ini.write_message())
    ini.read_message(res.write_message())
    assert ini.handshake_finished and res.handshake_finished
    ik, rk = transport_keys(ini), transport_keys(res)
    assert ik.send == rk.recv and ik.recv == rk.send
    print("OK test_noise_handshake_keys_align")


# --------------------------- интеграционные тесты -----------------------------

def test_tcp_tunnel_roundtrip_and_encrypted():
    echo = TcpEcho()
    s, c = keys.generate(), keys.generate()
    server = TcpTunnelServer(bind="127.0.0.1:0", target=_addr_str(echo.addr),
                             static_private=s.private).start()
    sniffer = TcpSniffer(upstream=server.address)
    client = TcpTunnelClient(local_bind="127.0.0.1:0",
                             server_addr=_addr_str(sniffer.addr),
                             static_private=c.private, server_public=s.public).start()
    try:
        conn = socket.create_connection(client.address, timeout=5)
        conn.sendall(MARKER)
        got = conn.recv(65536)
        assert got == MARKER, f"echo через туннель сломан: {got!r}"
        conn.close()
        time.sleep(0.2)
        with sniffer.lock:
            wire = bytes(sniffer.captured)
        assert wire, "сниффер ничего не записал"
        assert MARKER not in wire, "ПЛЕЙНТЕКСТ НА ПРОВОДЕ — шифрование не работает"
        # Сильнее, чем отсутствие маркера: энтропия записанного должна быть
        # близка к шифртексту. NB: это и есть baseline «голого» ядра по V4 —
        # высокая энтропия с первого байта сама по себе признак (Этап 3 её снизит).
        ent = _shannon_entropy(wire)
        assert ent > 6.0, f"подозрительно низкая энтропия провода: {ent:.2f} бит/байт"
        print(f"OK test_tcp_tunnel_roundtrip_and_encrypted "
              f"(на проводе {len(wire)} байт, плейнтекста нет, энтропия {ent:.2f} бит/байт)")
    finally:
        client.stop(); sniffer.stop(); server.stop(); echo.stop()


def test_udp_tunnel_roundtrip():
    echo = UdpEcho()
    s, c = keys.generate(), keys.generate()
    server = UdpTunnelServer(bind="127.0.0.1:0", target=_addr_str(echo.addr),
                             static_private=s.private).start()
    client = UdpTunnelClient(local_bind="127.0.0.1:0",
                             server_addr=_addr_str(server.address),
                             static_private=c.private, server_public=s.public).start()
    try:
        app = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        app.settimeout(5)
        app.sendto(MARKER, client.address)
        got, _ = app.recvfrom(65536)
        assert got == MARKER, f"UDP echo через туннель сломан: {got!r}"
        app.close()
        print("OK test_udp_tunnel_roundtrip")
    finally:
        client.stop(); server.stop(); echo.stop()


def _run_all():
    tests = [
        test_record_roundtrip_and_replay,
        test_record_rejects_tamper,
        test_window_not_advanced_on_tamper,
        test_window_rejects_mid_window_duplicate,
        test_record_nonce_layout_kat,
        test_noise_handshake_keys_align,
        test_tcp_tunnel_roundtrip_and_encrypted,
        test_udp_tunnel_roundtrip,
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
