"""Модуль (a): Reality-lite — туннель внутри НАСТОЯЩЕГО TLS 1.3 + relay зондов.

Главное свойство (критерий ревью №1): зонд (браузер/curl) на порт сервера видит
НАСТОЯЩИЙ донор, а не оборванный/странный эндпоинт. Достигается стирингом на
уровне ClientHello через MSG_PEEK (до терминации TLS):
  - SNI == секретный tunnel_sni  -> это наш клиент: терминируем TLS у себя,
    внутри гоним Noise-carrier;
  - иначе                        -> это зонд: прозрачно проксируем сырой TCP на
    донор, и зонд проходит настоящий TLS-хендшейк прямо с донором.

Документированные fidelity-gaps относительно production Reality (меряются на
Этапе 4 как цена отсутствия uTLS):
  - стиринг по covert-SNI, а не по аутентификатору в SessionID (stdlib `ssl` не
    даёт клиенту задать SessionID/ClientHello) — наш фиксированный tunnel_sni
    сам по себе признак (V5);
  - JA3/JA4 нашего клиента = отпечаток OpenSSL из stdlib, не браузера (V5).
Внешний TLS здесь — камуфляж; настоящая аутентификация сторон = внутренний Noise.
"""
from __future__ import annotations

import socket
import ssl
import threading
from itertools import count
from typing import Callable, Optional

from logconf import get_logger
from tunnel.framing import recv_frame as _recv_frame
from tunnel.framing import send_frame as _send_frame

from .base import Carrier, CarrierClient, CarrierServer, CostStats
from .tls_util import parse_sni

_PEEK = 4096
_counter = count(1)
log = get_logger("reality")


def _addr(value):
    host, port = value.rsplit(":", 1)
    return (host, int(port))


class TlsCarrier(Carrier):
    """Carrier поверх установленного TLS-сокета (Noise-фреймы с префиксом длины)."""

    def __init__(self, tls_sock: ssl.SSLSocket):
        self._sock = tls_sock
        self.cost = CostStats()
        self.tls_version = tls_sock.version()

    def send_frame(self, frame: bytes) -> None:
        _send_frame(self._sock, frame)
        self.cost.payload_bytes += len(frame)
        self.cost.payload_frames += 1
        self.cost.wire_bytes += len(frame) + 2  # +префикс (без учёта TLS-record overhead)
        self.cost.wire_segments += 1

    def recv_frame(self) -> Optional[bytes]:
        return _recv_frame(self._sock)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


# --------------------------- контрольный донор стенда --------------------------

class ControlTlsDonor:
    """Свой реальный TLS 1.3 сервер-донор для стенда (отдаёт фиксированную страницу).

    По указанию ревью: донор держим в рамках стенда (свой контрольный сервер),
    а не чужой публичный сайт — чище для воспроизводимости, без паразитной
    нагрузки. На реалистичный донор перейдём отдельно, если понадобится.
    """

    def __init__(self, bind: str, cert: str, key: str, body: bytes = b"DONOR-PAGE"):
        self._bind = _addr(bind)
        self._body = body
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self._ctx.load_cert_chain(cert, key)
        self._sock: Optional[socket.socket] = None
        self._running = False

    @property
    def address(self):
        return self._sock.getsockname() if self._sock else self._bind

    def start(self) -> "ControlTlsDonor":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self._bind)
        self._sock.listen(16)
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()
        return self

    def _loop(self):
        while self._running:
            try:
                raw, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw: socket.socket):
        try:
            tls = self._ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close(); return
        try:
            tls.recv(4096)  # прочитать запрос (HTTP GET и т.п.)
            resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(self._body)).encode() +
                    b"\r\nConnection: close\r\n\r\n" + self._body)
            tls.sendall(resp)
        except OSError:
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


# ------------------------------- сервер Reality --------------------------------

class RealityServer(CarrierServer):
    def __init__(self, bind: str, on_carrier: Callable[[Carrier], None],
                 donor: str, cert: str, key: str, tunnel_sni: str):
        self._bind = _addr(bind)
        self._on_carrier = on_carrier
        self._donor = _addr(donor)
        self._tunnel_sni = tunnel_sni
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self._ctx.load_cert_chain(cert, key)
        self._sock: Optional[socket.socket] = None
        self._running = False

    @property
    def address(self):
        return self._sock.getsockname() if self._sock else self._bind

    def start(self) -> "RealityServer":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self._bind)
        self._sock.listen(16)
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self

    def _accept_loop(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._steer, args=(conn,), daemon=True).start()

    def _steer(self, conn: socket.socket):
        cid = f"A{next(_counter):04d}"
        try:
            peeked = conn.recv(_PEEK, socket.MSG_PEEK)  # НЕ потребляет байты
        except OSError:
            conn.close(); return
        sni = parse_sni(peeked)
        if sni is not None and sni == self._tunnel_sni:
            log.info("conn %s SNI=%r -> ТУННЕЛЬ (TLS терминируем)", cid, sni)
            self._handle_tunnel(conn)
        else:
            log.info("conn %s SNI=%r -> ДОНОР relay (зонд видит настоящий донор)",
                     cid, sni)
            self._relay_to_donor(conn)

    def _handle_tunnel(self, conn: socket.socket):
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            conn.close(); return
        self._on_carrier(TlsCarrier(tls))

    def _relay_to_donor(self, conn: socket.socket):
        try:
            donor = socket.create_connection(self._donor)
        except OSError:
            conn.close(); return
        # ClientHello всё ещё в буфере conn (мы лишь подсмотрели), донор увидит его
        _raw_relay(conn, donor)

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


def _raw_relay(a: socket.socket, b: socket.socket):
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


# ------------------------------- клиент Reality --------------------------------

class RealityClient(CarrierClient):
    def __init__(self, server_addr: str, tunnel_sni: str, server_cert: str):
        self._server = _addr(server_addr)
        self._tunnel_sni = tunnel_sni
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        # Доверяем cert нашего же сервера; имя не сверяем (SNI — секретное,
        # не совпадает с CN). Настоящая аутентификация — внутренний Noise.
        self._ctx.load_verify_locations(server_cert)
        self._ctx.check_hostname = False
        self.last_tls_version: Optional[str] = None

    def connect(self) -> Carrier:
        raw = socket.create_connection(self._server)
        tls = self._ctx.wrap_socket(raw, server_hostname=self._tunnel_sni)
        self.last_tls_version = tls.version()
        return TlsCarrier(tls)
