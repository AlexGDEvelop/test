"""Noise-туннель Этапа 2 поверх ЛЮБОГО Carrier — единообразно для (a)/(b)/(c).

Логика туннеля (Noise IK хендшейк + перекачка данных приложения) здесь не знает,
как фреймы выглядят на проводе — это и обеспечивает честное сравнение модулей в
детекторе Этапа 4. Carrier гарантирует порядок и надёжность доставки фреймов
(TCP-семейство), поэтому транспорт — штатные conn.encrypt/decrypt noiseprotocol.
"""
from __future__ import annotations

import socket
import threading
from itertools import count
from typing import Callable, Optional

from logconf import get_logger
from tunnel import DEFAULT_PROLOGUE
from tunnel.noise_session import new_initiator, new_responder

from .base import Carrier, CarrierClient, CarrierServer

_CHUNK = 32 * 1024
_counter = count(1)
log = get_logger("carrier")


def _pump_app_to_carrier(app: socket.socket, carrier: Carrier, conn, stop):
    try:
        while not stop.is_set():
            data = app.recv(_CHUNK)
            if not data:
                break
            carrier.send_frame(conn.encrypt(data))
    except OSError:
        pass
    finally:
        stop.set()
        carrier.close()


def _pump_carrier_to_app(carrier: Carrier, app: socket.socket, conn, stop):
    try:
        while not stop.is_set():
            frame = carrier.recv_frame()
            if frame is None:
                break
            app.sendall(conn.decrypt(frame))
    except OSError:
        pass
    finally:
        stop.set()
        try:
            app.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def _splice(app: socket.socket, carrier: Carrier, conn, cid: str = "-", role: str = ""):
    stop = threading.Event()
    t1 = threading.Thread(target=_pump_app_to_carrier,
                          args=(app, carrier, conn, stop), daemon=True)
    t2 = threading.Thread(target=_pump_carrier_to_app,
                          args=(carrier, app, conn, stop), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    app.close(); carrier.close()
    log.info("conn %s (%s) closed: %s", cid, role, carrier.cost.snapshot())


def run_initiator(carrier: Carrier, app: socket.socket, static_private: bytes,
                  server_public: bytes, prologue: bytes = DEFAULT_PROLOGUE):
    cid = f"I{next(_counter):04d}"
    conn = new_initiator(static_private, server_public, prologue)
    carrier.send_frame(conn.write_message())          # msg1 (пустой payload)
    msg2 = carrier.recv_frame()
    if msg2 is None:
        log.warning("conn %s no server response (handshake)", cid)
        carrier.close(); app.close(); return
    conn.read_message(msg2)
    if not conn.handshake_finished:
        log.warning("conn %s handshake failed", cid)
        carrier.close(); app.close(); return
    log.info("conn %s initiator handshake ok", cid)
    _splice(app, carrier, conn, cid, "initiator")


def run_responder(carrier: Carrier, target, static_private: bytes,
                  prologue: bytes = DEFAULT_PROLOGUE):
    cid = f"R{next(_counter):04d}"
    conn = new_responder(static_private, prologue)
    msg1 = carrier.recv_frame()
    if msg1 is None:
        carrier.close(); return
    conn.read_message(msg1)
    carrier.send_frame(conn.write_message())          # msg2
    if not conn.handshake_finished:
        log.warning("conn %s handshake failed", cid)
        carrier.close(); return
    try:
        upstream = socket.create_connection(target)
    except OSError as exc:
        log.warning("conn %s upstream %s unreachable: %s", cid, target, exc)
        carrier.close(); return
    log.info("conn %s responder handshake ok -> target %s", cid, target)
    _splice(upstream, carrier, conn, cid, "responder")


def _addr(value):
    host, port = value.rsplit(":", 1)
    return (host, int(port))


class CarrierTunnelClient:
    """Слушает локально; каждое соединение приложения проводит через carrier."""

    def __init__(self, local_bind: str, carrier_client: CarrierClient,
                 static_private: bytes, server_public: bytes,
                 prologue: bytes = DEFAULT_PROLOGUE):
        self._local = _addr(local_bind)
        self._carrier_client = carrier_client
        self._priv = static_private
        self._server_pub = server_public
        self._prologue = prologue
        self._sock: Optional[socket.socket] = None
        self._running = False

    @property
    def address(self):
        return self._sock.getsockname() if self._sock else self._local

    def start(self) -> "CarrierTunnelClient":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self._local)
        self._sock.listen(16)
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self

    def _accept_loop(self):
        while self._running:
            try:
                app, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(app,), daemon=True).start()

    def _handle(self, app: socket.socket):
        try:
            carrier = self._carrier_client.connect()
        except OSError:
            app.close(); return
        run_initiator(carrier, app, self._priv, self._server_pub, self._prologue)

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


class CarrierTunnelServer:
    """Привязывает фабрику carrier-сервера к Noise-responder + форварду в target.

    make_server(on_carrier) -> CarrierServer. Переключение модуля (a)/(b)/(c) =
    передать другую фабрику; туннельная логика (_handle) не меняется.
    """

    def __init__(self, make_server: Callable[[Callable[[Carrier], None]], CarrierServer],
                 target: str, static_private: bytes,
                 prologue: bytes = DEFAULT_PROLOGUE):
        self._target = _addr(target)
        self._priv = static_private
        self._prologue = prologue
        self._server = make_server(self._handle)

    @property
    def address(self):
        return self._server.address

    def _handle(self, carrier: Carrier):
        run_responder(carrier, self._target, self._priv, self._prologue)

    def start(self) -> "CarrierTunnelServer":
        self._server.start()
        return self

    def stop(self):
        self._server.stop()
