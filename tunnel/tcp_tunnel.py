"""TCP-туннель point-to-point: порт-форвардер с Noise-IK посередине.

Топология стенда:
    [inner app] --plaintext--> [client local_bind]
                                     |  Noise_IK, поток шифруется
                                     v
                               [server bind] --plaintext--> [target]

Одно входящее TCP-соединение к клиенту = одно соединение к серверу = одно
соединение к target (минимальная честная реализация для стенда). По TCP
порядок гарантирован, поэтому транспорт — штатные conn.encrypt/decrypt
noiseprotocol (неявный счётчик-nonce), без собственного record-слоя.
"""
from __future__ import annotations

import socket
import threading
import time
from itertools import count
from typing import Optional

from logconf import get_logger

from . import DEFAULT_PROLOGUE
from .framing import recv_frame, send_frame
from .noise_session import new_initiator, new_responder

_CHUNK = 32 * 1024  # plaintext-чанк; ciphertext остаётся < 65535
_counter = count(1)
log = get_logger("tcp")


def _addr(value):
    host, port = value.rsplit(":", 1)
    return (host, int(port))


def _astr(addr):
    return f"{addr[0]}:{addr[1]}"


def _peer(sock: socket.socket) -> str:
    try:
        return _astr(sock.getpeername())
    except OSError:
        return "?"


def _pump_plain_to_noise(src: socket.socket, dst: socket.socket, conn, stop, stats):
    """Читать сырой поток из src, шифровать, слать кадрами в dst."""
    try:
        while not stop.is_set():
            data = src.recv(_CHUNK)
            if not data:
                break
            stats["p2e"] += len(data)
            send_frame(dst, conn.encrypt(data))
    except OSError:
        pass
    finally:
        stop.set()
        _shutdown(dst)


def _pump_noise_to_plain(src: socket.socket, dst: socket.socket, conn, stop, stats):
    """Читать кадры из src, расшифровывать, слать сырой поток в dst."""
    try:
        while not stop.is_set():
            frame = recv_frame(src)
            if frame is None:
                break
            plaintext = conn.decrypt(frame)
            stats["e2p"] += len(plaintext)
            dst.sendall(plaintext)
    except OSError:
        pass
    finally:
        stop.set()
        _shutdown(dst)


def _shutdown(sock: socket.socket):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _splice(plain: socket.socket, encrypted: socket.socket, conn, cid: str = "-"):
    """Двунаправленная перекачка между plaintext- и Noise-сторонами."""
    stop = threading.Event()
    stats = {"p2e": 0, "e2p": 0}
    t0 = time.monotonic()
    t1 = threading.Thread(target=_pump_plain_to_noise,
                          args=(plain, encrypted, conn, stop, stats), daemon=True)
    t2 = threading.Thread(target=_pump_noise_to_plain,
                          args=(encrypted, plain, conn, stop, stats), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    plain.close(); encrypted.close()
    log.info("conn %s closed: net→plain %dB, plain→net %dB, %.1fs",
             cid, stats["e2p"], stats["p2e"], time.monotonic() - t0)


class TcpTunnelServer:
    """Responder: принимает Noise-соединения, форвардит в target."""

    def __init__(self, bind: str, target: Optional[str], static_private: bytes,
                 prologue: bytes = DEFAULT_PROLOGUE):
        # target=None -> ДИНАМИЧЕСКИЙ режим: адрес назначения приходит от клиента
        # первым зашифрованным кадром (для локального SOCKS5 на клиенте).
        self._bind = _addr(bind)
        self._target = _addr(target) if target else None
        self._priv = static_private
        self._prologue = prologue
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    @property
    def address(self):
        return self._sock.getsockname() if self._sock else self._bind

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self._bind)
        self._sock.listen(16)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def _accept_loop(self):
        while self._running:
            try:
                client, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,),
                             daemon=True).start()

    def _handle(self, client: socket.socket):
        cid = f"S{next(_counter):04d}"
        log.info("conn %s accepted from %s", cid, _peer(client))
        try:
            conn = new_responder(self._priv, self._prologue)
            msg1 = recv_frame(client)
            if msg1 is None:
                log.warning("conn %s closed before handshake", cid)
                client.close(); return
            conn.read_message(msg1)
            send_frame(client, conn.write_message())  # msg2
            if not conn.handshake_finished:
                log.warning("conn %s handshake failed", cid)
                client.close(); return
            if self._target is not None:               # фиксированный режим
                upstream = socket.create_connection(self._target)
                log.info("conn %s handshake ok -> target %s", cid, _astr(self._target))
            else:                                      # динамический: адрес от клиента
                dframe = recv_frame(client)
                if dframe is None:
                    log.warning("conn %s no destination frame", cid)
                    client.close(); return
                dest = conn.decrypt(dframe).decode("ascii", "replace")
                upstream = socket.create_connection(_addr(dest))
                log.info("conn %s handshake ok -> dial %s", cid, dest)
        except Exception as exc:  # noqa: BLE001
            log.warning("conn %s setup error: %s", cid, exc)
            client.close(); return
        _splice(upstream, client, conn, cid)

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


class TcpTunnelClient:
    """Initiator: слушает локально, шифрует поток на сервер."""

    def __init__(self, local_bind: str, server_addr: str,
                 static_private: bytes, server_public: bytes,
                 prologue: bytes = DEFAULT_PROLOGUE):
        self._local = _addr(local_bind)
        self._server = _addr(server_addr)
        self._priv = static_private
        self._server_pub = server_public
        self._prologue = prologue
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    @property
    def address(self):
        return self._sock.getsockname() if self._sock else self._local

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self._local)
        self._sock.listen(16)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def _accept_loop(self):
        while self._running:
            try:
                app, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(app,),
                             daemon=True).start()

    def _handle(self, app: socket.socket):
        cid = f"C{next(_counter):04d}"
        log.info("conn %s accepted from %s", cid, _peer(app))
        try:
            server = socket.create_connection(self._server)
            conn = new_initiator(self._priv, self._server_pub, self._prologue)
            send_frame(server, conn.write_message())  # msg1
            msg2 = recv_frame(server)
            if msg2 is None:
                log.warning("conn %s no response from server %s", cid, _astr(self._server))
                app.close(); return
            conn.read_message(msg2)
            if not conn.handshake_finished:
                log.warning("conn %s handshake failed", cid)
                app.close(); server.close(); return
            log.info("conn %s handshake ok -> server %s", cid, _astr(self._server))
        except Exception as exc:  # noqa: BLE001
            log.warning("conn %s setup error: %s", cid, exc)
            app.close(); return
        _splice(app, server, conn, cid)

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
