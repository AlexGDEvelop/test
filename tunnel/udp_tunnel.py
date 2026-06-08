"""UDP-туннель point-to-point поверх Noise-IK + record-слой WireGuard-стиля.

Топология как у TCP-варианта, но датаграммная:
    [inner app] --UDP--> [client local_bind]
                              | Noise_IK хендшейк (с ретраями), затем
                              | record: counter||AEAD, защита от повтора
                              v
                         [server bind] --UDP--> [target]

Минимальная для стенда модель: один клиентский процесс держит одну Noise-сессию
к серверу; сервер ведёт по сессии на каждый исходный адрес клиента. На каждой
стороне после хендшейка работает RecordSealer/RecordOpener (см. record.py),
потому что по UDP неявный счётчик noiseprotocol неприменим.

Тип датаграммы — 1 байт префикса:
    0x01 — handshake (Noise msg1/msg2),
    0x02 — data (record).
"""
from __future__ import annotations

import socket
import threading
from typing import Optional

from . import DEFAULT_PROLOGUE
from .noise_session import new_initiator, new_responder, transport_keys
from .record import RecordOpener, RecordSealer, ReplayError

T_HANDSHAKE = 0x01
T_DATA = 0x02
_MAX_DGRAM = 65535
_HANDSHAKE_RETRIES = 5
_HANDSHAKE_TIMEOUT = 1.0


def _addr(value):
    host, port = value.rsplit(":", 1)
    return (host, int(port))


class _Session:
    __slots__ = ("sealer", "opener", "upstream", "client_addr", "reader")

    def __init__(self, sealer, opener, upstream, client_addr):
        self.sealer = sealer
        self.opener = opener
        self.upstream = upstream
        self.client_addr = client_addr
        self.reader: Optional[threading.Thread] = None


class UdpTunnelServer:
    """Responder: по сессии на адрес клиента, форвард датаграмм в target."""

    def __init__(self, bind: str, target: str, static_private: bytes,
                 prologue: bytes = DEFAULT_PROLOGUE):
        self._bind = _addr(bind)
        self._target = _addr(target)
        self._priv = static_private
        self._prologue = prologue
        self._sock: Optional[socket.socket] = None
        self._sessions: dict = {}
        self._lock = threading.Lock()
        self._running = False

    @property
    def address(self):
        return self._sock.getsockname() if self._sock else self._bind

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self._bind)
        self._running = True
        threading.Thread(target=self._recv_loop, daemon=True).start()
        return self

    def _recv_loop(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(_MAX_DGRAM)
            except OSError:
                break
            if not data:
                continue
            kind, payload = data[0], data[1:]
            if kind == T_HANDSHAKE:
                self._on_handshake(payload, addr)
            elif kind == T_DATA:
                self._on_data(payload, addr)

    def _on_handshake(self, msg1: bytes, addr):
        try:
            conn = new_responder(self._priv, self._prologue)
            conn.read_message(msg1)
            msg2 = conn.write_message()
            if not conn.handshake_finished:
                return
            keys = transport_keys(conn)
            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream.connect(self._target)
            sess = _Session(RecordSealer(keys.send), RecordOpener(keys.recv),
                            upstream, addr)
            with self._lock:
                old = self._sessions.get(addr)
                if old:
                    old.upstream.close()
                self._sessions[addr] = sess
            sess.reader = threading.Thread(target=self._upstream_reader,
                                           args=(sess,), daemon=True)
            sess.reader.start()
            self._sock.sendto(bytes([T_HANDSHAKE]) + msg2, addr)
        except Exception:
            return

    def _on_data(self, record: bytes, addr):
        with self._lock:
            sess = self._sessions.get(addr)
        if sess is None:
            return  # данные без сессии — игнорируем (нет ключей)
        try:
            plaintext = sess.opener.open(record)
        except (ReplayError, Exception):
            return
        try:
            sess.upstream.send(plaintext)
        except OSError:
            pass

    def _upstream_reader(self, sess: _Session):
        sess.upstream.settimeout(1.0)
        while self._running:
            try:
                reply = sess.upstream.recv(_MAX_DGRAM)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                wire = bytes([T_DATA]) + sess.sealer.seal(reply)
                self._sock.sendto(wire, sess.client_addr)
            except OSError:
                break

    def stop(self):
        self._running = False
        with self._lock:
            for s in self._sessions.values():
                try:
                    s.upstream.close()
                except OSError:
                    pass
            self._sessions.clear()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


class UdpTunnelClient:
    """Initiator: одна сессия к серверу, релеит датаграммы локального приложения."""

    def __init__(self, local_bind: str, server_addr: str,
                 static_private: bytes, server_public: bytes,
                 prologue: bytes = DEFAULT_PROLOGUE):
        self._local = _addr(local_bind)
        self._server = _addr(server_addr)
        self._priv = static_private
        self._server_pub = server_public
        self._prologue = prologue
        self._app_sock: Optional[socket.socket] = None
        self._srv_sock: Optional[socket.socket] = None
        self._sealer: Optional[RecordSealer] = None
        self._opener: Optional[RecordOpener] = None
        self._app_addr = None
        self._lock = threading.Lock()
        self._running = False

    @property
    def address(self):
        return self._app_sock.getsockname() if self._app_sock else self._local

    def start(self):
        self._app_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._app_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._app_sock.bind(self._local)
        self._srv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._srv_sock.connect(self._server)
        self._handshake()
        self._running = True
        threading.Thread(target=self._app_loop, daemon=True).start()
        threading.Thread(target=self._server_loop, daemon=True).start()
        return self

    def _handshake(self):
        conn = new_initiator(self._priv, self._server_pub, self._prologue)
        msg1 = bytes([T_HANDSHAKE]) + conn.write_message()
        self._srv_sock.settimeout(_HANDSHAKE_TIMEOUT)
        for _ in range(_HANDSHAKE_RETRIES):
            self._srv_sock.send(msg1)
            try:
                resp = self._srv_sock.recv(_MAX_DGRAM)
            except socket.timeout:
                continue
            if resp and resp[0] == T_HANDSHAKE:
                conn.read_message(resp[1:])
                if conn.handshake_finished:
                    keys = transport_keys(conn)
                    self._sealer = RecordSealer(keys.send)
                    self._opener = RecordOpener(keys.recv)
                    self._srv_sock.settimeout(None)
                    return
        raise TimeoutError("UDP Noise-хендшейк не завершён (нет ответа сервера)")

    def _app_loop(self):
        while self._running:
            try:
                data, addr = self._app_sock.recvfrom(_MAX_DGRAM)
            except OSError:
                break
            with self._lock:
                self._app_addr = addr
            try:
                self._srv_sock.send(bytes([T_DATA]) + self._sealer.seal(data))
            except OSError:
                break

    def _server_loop(self):
        while self._running:
            try:
                resp = self._srv_sock.recv(_MAX_DGRAM)
            except OSError:
                break
            if not resp or resp[0] != T_DATA:
                continue
            try:
                plaintext = self._opener.open(resp[1:])
            except (ReplayError, Exception):
                continue
            with self._lock:
                app_addr = self._app_addr
            if app_addr is not None:
                try:
                    self._app_sock.sendto(plaintext, app_addr)
                except OSError:
                    break

    def stop(self):
        self._running = False
        for s in (self._app_sock, self._srv_sock):
            if s:
                try:
                    s.close()
                except OSError:
                    pass
