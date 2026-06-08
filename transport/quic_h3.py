"""Модуль (b): туннель внутри НАСТОЯЩЕГО QUIC (aioquic), ALPN h3.

Честный (b) по логике parrot-критики: используем реальный QUIC-стек (aioquic),
а не «похожие на QUIC» датаграммы — иначе «кривой QUIC» сам по себе отпечаток
(§4 Этапа 1). ALPN = ["h3"], так что на уровне ALPN мы выглядим как HTTP/3.
Noise-фреймы идут length-prefixed по одному QUIC-стриму.

Мост async↔sync: aioquic асинхронный, а контракт Carrier синхронный (чтобы
Noise-туннель Этапа 2 работал поверх (a)/(b)/(c) одинаково). Держим один фоновый
asyncio-loop в отдельном потоке и зовём корутины через run_coroutine_threadsafe.
Блокирующая логика туннеля (хендшейк+splice) исполняется в ОТДЕЛЬНЫХ потоках, не
в loop-потоке — иначе .result() из loop-потока даст дедлок.

Честные ограничения (для Этапа 4): CostStats считает полезные байты и фрейм+2;
реальный QUIC-overhead (заголовки пакетов, ACK, паддинг до MTU) на этом слое не
виден — строгий учёт overhead для (b) делается по pcap на Этапе 4.
"""
from __future__ import annotations

import asyncio
import threading
from typing import Callable, Optional, Tuple

from aioquic.asyncio import connect, serve
from aioquic.quic.configuration import QuicConfiguration

from .base import Carrier, CarrierClient, CarrierServer, CostStats

ALPN = ["h3"]

# ------------------------- единый фоновый asyncio-loop -------------------------
_loop: Optional[asyncio.AbstractEventLoop] = None
_loop_lock = threading.Lock()


def _ensure_loop() -> asyncio.AbstractEventLoop:
    global _loop
    with _loop_lock:
        if _loop is None:
            _loop = asyncio.new_event_loop()
            threading.Thread(target=_loop.run_forever, daemon=True).start()
        return _loop


def _run(coro):
    return asyncio.run_coroutine_threadsafe(coro, _ensure_loop()).result()


def _addr(value):
    host, port = value.rsplit(":", 1)
    return host, int(port)


# ------------------------------- carrier --------------------------------------

class QuicStreamCarrier(Carrier):
    """Carrier поверх одного bidirectional QUIC-стрима (length-prefixed фреймы)."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 loop: asyncio.AbstractEventLoop):
        self._r = reader
        self._w = writer
        self._loop = loop
        self.cost = CostStats()
        self._keep = None  # держим ссылки на protocol/context manager, чтобы не закрылись

    def send_frame(self, frame: bytes) -> None:
        async def _s():
            self._w.write(len(frame).to_bytes(2, "big") + frame)
            await self._w.drain()
        asyncio.run_coroutine_threadsafe(_s(), self._loop).result()
        self.cost.payload_bytes += len(frame)
        self.cost.payload_frames += 1
        self.cost.wire_bytes += len(frame) + 2
        self.cost.wire_segments += 1

    def recv_frame(self) -> Optional[bytes]:
        async def _r():
            hdr = await self._r.readexactly(2)
            n = int.from_bytes(hdr, "big")
            return await self._r.readexactly(n)
        try:
            return asyncio.run_coroutine_threadsafe(_r(), self._loop).result()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            return None

    def close(self) -> None:
        async def _c():
            try:
                self._w.write_eof()
            except Exception:
                pass
        try:
            asyncio.run_coroutine_threadsafe(_c(), self._loop).result(timeout=2)
        except Exception:
            pass


# ------------------------------- клиент ---------------------------------------

class QuicClient(CarrierClient):
    def __init__(self, server_addr: str, server_cert: str,
                 server_name: str = "quic.local"):
        self._host, self._port = _addr(server_addr)
        self._cert = server_cert
        self._server_name = server_name

    def connect(self) -> Carrier:
        loop = _ensure_loop()

        async def _c():
            config = QuicConfiguration(is_client=True, alpn_protocols=ALPN)
            config.server_name = self._server_name
            config.load_verify_locations(cafile=self._cert)
            cm = connect(self._host, self._port, configuration=config)
            proto = await cm.__aenter__()
            await proto.wait_connected()
            reader, writer = await proto.create_stream()
            return cm, proto, reader, writer

        cm, proto, reader, writer = asyncio.run_coroutine_threadsafe(_c(), loop).result()
        carrier = QuicStreamCarrier(reader, writer, loop)
        carrier._keep = (cm, proto)  # не дать сборщику закрыть соединение
        return carrier


# ------------------------------- сервер ---------------------------------------

class QuicServer(CarrierServer):
    def __init__(self, bind: str, on_carrier: Callable[[Carrier], None],
                 cert: str, key: str):
        self._host, self._port = _addr(bind)
        self._on_carrier = on_carrier
        self._cert = cert
        self._key = key
        self._server = None
        self._bound = (self._host, self._port)

    @property
    def address(self):
        return self._bound

    def start(self) -> "QuicServer":
        loop = _ensure_loop()

        def stream_handler(reader, writer):
            carrier = QuicStreamCarrier(reader, writer, loop)
            # on_carrier блокирующий (Noise хендшейк + splice) -> в отдельный поток,
            # чтобы не блокировать loop и не словить дедлок на .result()
            threading.Thread(target=self._on_carrier, args=(carrier,),
                             daemon=True).start()

        async def _s():
            config = QuicConfiguration(is_client=False, alpn_protocols=ALPN)
            config.load_cert_chain(self._cert, self._key)
            server = await serve(self._host, self._port, configuration=config,
                                 stream_handler=stream_handler)
            sock = server._transport.get_extra_info("socket")
            return server, sock.getsockname()

        self._server, self._bound = asyncio.run_coroutine_threadsafe(_s(), loop).result()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.close()
