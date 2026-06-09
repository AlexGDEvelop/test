"""Единая фабрика carrier'ов — ОДИН источник правды для боевого пути (tunnel.cli)
и лаборатории (detect.generate).

Зачем общая: боевой путь и Этап 4 ОБЯЗАНЫ собирать carrier идентично, иначе
замеры детектора перестанут соответствовать тому, что реально на проводе.
Поэтому и CLI, и TunnelBench строят carrier только через эти функции.

Здесь НЕ создаётся крипто и НЕ меняются модули transport/* — только выбор и
конфигурация уже готовых классов (Plain/Padded/Reality/Quic).
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from typing import Callable, Optional

from transport.base import Carrier, CarrierClient, CarrierServer
from transport.padding import PaddedTcpClient, PaddedTcpServer, PaddingPolicy
from transport.plain_tcp import PlainTcpClient, PlainTcpServer
from transport.quic_h3 import QuicClient, QuicServer
from transport.reality import RealityClient, RealityServer
from transport.tls_util import generate_self_signed

TRANSPORTS = ("plain", "padded", "reality", "quic")
DEFAULT_TUNNEL_SNI = "s3cr3t.tunnel.invalid"
DEFAULT_QUIC_SNI = "quic.local"


def default_padding() -> PaddingPolicy:
    """Дефолтный профиль (c). Формат фрагментов симметричен — стороны могут иметь
    независимые политики, поэтому свежий экземпляр на сторону безопасен."""
    return PaddingPolicy(max_fragment_payload=600, min_size=600, max_size=1400,
                         max_delay_s=0.002)


@dataclass
class TransportSpec:
    """Параметры выбранного транспорта (union по всем модулям; лишние = None)."""
    name: str = "plain"
    padding: Optional[PaddingPolicy] = None
    # reality (сервер)
    reality_donor: Optional[str] = None        # addr запущенного ControlTlsDonor
    reality_cert: Optional[str] = None
    reality_key: Optional[str] = None
    reality_sni: str = DEFAULT_TUNNEL_SNI
    # reality (клиент) — пиннит ИМЕННО этот cert сервера
    reality_server_cert: Optional[str] = None
    # quic
    quic_cert: Optional[str] = None
    quic_key: Optional[str] = None
    quic_server_name: str = DEFAULT_QUIC_SNI
    quic_server_cert: Optional[str] = None     # cert сервера для пиннинга на клиенте

    def __post_init__(self):
        if self.name not in TRANSPORTS:
            raise ValueError(f"неизвестный transport: {self.name} (из {TRANSPORTS})")


def make_server(spec: TransportSpec, bind: str,
                on_carrier: Callable[[Carrier], None]) -> CarrierServer:
    """Серверный carrier выбранного транспорта (для CarrierTunnelServer.make_server)."""
    if spec.name == "plain":
        return PlainTcpServer(bind, on_carrier)
    if spec.name == "padded":
        return PaddedTcpServer(bind, on_carrier, spec.padding or default_padding())
    if spec.name == "reality":
        return RealityServer(bind, on_carrier, donor=spec.reality_donor,
                             cert=spec.reality_cert, key=spec.reality_key,
                             tunnel_sni=spec.reality_sni)
    if spec.name == "quic":
        return QuicServer(bind, on_carrier, cert=spec.quic_cert, key=spec.quic_key)
    raise ValueError(spec.name)


def make_client(spec: TransportSpec, server_addr: str) -> CarrierClient:
    """Клиентский carrier выбранного транспорта (для CarrierTunnelClient)."""
    if spec.name == "plain":
        return PlainTcpClient(server_addr)
    if spec.name == "padded":
        return PaddedTcpClient(server_addr, spec.padding or default_padding())
    if spec.name == "reality":
        # пиннинг: RealityClient доверяет ТОЛЬКО reality_server_cert (verify не off)
        return RealityClient(server_addr, spec.reality_sni, spec.reality_server_cert)
    if spec.name == "quic":
        return QuicClient(server_addr, spec.quic_server_cert, spec.quic_server_name)
    raise ValueError(spec.name)


def ensure_cert(cert_path: str, key_path: str, common_name: str) -> None:
    """Сгенерировать self-signed cert+key в заданные пути, если их ещё нет.

    Нужно, чтобы cert ПЕРСИСТЕНТНО лежал на сервере и клиент мог его запиннить
    (скопировать .crt на клиента, как публичный ключ)."""
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return
    tmp_cert, tmp_key = generate_self_signed(common_name)
    os.makedirs(os.path.dirname(os.path.abspath(cert_path)), exist_ok=True)
    shutil.copy(tmp_cert, cert_path)
    shutil.copy(tmp_key, key_path)
