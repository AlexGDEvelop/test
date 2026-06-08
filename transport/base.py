"""Общий контракт транспорт-обёртки + учёт стоимости маскировки.

Carrier — это установленный, привязанный к пиру, СООБЩЕНИЕ-ОРИЕНТИРОВАННЫЙ канал
для непрозрачных фреймов. Поверх него работает Noise-туннель Этапа 2; модуль
обёртки меняет только представление фреймов на проводе. Если этот интерфейс
«потечёт» под специфику конкретного модуля (например, TLS-модуля (a)), сравнение
модулей в детекторе станет нечестным — поэтому контракт намеренно узкий.
"""
from __future__ import annotations

import abc
from dataclasses import asdict, dataclass


@dataclass
class CostStats:
    """Ось стоимости маскировки (договорённость Этапа 1: §2/строка C + §4).

    Каждый carrier ведёт это сам, чтобы Этап 4 строил кривую «детектируемость
    vs цена», а не оценивал маскировку в вакууме. Без этой оси «качество
    маскировки» нечитаемо.
    """
    payload_bytes: int = 0       # полезные байты Noise-фреймов (до обфускации)
    wire_bytes: int = 0          # фактически ушло на провод (паддинг + заголовки)
    payload_frames: int = 0      # логические фреймы (что просил туннель)
    wire_segments: int = 0       # физические сегменты (после фрагментации)
    injected_delay_s: float = 0.0  # суммарная искусственно внесённая задержка

    @property
    def overhead_ratio(self) -> float:
        """Накладные расходы полосы: (wire/payload - 1). 0.0 = без overhead."""
        if not self.payload_bytes:
            return 0.0
        return self.wire_bytes / self.payload_bytes - 1.0

    def snapshot(self) -> dict:
        d = asdict(self)
        d["overhead_ratio"] = round(self.overhead_ratio, 4)
        return d


class Carrier(abc.ABC):
    """Канал передачи непрозрачных фреймов между двумя пирами."""

    cost: CostStats

    @abc.abstractmethod
    def send_frame(self, frame: bytes) -> None:
        """Отправить один логический фрейм (модуль волен паддить/фрагментировать)."""

    @abc.abstractmethod
    def recv_frame(self) -> bytes | None:
        """Получить один логический фрейм; None — пир закрыл канал."""

    @abc.abstractmethod
    def close(self) -> None:
        ...


class CarrierClient(abc.ABC):
    """Клиентская фабрика: устанавливает обфусцированный canal к серверу."""

    @abc.abstractmethod
    def connect(self) -> Carrier:
        ...


class CarrierServer(abc.ABC):
    """Серверная фабрика: принимает соединения и для КАЖДОГО аутентифицированного
    туннель-клиента вызывает on_carrier(carrier). Неаутентифицированные
    соединения (зонды) обрабатываются ВНУТРИ модуля по его правилам — например,
    модуль (a) проксирует их на донор. Это намеренно скрыто за контрактом, чтобы
    туннельная логика была одинаковой для всех модулей.
    """

    @abc.abstractmethod
    def start(self) -> "CarrierServer":
        ...

    @abc.abstractmethod
    def stop(self) -> None:
        ...

    @property
    @abc.abstractmethod
    def address(self):
        ...
