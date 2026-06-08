"""Транспортный record для UDP: явный счётчик-nonce + защита от повтора.

ЭТО ЕДИНСТВЕННЫЙ написанный руками крипто-смежный слой в проекте, и он
намеренно минимален: используется только AEAD-примитив ChaCha20-Poly1305 из
аудированной `cryptography`, ключи приходят из Noise-хендшейка. Мы НЕ
изобретаем шифр и НЕ делаем обмен ключами — мы лишь оформляем record поверх
готового AEAD с явным счётчиком, ровно как это делает WireGuard для UDP.

Зачем не штатный noiseprotocol.encrypt: его CipherState ведёт неявный
инкрементный nonce и предполагает доставку по порядку (TCP). По UDP датаграммы
теряются и переставляются — неявный счётчик рассинхронизируется. Поэтому для
UDP счётчик передаётся явно в каждом пакете, а приёмная сторона держит
скользящее окно против повторов.

Формат датаграммы record: counter(8, big-endian) || ciphertext(AEAD).
Nonce для AEAD: 4 нулевых байта || counter(8, little-endian) — раскладка,
совместимая с ChaChaPoly в Noise.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

_COUNTER_BYTES = 8
_NONCE_PAD = b"\x00\x00\x00\x00"  # ChaChaPoly nonce = 12 байт


class ReplayError(Exception):
    """Датаграмма с уже виденным/слишком старым счётчиком (повтор)."""


class _ReplayWindow:
    """Скользящее окно защиты от повтора (как в IPsec/WireGuard)."""

    def __init__(self, size: int = 64) -> None:
        self._size = size
        self._highest = -1
        self._bitmap = 0

    def check(self, counter: int) -> None:
        """Бросить ReplayError, если counter — повтор или вне окна. Не коммитит."""
        if counter < 0:
            raise ReplayError("отрицательный счётчик")
        if counter > self._highest:
            return
        offset = self._highest - counter
        if offset >= self._size:
            raise ReplayError(f"счётчик {counter} слишком старый (вне окна)")
        if self._bitmap & (1 << offset):
            raise ReplayError(f"счётчик {counter} уже принят (повтор)")

    def commit(self, counter: int) -> None:
        """Зафиксировать счётчик как принятый (после успешной расшифровки)."""
        if counter > self._highest:
            shift = counter - self._highest
            self._bitmap = ((self._bitmap << shift) | 1) & ((1 << self._size) - 1)
            self._highest = counter
        else:
            self._bitmap |= 1 << (self._highest - counter)


def _nonce(counter: int) -> bytes:
    return _NONCE_PAD + counter.to_bytes(_COUNTER_BYTES, "little")


class RecordSealer:
    """Исходящее направление: шифрует датаграммы с монотонным счётчиком."""

    def __init__(self, key: bytes) -> None:
        self._aead = ChaCha20Poly1305(key)
        self._counter = 0

    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        counter = self._counter
        if counter >> (8 * _COUNTER_BYTES):
            raise OverflowError("счётчик nonce исчерпан — требуется rekey")
        self._counter += 1
        ct = self._aead.encrypt(_nonce(counter), plaintext, aad)
        return counter.to_bytes(_COUNTER_BYTES, "big") + ct


class RecordOpener:
    """Входящее направление: расшифровывает с проверкой повтора."""

    def __init__(self, key: bytes, window: int = 64) -> None:
        self._aead = ChaCha20Poly1305(key)
        self._window = _ReplayWindow(window)

    def open(self, wire: bytes, aad: bytes = b"") -> bytes:
        if len(wire) < _COUNTER_BYTES:
            raise ValueError("датаграмма короче заголовка счётчика")
        counter = int.from_bytes(wire[:_COUNTER_BYTES], "big")
        self._window.check(counter)  # бросит ReplayError до расшифровки
        plaintext = self._aead.decrypt(_nonce(counter), wire[_COUNTER_BYTES:], aad)
        # коммитим окно только после успешной (аутентифицированной) расшифровки
        self._window.commit(counter)
        return plaintext
