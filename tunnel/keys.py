"""Генерация и (де)сериализация статических ключей X25519.

Ключи — это материал крипто-ядра, поэтому генерируются библиотекой
`cryptography` (тот же бэкенд, что использует noiseprotocol). Формат хранения —
hex от raw-байтов (32 байта), удобно класть в JSON-конфиг стенда.
"""
from __future__ import annotations

import binascii
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

_RAW_PRIV = dict(
    encoding=_ser.Encoding.Raw,
    format=_ser.PrivateFormat.Raw,
    encryption_algorithm=_ser.NoEncryption(),
)
_RAW_PUB = dict(encoding=_ser.Encoding.Raw, format=_ser.PublicFormat.Raw)


@dataclass(frozen=True)
class Keypair:
    private: bytes  # 32 байта raw
    public: bytes   # 32 байта raw

    @property
    def private_hex(self) -> str:
        return self.private.hex()

    @property
    def public_hex(self) -> str:
        return self.public.hex()


def generate() -> Keypair:
    sk = X25519PrivateKey.generate()
    priv = sk.private_bytes(**_RAW_PRIV)
    pub = sk.public_key().public_bytes(**_RAW_PUB)
    return Keypair(private=priv, public=pub)


def public_from_private(private: bytes) -> bytes:
    """Восстановить публичный ключ из приватного (для проверки конфига)."""
    sk = X25519PrivateKey.from_private_bytes(private)
    return sk.public_key().public_bytes(**_RAW_PUB)


def from_hex(value: str) -> bytes:
    raw = binascii.unhexlify(value.strip())
    if len(raw) != 32:
        raise ValueError(f"ожидалось 32 байта ключа X25519, получено {len(raw)}")
    return raw
