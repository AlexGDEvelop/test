"""Обёртка над noiseprotocol для паттерна Noise_IK_25519_ChaChaPoly_SHA256.

Вся «настоящая» криптография (DH, KDF, аутентификация сторон, forward secrecy)
живёт здесь и делегируется библиотеке. Мы лишь:
  - удобно конфигурируем initiator/responder,
  - прогоняем 2 сообщения хендшейка IK,
  - отдаём наружу готовые транспортные ключи (для UDP-record) и
    методы encrypt/decrypt (для TCP-потока).

IK-паттерн: initiator заранее знает статический ключ responder (s),
responder узнаёт статический ключ initiator в ходе хендшейка. Это даёт:
  - взаимную аутентификацию по статическим ключам,
  - сокрытие статического ключа initiator от пассивного наблюдателя,
  - forward secrecy для транспортных данных (за счёт эфемерных ключей).
Известный нюанс IK: первое сообщение допускает replay (0-RTT), поэтому в msg1
мы НЕ передаём полезную/чувствительную нагрузку — только пустой payload.
"""
from __future__ import annotations

from dataclasses import dataclass

from noise.connection import Keypair as NoiseKeypair
from noise.connection import NoiseConnection

from . import DEFAULT_PROLOGUE, NOISE_PROTOCOL


@dataclass
class TransportKeys:
    send: bytes  # ключ для нашего исходящего направления
    recv: bytes  # ключ для входящего направления


def _new(prologue: bytes) -> NoiseConnection:
    conn = NoiseConnection.from_name(NOISE_PROTOCOL)
    conn.set_prologue(prologue)
    return conn


def new_initiator(local_private: bytes, remote_public: bytes,
                  prologue: bytes = DEFAULT_PROLOGUE) -> NoiseConnection:
    conn = _new(prologue)
    conn.set_as_initiator()
    conn.set_keypair_from_private_bytes(NoiseKeypair.STATIC, local_private)
    conn.set_keypair_from_public_bytes(NoiseKeypair.REMOTE_STATIC, remote_public)
    conn.start_handshake()
    return conn


def new_responder(local_private: bytes,
                  prologue: bytes = DEFAULT_PROLOGUE) -> NoiseConnection:
    conn = _new(prologue)
    conn.set_as_responder()
    conn.set_keypair_from_private_bytes(NoiseKeypair.STATIC, local_private)
    conn.start_handshake()
    return conn


def transport_keys(conn: NoiseConnection) -> TransportKeys:
    """Извлечь транспортные ключи после завершения хендшейка.

    Нужны для UDP-record-слоя, где неявный счётчик noiseprotocol неприменим
    (датаграммы теряются/переставляются). Для TCP это не используется — там
    работают штатные conn.encrypt/decrypt.
    """
    if not conn.handshake_finished:
        raise RuntimeError("handshake ещё не завершён")
    proto = conn.noise_protocol
    return TransportKeys(
        send=proto.cipher_state_encrypt.k,
        recv=proto.cipher_state_decrypt.k,
    )
