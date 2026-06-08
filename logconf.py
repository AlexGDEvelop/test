"""Единый логгер проекта (namespace `obf.*`).

По умолчанию МОЛЧИТ (NullHandler) — библиотечный импорт и тесты не шумят. Логи
включаются явным вызовом setup_logging(level) из CLI/скриптов запуска.

Уровни по смыслу:
  INFO  — жизненный цикл: accept, handshake ok, upstream, закрытие (байты/время),
          в прокси — запрашиваемый хост.
  WARNING — отказы: handshake failed, upstream недоступен, отказ стиринга.
  DEBUG — детально (по желанию): пер-чанк, внутренние шаги.
"""
from __future__ import annotations

import logging
import sys

_NS = "obf"
_base = logging.getLogger(_NS)
_base.addHandler(logging.NullHandler())
_base.propagate = False


def setup_logging(level: str = "INFO") -> logging.Logger:
    for h in list(_base.handlers):
        if not isinstance(h, logging.NullHandler):
            _base.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-5s %(name)s | %(message)s", datefmt="%H:%M:%S"))
    _base.addHandler(handler)
    _base.setLevel(getattr(logging, level.upper(), logging.INFO))
    return _base


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"{_NS}.{name}")
