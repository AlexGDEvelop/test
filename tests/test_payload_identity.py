"""Тест блокера ревью Этапа 4: нагрузка через туннель == нагрузка напрямую.

Доказываем, что generate тянет ОДИН И ТОТ ЖЕ контент и через туннель (как через
CONNECT-прокси), и напрямую — различается только транспорт. Если бы туннель нёс
служебный трафик (echo), детектор делил бы классы по приложению, а не по обёртке.

Локальный контрольный HTTPS-сервер играет роль «сайта» — без tshark и интернета.

Запуск: python tests/test_payload_identity.py
"""
from __future__ import annotations

import os
import ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detect.generate import TunnelBench, fetch_direct
from transport.reality import ControlTlsDonor
from transport.tls_util import generate_self_signed

BODY = b"PAYLOAD-IDENTITY-CHECK-42"


def _run_module(module: str, url: str, ctx) -> None:
    tb = TunnelBench(module)
    try:
        tunneled = tb.fetch(url, ssl_ctx=ctx, timeout=20)
        assert tunneled == BODY, f"[{module}] через туннель пришло другое тело: {tunneled!r}"
    finally:
        tb.stop()


def test_payload_identical_tunnel_vs_direct():
    cert, key = generate_self_signed("localhost")
    site = ControlTlsDonor("127.0.0.1:0", cert, key, body=BODY).start()
    url = f"https://127.0.0.1:{site.address[1]}/"
    ctx = ssl._create_unverified_context()  # тест пути данных, не верификации TLS
    try:
        direct = fetch_direct(url, ssl_ctx=ctx, timeout=20)
        assert direct == BODY, f"напрямую пришло другое тело: {direct!r}"
        for module in ("plain", "padded", "reality", "quic"):
            _run_module(module, url, ctx)
            print(f"  [{module}] тело через туннель идентично прямому")
        print("OK test_payload_identical_tunnel_vs_direct "
              "(нагрузка идентична во всех модулях; различается только транспорт)")
    finally:
        site.stop()


def _run_all():
    failed = 0
    for t in (test_payload_identical_tunnel_vs_direct,):
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}: {exc!r}")
    print(f"\n{1 - failed}/1 прошло")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
