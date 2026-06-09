"""4.5.3 Самозондирование (с ТРЕТЬЕГО адреса, standalone).

Имитируем активный зонд цензора: обычный TLS-запрос на порт сервера и смотрим,
что сервер показывает «постороннему»:
  - reality -> настоящий сертификат + страница ДОНОРА (уровень-3/активное
    зондирование закрыто: для зонда это «обычный сайт»);
  - plain/padded -> Noise ждёт свои байты -> обрыв/мусор (палево под зонд);
  - quic -> UDP; TCP-зонд тут НЕИНФОРМАТИВЕН (см. ниже).

ВАЖНО (ревью) про quic: stdlib-TCP-зонд на UDP-порт ВСЕГДА даёт «нет ответа»
независимо от палевности — это НЕ значит «спрятан». Для quic нужен отдельный
QUIC/UDP-пробер (не реализован); тут для quic печатаем INCONCLUSIVE, а не вывод.

Не тянет ничего из проекта (генерический пробер). Запуск с третьего хоста:
    python -m field.selfprobe --host <IP сервера> --port 5555 --transport reality
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl


def probe_tls(host: str, port: int, timeout: float = 8.0) -> dict:
    """TCP+TLS зонд (без верификации — чтобы УВИДЕТь cert, а не проверить его)."""
    ctx = ssl._create_unverified_context()
    res = {"tls_completed": False, "cert_subject": None, "response_head": None,
           "error": None}
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        res["error"] = f"tcp connect: {exc}"
        return res
    try:
        s = ctx.wrap_socket(raw, server_hostname=host)
        res["tls_completed"] = True
        der = s.getpeercert(binary_form=True)
        if der:
            try:
                from cryptography import x509
                res["cert_subject"] = x509.load_der_x509_certificate(der).subject.rfc4514_string()
            except Exception:
                res["cert_subject"] = "<не разобран>"
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        res["response_head"] = s.recv(256).decode("latin1", "replace")
        s.close()
    except Exception as exc:  # noqa: BLE001
        res["error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
    finally:
        try:
            raw.close()
        except OSError:
            pass
    return res


def _main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--transport", default="unknown",
                   choices=["plain", "padded", "reality", "quic", "unknown"])
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--out")
    args = p.parse_args(argv)

    if args.transport == "quic":
        report = {"host": args.host, "port": args.port, "transport": "quic",
                  "verdict": "INCONCLUSIVE",
                  "note": "TCP-зонд на UDP/QUIC-порт неинформативен: 'нет ответа' "
                          "не равно 'спрятан'. Нужен QUIC/UDP-пробер (не реализован)."}
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        probe = probe_tls(args.host, args.port, args.timeout)
        report = {"host": args.host, "port": args.port, "transport": args.transport,
                  "probe": probe,
                  "note": ("reality: tls_completed=True + cert/страница ДОНОРА = зонд "
                           "видит «обычный сайт» (уровень-3 закрыт). "
                           "plain/padded: ошибка/обрыв = сервер не похож на сайт "
                           "(палево под зонд). Вывод — сопоставь с тем, что ОЖИДАЛ.")}
        print(json.dumps(report, ensure_ascii=False, indent=2))

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
