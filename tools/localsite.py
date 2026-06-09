"""Локальный HTTPS-сайт для loopback-смоука лаборатории (без ТСПУ и интернета).

Отдаёт тело СЛУЧАЙНОГО размера (вариативность трафика). Нужен, чтобы и фон, и
туннель ходили к ОДНОМУ локальному адресу по loopback — тогда захват на
loopback-интерфейсе видит оба класса, и детектор меряет именно carrier
(а не латентность/хоп до реального сайта).

    python tools/localsite.py --port 8443
    # urls.txt: одна строка  https://127.0.0.1:8443/
"""
from __future__ import annotations

import argparse
import os
import random
import socket
import ssl
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from transport.tls_util import generate_self_signed  # noqa: E402


def _serve(host: str, port: int, min_kb: int, max_kb: int):
    cert, key = generate_self_signed("localhost")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(128)
    print(f"local HTTPS site on {host}:{port}  (тело {min_kb}-{max_kb} КБ; Ctrl+C для остановки)")

    def handle(c):
        try:
            t = ctx.wrap_socket(c, server_side=True)
            t.recv(4096)
            body = os.urandom(random.randint(min_kb, max_kb) * 1024)
            t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                      b"\r\nConnection: close\r\n\r\n" + body)
            t.close()
        except OSError:
            try:
                c.close()
            except OSError:
                pass

    while True:
        try:
            c, _ = srv.accept()
        except OSError:
            break
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def main():
    p = argparse.ArgumentParser(description="Локальный HTTPS-сайт для loopback-смоука")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--min-kb", type=int, default=2)
    p.add_argument("--max-kb", type=int, default=150)
    args = p.parse_args()
    threading.Thread(target=_serve, args=(args.host, args.port, args.min_kb, args.max_kb),
                     daemon=True).start()
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nстоп")


if __name__ == "__main__":
    main()
