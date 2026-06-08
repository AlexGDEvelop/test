"""CLI стенда: генерация ключей и запуск ролей туннеля.

Примеры:
    python -m tunnel.cli keygen
    python -m tunnel.cli run --config config/bench.example.json --role server --proto tcp
    python -m tunnel.cli run --config config/bench.example.json --role client --proto udp

Конфиг — JSON с секциями server/client (см. config/bench.example.json).
Для двух хостов разнесите секции: каждому хосту нужен только свой приватный
ключ и публичный ключ сервера.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from logconf import setup_logging

from . import keys
from .socks_client import Socks5TunnelClient
from .tcp_tunnel import TcpTunnelClient, TcpTunnelServer
from .udp_tunnel import UdpTunnelClient, UdpTunnelServer


def _cmd_keygen(_args):
    kp = keys.generate()
    print("# Статическая пара X25519 (raw hex).")
    print("# private — секрет хоста, public — отдаёте противоположной стороне.")
    print(f"private = {kp.private_hex}")
    print(f"public  = {kp.public_hex}")


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _cmd_run(args):
    setup_logging(args.log_level)
    cfg = _load(args.config)
    if args.role == "server":
        s = cfg["server"]
        priv = keys.from_hex(s["static_private"])
        target = s.get("target")  # None/отсутствует -> динамический режим (для socks)
        cls = TcpTunnelServer if args.proto == "tcp" else UdpTunnelServer
        node = cls(bind=s["bind"], target=target, static_private=priv)
        node.start()
        mode = target or "ДИНАМИЧЕСКИЙ (адрес от клиента)"
        print(f"[server/{args.proto}] bind={node.address} -> target={mode}")
    elif args.role == "socks":
        c = cfg["client"]
        priv = keys.from_hex(c["static_private"])
        server_pub = keys.from_hex(c["server_public"])
        node = Socks5TunnelClient(local_bind=c["local_bind"], server_addr=c["server_addr"],
                                  static_private=priv, server_public=server_pub)
        node.start()
        print(f"[socks] локальный SOCKS5 {node.address} -> server={c['server_addr']}")
    else:  # client (фиксированный target на сервере)
        c = cfg["client"]
        priv = keys.from_hex(c["static_private"])
        server_pub = keys.from_hex(c["server_public"])
        cls = TcpTunnelClient if args.proto == "tcp" else UdpTunnelClient
        node = cls(local_bind=c["local_bind"], server_addr=c["server_addr"],
                   static_private=priv, server_public=server_pub)
        node.start()
        print(f"[client/{args.proto}] local={node.address} -> server={c['server_addr']}")

    print("Ctrl+C для остановки.")
    # На Windows Event.wait() без таймаута НЕ прерывается Ctrl+C — используем
    # прерываемый sleep-цикл (time.sleep на главном потоке ловит KeyboardInterrupt).
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nостановка...")
    finally:
        node.stop()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="tunnel", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen", help="сгенерировать статическую пару X25519")

    run = sub.add_parser("run", help="запустить роль туннеля")
    run.add_argument("--config", required=True)
    run.add_argument("--role", required=True, choices=["server", "client", "socks"],
                     help="socks = локальный SOCKS5-клиент (для FoxyProxy); "
                          "сервер тогда должен быть с target=null (динамический)")
    run.add_argument("--proto", default="tcp", choices=["tcp", "udp"],
                     help="tcp по умолчанию; socks всегда tcp")
    run.add_argument("--log-level", default="INFO",
                     choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                     help="уровень логов (по умолчанию INFO)")

    args = parser.parse_args(argv)
    if args.cmd == "keygen":
        _cmd_keygen(args)
    elif args.cmd == "run":
        _cmd_run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
