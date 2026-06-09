"""CLI стенда: генерация ключей и запуск ролей туннеля.

Примеры:
    python -m tunnel.cli keygen
    # базовый Noise (plain) — палевно для DPI, но просто:
    python -m tunnel.cli run --config config/bench.socks.json --role server
    python -m tunnel.cli run --config config/bench.socks.json --role socks
    # обфусцированный транспорт (прятки от DPI):
    python -m tunnel.cli run --config config/transport.example.json --role server --transport reality
    python -m tunnel.cli run --config config/transport.example.json --role socks  --transport reality

Конфиг — JSON с секциями server/client (+ опц. transport). Для двух хостов
разнесите секции: каждому хосту нужен только свой приватный ключ и публичный
ключ сервера (а для reality/quic — ещё cert сервера на клиенте).
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from logconf import setup_logging
from transport.carrier_tunnel import CarrierTunnelClient, CarrierTunnelServer
from transport.reality import ControlTlsDonor
from transport.tls_util import generate_self_signed
from transports import DEFAULT_TUNNEL_SNI, TransportSpec, ensure_cert, make_client, make_server

from . import keys
from .socks_client import Socks5TunnelClient
from .tcp_tunnel import TcpTunnelClient, TcpTunnelServer
from .udp_tunnel import UdpTunnelClient, UdpTunnelServer


def _astr(addr):
    return f"{addr[0]}:{addr[1]}"


def _cmd_keygen(_args):
    kp = keys.generate()
    print("# Статическая пара X25519 (raw hex).")
    print("# private — секрет хоста, public — отдаёте противоположной стороне.")
    print(f"private = {kp.private_hex}")
    print(f"public  = {kp.public_hex}")


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ----------------------- сборка carrier-спеки из конфига ----------------------

def _carrier_spec(transport: str, role: str, cfg: dict):
    """Вернуть (TransportSpec, [объекты_для_остановки]) под выбранный транспорт.

    Carrier строится через общую фабрику transports.* — тот же код, что в
    лаборатории (detect.generate), чтобы провод совпадал с замерами.
    """
    extra = []
    t = cfg.get("transport", {})
    if transport == "plain":
        return TransportSpec(name="plain"), extra
    if transport == "padded":
        return TransportSpec(name="padded"), extra
    if transport == "reality":
        r = t.get("reality", {})
        sni = r.get("tunnel_sni", DEFAULT_TUNNEL_SNI)
        cert = r.get("server_cert", "config/reality.crt")
        key = r.get("server_key", "config/reality.key")
        if role == "server":
            ensure_cert(cert, key, "reality.local")           # cert сервера (персистентный)
            d_cert, d_key = generate_self_signed("donor.local")  # cert донора (для зондов)
            donor = ControlTlsDonor("127.0.0.1:0", d_cert, d_key).start()
            extra.append(donor)
            return TransportSpec(name="reality", reality_donor=_astr(donor.address),
                                 reality_cert=cert, reality_key=key, reality_sni=sni), extra
        # клиент: ПИННИТ cert сервера (скопированный с сервера), verify не off
        return TransportSpec(name="reality", reality_sni=sni,
                             reality_server_cert=cert), extra
    if transport == "quic":
        q = t.get("quic", {})
        name = q.get("server_name", "quic.local")
        cert = q.get("server_cert", "config/quic.crt")
        key = q.get("server_key", "config/quic.key")
        if role == "server":
            ensure_cert(cert, key, name)
            return TransportSpec(name="quic", quic_cert=cert, quic_key=key,
                                 quic_server_name=name), extra
        return TransportSpec(name="quic", quic_server_cert=cert,
                             quic_server_name=name), extra
    raise ValueError(transport)


# ------------------------------- запуск ролей ---------------------------------

def _run_plain(args, cfg):
    """Базовый Noise (plain): текущие server/client/socks без изменений."""
    if args.role == "server":
        s = cfg["server"]
        target = s.get("target")  # None -> динамический (для socks)
        cls = TcpTunnelServer if args.proto == "tcp" else UdpTunnelServer
        node = cls(bind=s["bind"], target=target,
                   static_private=keys.from_hex(s["static_private"]))
        node.start()
        print(f"[server/{args.proto}/plain] bind={node.address} "
              f"-> target={target or 'ДИНАМИЧЕСКИЙ (адрес от клиента)'}")
    elif args.role == "socks":
        c = cfg["client"]
        node = Socks5TunnelClient(local_bind=c["local_bind"], server_addr=c["server_addr"],
                                  static_private=keys.from_hex(c["static_private"]),
                                  server_public=keys.from_hex(c["server_public"]))
        node.start()
        print(f"[socks/plain] локальный SOCKS5 {node.address} -> server={c['server_addr']}")
    else:  # client (фиксированный target)
        c = cfg["client"]
        cls = TcpTunnelClient if args.proto == "tcp" else UdpTunnelClient
        node = cls(local_bind=c["local_bind"], server_addr=c["server_addr"],
                   static_private=keys.from_hex(c["static_private"]),
                   server_public=keys.from_hex(c["server_public"]))
        node.start()
        print(f"[client/{args.proto}/plain] local={node.address} -> server={c['server_addr']}")
    return node, []


def _run_carrier(args, cfg):
    """Обфусцированный транспорт (padded/reality/quic) через общую фабрику.

    Браузер -> FoxyProxy SOCKS5 -> локальный carrier-клиент -> (обёртка) ->
    сервер -> локальный SOCKS5-прокси на сервере -> сайт. SOCKS5 идёт ВНУТРИ
    обёртки, на проводе его нет.
    """
    spec, extra = _carrier_spec(args.transport, args.role, cfg)
    if args.role == "server":
        s = cfg["server"]
        if args.exit == "connect":   # HTTP-CONNECT выход (для лаборатории detect.generate)
            from detect.connect_proxy import ConnectProxy
            proxy = ConnectProxy(("127.0.0.1", 0)).start()
            exit_kind = "CONNECT"
        else:                        # SOCKS5 выход (для FoxyProxy/браузинга)
            from tools.socks5 import Socks5Proxy
            proxy = Socks5Proxy(("127.0.0.1", 0)).start()
            exit_kind = "SOCKS5"
        extra.append(proxy)
        node = CarrierTunnelServer(
            make_server=lambda h: make_server(spec, s["bind"], h),
            target=_astr(proxy.addr),
            static_private=keys.from_hex(s["static_private"])).start()
        print(f"[server/{args.transport}] bind={node.address} -> {exit_kind}-выход {_astr(proxy.addr)}")
    else:  # socks / client -> локальный carrier-клиент (FoxyProxy SOCKS5 на него)
        c = cfg["client"]
        node = CarrierTunnelClient(
            local_bind=c["local_bind"],
            carrier_client=make_client(spec, c["server_addr"]),
            static_private=keys.from_hex(c["static_private"]),
            server_public=keys.from_hex(c["server_public"])).start()
        print(f"[{args.role}/{args.transport}] локальный порт {node.address} "
              f"-> server={c['server_addr']} (FoxyProxy: SOCKS5)")
    return node, extra


def _cmd_run(args):
    setup_logging(args.log_level)
    cfg = _load(args.config)
    # --exit connect = лабораторный сервер (carrier + ConnectProxy) для ЛЮБОГО
    # транспорта, включая plain. Иначе plain идёт штатным путём (SOCKS/динамика).
    if args.exit == "connect":
        node, extra = _run_carrier(args, cfg)
    elif args.transport == "plain":
        node, extra = _run_plain(args, cfg)
    else:
        node, extra = _run_carrier(args, cfg)

    print("Ctrl+C для остановки.")
    # time.sleep прерывается Ctrl+C на Windows, а Event.wait() без таймаута — нет.
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nостановка...")
    finally:
        node.stop()
        for e in extra:
            e.stop()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="tunnel", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("keygen", help="сгенерировать статическую пару X25519")

    run = sub.add_parser("run", help="запустить роль туннеля")
    run.add_argument("--config", required=True)
    run.add_argument("--role", required=True, choices=["server", "client", "socks"],
                     help="socks = локальный SOCKS5 (для FoxyProxy)")
    run.add_argument("--proto", default="tcp", choices=["tcp", "udp"],
                     help="только для plain; socks/обёртки всегда tcp")
    run.add_argument("--transport", default="plain",
                     choices=["plain", "padded", "reality", "quic"],
                     help="обёртка для пряток от DPI (plain = голый Noise, по умолчанию)")
    run.add_argument("--exit", default="socks", choices=["socks", "connect"],
                     help="выход сервера: socks (FoxyProxy/браузинг, по умолчанию) "
                          "или connect (HTTP-CONNECT для лаборатории detect.generate --remote)")
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
