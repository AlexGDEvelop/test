"""4.5.2 Серверный логгер (расходный VPS): carrier-сервер + ConnectProxy + pcap +
СЫРЫЕ факты по входящим соединениям.

ВАЖНО (ревью): НЕ маркируем «зонд». Пишем только наблюдаемое: src, время,
длительность, байты по направлениям, был ли SYN/RST, совпал ли src с известным
IP клиента. Вердикт — за человеком (см. correlate / глазами).
  Не-client-IP + короткое/оборванное соединение = КАНДИДАТ, НЕ зонд.
  Ложноположительные: динамический IP клиента (мобила/РТК), обрывы связи,
  фоновый интернет-скан. «N зондов» мы НЕ выдаём.

Хендшейк-исходы (завершён/нет, для reality — донор-relay vs туннель) пишутся в
лог-файл obf.* по timestamp; src — из pcap. Их сопоставление по времени — ручное.

pcap пишется тем же detect.capture (dumpcap/tshark) и пригоден для
detect.features (V1–V7) — сравнение поля с лабораторией.

Запуск на VPS:
    python -m field.server_log --config config/transport.example.json --transport reality \
        --iface eth0 --pcap field_reality.pcap --client-ip <IP клиента> --out conns_reality.json
"""
from __future__ import annotations

import argparse
import json
import logging
import socket
import time

import dpkt

from logconf import get_logger, setup_logging
from transport.carrier_tunnel import CarrierTunnelServer
from transports import make_server
from tunnel import keys
from tunnel.cli import _carrier_spec

from detect.capture import Capture
from detect.connect_proxy import ConnectProxy

log = get_logger("field.server")


def _astr(addr):
    return f"{addr[0]}:{addr[1]}"


def _ipstr(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET if len(raw) == 4 else socket.AF_INET6, raw)


def _decoder(datalink):
    if datalink == 1:
        return lambda b: dpkt.ethernet.Ethernet(b).data
    if datalink in (0, 108):
        return lambda b: dpkt.loopback.Loopback(b).data
    if datalink in (101, 12, 14):
        return lambda b: dpkt.ip.IP(b)
    if datalink == 113:
        return lambda b: dpkt.sll.SLL(b).data
    return lambda b: dpkt.ethernet.Ethernet(b).data


def connections_from_pcap(pcap_path: str, server_port: int, client_ip=None) -> list:
    """СЫРЫЕ факты по соединениям, касающимся server_port. Без вердиктов."""
    flows: dict = {}
    with open(pcap_path, "rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        decode = _decoder(reader.datalink())
        for ts, buf in reader:
            try:
                ip = decode(buf)
            except Exception:
                continue
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            l4 = ip.data
            if isinstance(l4, dpkt.tcp.TCP):
                proto, flags = "tcp", l4.flags
            elif isinstance(l4, dpkt.udp.UDP):
                proto, flags = "udp", 0
            else:
                continue
            src, dst = _ipstr(ip.src), _ipstr(ip.dst)
            if l4.dport == server_port:
                peer, direction = (src, l4.sport), "up"      # peer -> server
            elif l4.sport == server_port:
                peer, direction = (dst, l4.dport), "down"    # server -> peer
            else:
                continue
            key = (peer, proto)
            f = flows.setdefault(key, {
                "src": peer[0], "peer_port": peer[1], "proto": proto,
                "t_start": ts, "t_end": ts, "bytes_up": 0, "bytes_down": 0,
                "syn": False, "rst": False})
            f["t_start"] = min(f["t_start"], ts)
            f["t_end"] = max(f["t_end"], ts)
            if direction == "up":
                f["bytes_up"] += len(buf)
            else:
                f["bytes_down"] += len(buf)
            if proto == "tcp":
                if (flags & dpkt.tcp.TH_SYN) and not (flags & dpkt.tcp.TH_ACK):
                    f["syn"] = True
                if flags & dpkt.tcp.TH_RST:
                    f["rst"] = True
    out = []
    for f in flows.values():
        out.append({
            "src": f["src"], "peer_port": f["peer_port"], "proto": f["proto"],
            "t_start": round(f["t_start"], 3),
            "duration_s": round(f["t_end"] - f["t_start"], 3),
            "bytes_up": f["bytes_up"], "bytes_down": f["bytes_down"],
            "syn": f["syn"], "rst": f["rst"],
            "from_client_ip": client_ip is not None and f["src"] == client_ip,
        })
    out.sort(key=lambda x: x["t_start"])
    return out


def _run(args):
    setup_logging(args.log_level)
    # дублируем obf.* в файл рядом с pcap (хендшейк-исходы по времени)
    fh = logging.FileHandler(args.pcap + ".obf.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s %(name)s | %(message)s"))
    logging.getLogger("obf").addHandler(fh)

    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)
    spec, extra = _carrier_spec(args.transport, "server", cfg)
    bind = cfg["server"]["bind"]
    port = int(bind.rsplit(":", 1)[1])
    proxy = ConnectProxy(("127.0.0.1", 0)).start()
    extra.append(proxy)
    server = CarrierTunnelServer(
        make_server=lambda h: make_server(spec, bind, h),
        target=_astr(proxy.addr),
        static_private=keys.from_hex(cfg["server"]["static_private"])).start()
    log.info("server_log: transport=%s bind=%s -> ConnectProxy %s",
             args.transport, server.address, _astr(proxy.addr))

    bpf = f"tcp port {port} or udp port {port}"
    print(f"Захват в {args.pcap}; Ctrl+C для остановки (потом разбор pcap).")
    try:
        with Capture(out=args.pcap, iface=args.iface, bpf=bpf):
            try:
                while True:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                print("\nостановка захвата...")
    finally:
        server.stop()
        for e in extra:
            e.stop()

    conns = connections_from_pcap(args.pcap, port, args.client_ip)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"server_port": port, "client_ip": args.client_ip,
                   "connections": conns}, f, ensure_ascii=False, indent=2)
    from_client = sum(1 for c in conns if c["from_client_ip"])
    with_rst = sum(1 for c in conns if c["rst"])
    print(f"\nСЫРЫЕ факты: соединений={len(conns)}, с client-IP={from_client}, "
          f"не-client-IP={len(conns) - from_client}, с RST={with_rst} -> {args.out}")
    print("NB: не-client-IP + короткое/оборванное = КАНДИДАТ, не зонд "
          "(ложные: динамический IP клиента, обрывы, фон-скан). Вердикт — твой.")


def _main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", required=True)
    p.add_argument("--transport", required=True,
                   choices=["plain", "padded", "reality", "quic"])
    p.add_argument("--iface", required=True, help="интерфейс для захвата (см. detect.generate --list-ifaces)")
    p.add_argument("--pcap", required=True)
    p.add_argument("--client-ip", default=None, help="IP клиента — для пометки from_client_ip (не фильтр)")
    p.add_argument("--out", required=True)
    p.add_argument("--log-level", default="INFO")
    _run(p.parse_args(argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
