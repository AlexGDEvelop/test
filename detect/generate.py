"""Генерация размеченного датасета pcap с ИДЕНТИЧНОЙ нагрузкой в обоих классах.

Корректность замера (блокер ревью Этапа 4): различаться между positive и negative
должен ТОЛЬКО транспорт, а не приложение. Поэтому:
  - negative = тот же URL тянется НАПРЯМУЮ (обычный HTTPS/h3 к реальному сайту);
  - positive = ТОТ ЖЕ URL тянется ЧЕРЕЗ туннель (клиент ходит в локальный порт
    туннеля как в CONNECT-прокси; сервер форвардит в connect_proxy -> реальный
    сайт). Нагрузка идентична, обёртка разная.

Контроль конфаундов (§3 Этапа 1) + чередование (ревью Этапа 4): в каждом раунде
один и тот же URL снимается для фона и КАЖДОГО модуля, порядок раундов
перемешан — короткие чередующиеся сессии, а не большие последовательные блоки
(иначе детектор выучит сетевой контекст блока/время суток, не транспорт).

Структурное по V7 (ревью Этапа 4): через туннель весь трафик идёт на ОДИН адрес
(сервер), напрямую — веер на CDN. Это by construction и лечится только
многоэндпоинтностью (fronting), НЕ mux. Здесь это не «чиним», а честно
фиксируем — детектор измерит вес v7_unique_dests.

Запуск на стенде (нужен dumpcap/tshark + Npcap):
    python -m detect.generate --list-ifaces
    python -m detect.generate --paired --iface N --out-root data --urls urls.txt \
        --modules plain,padded,reality,quic --rounds 3000
"""
from __future__ import annotations

import argparse
import os
import random
import ssl
import urllib.request
from typing import List, Optional

from tunnel import keys
from transport.carrier_tunnel import CarrierTunnelClient, CarrierTunnelServer
from transport.padding import PaddedTcpClient, PaddedTcpServer, PaddingPolicy
from transport.plain_tcp import PlainTcpClient, PlainTcpServer
from transport.quic_h3 import QuicClient, QuicServer
from transport.reality import ControlTlsDonor, RealityClient, RealityServer
from transport.tls_util import generate_self_signed

from .capture import Capture
from .connect_proxy import ConnectProxy

TUNNEL_SNI = "s3cr3t.tunnel.invalid"


def _astr(addr):
    return f"{addr[0]}:{addr[1]}"


class TunnelBench:
    """Туннель выбранного модуля; upstream = CONNECT-прокси, чтобы нести реальный веб."""

    def __init__(self, module: str, policy: Optional[PaddingPolicy] = None):
        self.module = module
        self.proxy = ConnectProxy().start()       # upstream: набирает реальные сайты
        self._extra = []
        s, c = keys.generate(), keys.generate()
        target = _astr(self.proxy.addr)

        if module == "plain":
            self.server = CarrierTunnelServer(
                lambda h: PlainTcpServer("127.0.0.1:0", h), target, s.private).start()
            cf = PlainTcpClient(_astr(self.server.address))
        elif module == "padded":
            pol = policy or PaddingPolicy(max_fragment_payload=600, min_size=600,
                                          max_size=1400, max_delay_s=0.002)
            self.server = CarrierTunnelServer(
                lambda h: PaddedTcpServer("127.0.0.1:0", h, pol), target, s.private).start()
            cf = PaddedTcpClient(_astr(self.server.address), pol)
        elif module == "reality":
            d_cert, d_key = generate_self_signed("donor.local")
            r_cert, r_key = generate_self_signed("reality.local")
            donor = ControlTlsDonor("127.0.0.1:0", d_cert, d_key).start()
            self._extra.append(donor)
            self.server = CarrierTunnelServer(
                lambda h: RealityServer("127.0.0.1:0", h, donor=_astr(donor.address),
                                        cert=r_cert, key=r_key, tunnel_sni=TUNNEL_SNI),
                target, s.private).start()
            cf = RealityClient(_astr(self.server.address), TUNNEL_SNI, r_cert)
        elif module == "quic":
            q_cert, q_key = generate_self_signed("quic.local")
            self.server = CarrierTunnelServer(
                lambda h: QuicServer("127.0.0.1:0", h, cert=q_cert, key=q_key),
                target, s.private).start()
            cf = QuicClient(_astr(self.server.address), q_cert, "quic.local")
        else:
            raise ValueError(f"неизвестный модуль: {module}")

        self.client = CarrierTunnelClient("127.0.0.1:0", cf, c.private, s.public).start()

    def fetch(self, url: str, ssl_ctx: Optional[ssl.SSLContext] = None, timeout: float = 15):
        """Тянуть URL ЧЕРЕЗ туннель (как через HTTPS CONNECT-прокси)."""
        proxy_url = f"http://127.0.0.1:{self.client.address[1]}"
        handlers = [urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})]
        if ssl_ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))
        opener = urllib.request.build_opener(*handlers)
        with opener.open(url, timeout=timeout) as r:
            return r.read()

    def stop(self):
        self.client.stop(); self.server.stop(); self.proxy.stop()
        for e in self._extra:
            e.stop()


def fetch_direct(url: str, ssl_ctx: Optional[ssl.SSLContext] = None, timeout: float = 15):
    """Тянуть URL НАПРЯМУЮ (negative-класс)."""
    if ssl_ctx is not None:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_ctx))
        with opener.open(url, timeout=timeout) as r:
            return r.read()
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def generate_paired(modules: List[str], iface: str, out_root: str, urls: List[str],
                    rounds: int, bpf: Optional[str] = "tcp or udp", seed: int = 0):
    rng = random.Random(seed)
    benches = {m: TunnelBench(m) for m in modules}
    labels = {"background": None, **{f"tunnel_{m}": benches[m] for m in modules}}
    for d in labels:
        os.makedirs(os.path.join(out_root, d), exist_ok=True)
    try:
        for r in range(rounds):
            url = rng.choice(urls)
            order = list(labels.items())
            rng.shuffle(order)  # чередуем фон и модули внутри раунда
            for label, bench in order:
                out = os.path.join(out_root, label, f"{r:05d}.pcap")
                try:
                    with Capture(out=out, iface=iface, bpf=bpf):
                        if bench is None:
                            fetch_direct(url)
                        else:
                            bench.fetch(url)
                except Exception as exc:  # noqa: BLE001
                    print(f"[{label}] {url}: {exc}")
            if (r + 1) % 25 == 0:
                print(f"[paired] раунд {r + 1}/{rounds}")
    finally:
        for b in benches.values():
            b.stop()


def _main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--list-ifaces", action="store_true")
    p.add_argument("--paired", action="store_true")
    p.add_argument("--iface")
    p.add_argument("--out-root")
    p.add_argument("--urls")
    p.add_argument("--modules", default="plain,padded,reality,quic")
    p.add_argument("--rounds", type=int, default=1000)
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args(argv)

    if args.list_ifaces:
        from .capture import list_interfaces
        print(list_interfaces()); return 0

    if not args.paired:
        p.error("укажи --paired (единственный корректный режим: идентичная нагрузка) "
                "или --list-ifaces")
    if not (args.iface and args.out_root and args.urls):
        p.error("нужны --iface, --out-root, --urls")

    with open(args.urls, encoding="utf-8") as f:
        urls = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    modules = [m.strip() for m in args.modules.split(",") if m.strip()]
    generate_paired(modules, args.iface, args.out_root, urls, args.rounds, seed=args.seed)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
