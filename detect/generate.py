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
import json
import os
import random
import ssl
import urllib.request
from typing import List, Optional

from tunnel import keys
from transport.carrier_tunnel import CarrierTunnelClient, CarrierTunnelServer
from transport.padding import PaddingPolicy
from transport.reality import ControlTlsDonor
from transport.tls_util import generate_self_signed
from transports import DEFAULT_TUNNEL_SNI, TransportSpec, make_client, make_server

from .capture import Capture
from .connect_proxy import ConnectProxy

TUNNEL_SNI = DEFAULT_TUNNEL_SNI


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

        # carrier собирается ТОЛЬКО через общую фабрику transports.* — тот же код,
        # что и в боевом пути (tunnel.cli), иначе замеры разойдутся с проводом.
        spec = self._build_spec(module, policy)
        self.server = CarrierTunnelServer(
            make_server=lambda h: make_server(spec, "127.0.0.1:0", h),
            target=target, static_private=s.private).start()
        self.client = CarrierTunnelClient(
            "127.0.0.1:0", make_client(spec, _astr(self.server.address)),
            static_private=c.private, server_public=s.public).start()

    def _build_spec(self, module: str, policy: Optional[PaddingPolicy]) -> TransportSpec:
        if module == "reality":
            d_cert, d_key = generate_self_signed("donor.local")
            r_cert, r_key = generate_self_signed("reality.local")
            donor = ControlTlsDonor("127.0.0.1:0", d_cert, d_key).start()
            self._extra.append(donor)
            return TransportSpec(name="reality", reality_donor=_astr(donor.address),
                                 reality_cert=r_cert, reality_key=r_key,
                                 reality_sni=TUNNEL_SNI, reality_server_cert=r_cert)
        if module == "quic":
            q_cert, q_key = generate_self_signed("quic.local")
            return TransportSpec(name="quic", quic_cert=q_cert, quic_key=q_key,
                                 quic_server_cert=q_cert)
        if module == "padded":
            return TransportSpec(name="padded", padding=policy)
        return TransportSpec(name="plain")

    def fetch(self, url: str, ssl_ctx: Optional[ssl.SSLContext] = None,
              timeout: float = 8, max_bytes: Optional[int] = None):
        """Тянуть URL ЧЕРЕЗ туннель (как через HTTPS CONNECT-прокси)."""
        return _fetch_via_proxy(f"http://127.0.0.1:{self.client.address[1]}",
                                url, ssl_ctx, timeout, max_bytes)

    def stop(self):
        self.client.stop(); self.server.stop(); self.proxy.stop()
        for e in self._extra:
            e.stop()


# Браузерный UA: без него многие сайты отдают 403 боту urllib (telegraaf/rabobank/…).
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def _request(url: str) -> "urllib.request.Request":
    return urllib.request.Request(url, headers={
        "User-Agent": _UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "nl,en;q=0.8"})


def _fetch_via_proxy(proxy_url: str, url: str, ssl_ctx: Optional[ssl.SSLContext],
                     timeout: float = 8, max_bytes: Optional[int] = None):
    handlers = [urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})]
    if ssl_ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))
    opener = urllib.request.build_opener(*handlers)
    with opener.open(_request(url), timeout=timeout) as r:
        return r.read(max_bytes) if max_bytes else r.read()


class RemoteBench:
    """Клиент туннеля к РЕАЛЬНОМУ серверу (VPS) — для валидного захвата на NIC.

    В отличие от TunnelBench (всё на loopback), здесь поднимается ТОЛЬКО клиент,
    а carrier-сервер + ConnectProxy крутятся на VPS (`tunnel.cli --role server
    --transport X --exit connect`). Тогда carrier пересекает реальный NIC рядом с
    фоном -> один захватчик, сопоставимо. Сервер-target = ConnectProxy на VPS.
    """

    def __init__(self, transport: str, cfg: dict):
        from tunnel.cli import _carrier_spec
        spec, _ = _carrier_spec(transport, "client", cfg)
        c = cfg["client"]
        self.client = CarrierTunnelClient(
            local_bind="127.0.0.1:0",
            carrier_client=make_client(spec, c["server_addr"]),
            static_private=keys.from_hex(c["static_private"]),
            server_public=keys.from_hex(c["server_public"])).start()

    def fetch(self, url: str, ssl_ctx: Optional[ssl.SSLContext] = None,
              timeout: float = 8, max_bytes: Optional[int] = None):
        return _fetch_via_proxy(f"http://127.0.0.1:{self.client.address[1]}",
                                url, ssl_ctx, timeout, max_bytes)

    def stop(self):
        self.client.stop()


def fetch_direct(url: str, ssl_ctx: Optional[ssl.SSLContext] = None,
                 timeout: float = 8, max_bytes: Optional[int] = None):
    """Тянуть URL НАПРЯМУЮ (negative-класс)."""
    handlers = []
    if ssl_ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))
    opener = urllib.request.build_opener(*handlers)
    with opener.open(_request(url), timeout=timeout) as r:
        return r.read(max_bytes) if max_bytes else r.read()


def generate_paired(modules: List[str], iface: str, out_root: str, urls: List[str],
                    rounds: int, bpf: Optional[str] = "tcp or udp", seed: int = 0,
                    ssl_ctx: Optional[ssl.SSLContext] = None,
                    timeout: float = 8, max_bytes: Optional[int] = None,
                    settle: float = 0.5):
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
                fetch = fetch_direct if bench is None else bench.fetch
                try:
                    with Capture(out=out, iface=iface, bpf=bpf, settle_s=settle):
                        fetch(url, ssl_ctx=ssl_ctx, timeout=timeout, max_bytes=max_bytes)
                except Exception as exc:  # noqa: BLE001
                    print(f"[{label}] {url}: {exc}")
            if (r + 1) % 25 == 0:
                print(f"[paired] раунд {r + 1}/{rounds}")
    finally:
        for b in benches.values():
            b.stop()


def generate_paired_remote(transport: str, iface: str, out_root: str, urls: List[str],
                           rounds: int, cfg: dict, bpf: Optional[str] = "tcp or udp",
                           seed: int = 0, ssl_ctx: Optional[ssl.SSLContext] = None,
                           timeout: float = 8, max_bytes: Optional[int] = None,
                           settle: float = 0.5):
    """ВАЛИДНЫЙ датасет: туннель к РЕАЛЬНОМУ серверу (carrier пересекает NIC) +
    фон напрямую, оба снимаются на --iface (реальный NIC). Сервер на VPS:
    `tunnel.cli --role server --transport <X> --exit connect`."""
    rng = random.Random(seed)
    bench = RemoteBench(transport, cfg)
    labels = {"background": None, f"tunnel_{transport}": bench}
    for d in labels:
        os.makedirs(os.path.join(out_root, d), exist_ok=True)
    try:
        for r in range(rounds):
            url = rng.choice(urls)
            order = list(labels.items())
            rng.shuffle(order)
            for label, b in order:
                out = os.path.join(out_root, label, f"{r:05d}.pcap")
                fetch = fetch_direct if b is None else b.fetch
                try:
                    with Capture(out=out, iface=iface, bpf=bpf, settle_s=settle):
                        fetch(url, ssl_ctx=ssl_ctx, timeout=timeout, max_bytes=max_bytes)
                except Exception as exc:  # noqa: BLE001
                    print(f"[{label}] {url}: {exc}")
            if (r + 1) % 25 == 0:
                print(f"[paired/remote {transport}] раунд {r + 1}/{rounds}")
    finally:
        bench.stop()


def _main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--list-ifaces", action="store_true")
    p.add_argument("--paired", action="store_true")
    p.add_argument("--remote", action="store_true",
                   help="туннель к РЕАЛЬНОМУ серверу из --config (валидный захват на NIC); "
                        "требует --config и --transport; сервер на VPS с --exit connect")
    p.add_argument("--config", help="JSON-конфиг с секцией client (для --remote)")
    p.add_argument("--transport", choices=["plain", "padded", "reality", "quic"],
                   help="один транспорт для --remote")
    p.add_argument("--iface")
    p.add_argument("--out-root")
    p.add_argument("--urls")
    p.add_argument("--modules", default="plain,padded,reality,quic")
    p.add_argument("--rounds", type=int, default=1000)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--verify-tls", action="store_true",
                   help="включить проверку TLS-серта при фетче (по умолчанию ВЫКЛ: "
                        "это traffic-генератор, не безопасная загрузка — как curl -k; "
                        "иначе self-signed/MITM/свой-сервер валят фетч и трафик не идёт)")
    p.add_argument("--timeout", type=float, default=8,
                   help="таймаут фетча, сек (по умолчанию 8; меньше = быстрее на флаки-сайтах)")
    p.add_argument("--max-bytes", type=int, default=150000,
                   help="читать не больше N байт ответа (0 = весь; по умолчанию 150к = быстрее)")
    p.add_argument("--settle", type=float, default=0.5,
                   help="пауза старт/слив захвата, сек (по умолчанию 0.5; меньше = быстрее, "
                        "но риск потерять первые пакеты)")
    args = p.parse_args(argv)

    if args.list_ifaces:
        from .capture import list_interfaces
        print(list_interfaces()); return 0

    if not (args.paired or args.remote):
        p.error("укажи --paired (loopback-смоук) или --remote (валидно: туннель к VPS) "
                "или --list-ifaces")
    if not (args.iface and args.out_root and args.urls):
        p.error("нужны --iface, --out-root, --urls")

    with open(args.urls, encoding="utf-8") as f:
        urls = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    ssl_ctx = None if args.verify_tls else ssl._create_unverified_context()
    if ssl_ctx is not None:
        print("[generate] TLS-верификация ВЫКЛ (traffic-генератор; --verify-tls чтобы включить)")

    max_bytes = args.max_bytes or None
    if args.remote:
        if not (args.config and args.transport):
            p.error("--remote требует --config и --transport")
        with open(args.config, encoding="utf-8") as f:
            cfg = json.load(f)
        generate_paired_remote(args.transport, args.iface, args.out_root, urls,
                               args.rounds, cfg, seed=args.seed, ssl_ctx=ssl_ctx,
                               timeout=args.timeout, max_bytes=max_bytes, settle=args.settle)
    else:
        print("[generate] --paired LOOPBACK: смоук механики; carrier на loopback, "
              "фон на NIC -> НЕ валидный датасет. Для данных используй --remote.")
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        generate_paired(modules, args.iface, args.out_root, urls, args.rounds,
                        seed=args.seed, ssl_ctx=ssl_ctx,
                        timeout=args.timeout, max_bytes=max_bytes, settle=args.settle)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
