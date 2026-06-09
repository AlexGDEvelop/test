"""4.5.1 Клиентский раннер (РФ-сторона): гонит реальный веб через туннель и
пишет ВРЕМЕННОЙ РЯД доставки (скорость/RTT/ресеты во времени).

Туннель поднимается через ту же фабрику transports.* (carrier = как в
лаборатории). Веб тянется тем же механизмом, что detect.generate — urllib через
локальный HTTP-CONNECT-порт туннеля (сервер-target = ConnectProxy), без новых
зависимостей. Каждый транспорт — отдельный прогон.

Запуск (клиент в РФ):
    python -m field.runner --config config/transport.example.json --transport reality \
        --operator rostelecom --urls config/urls.example.txt --duration 10 --out field_reality.json
"""
from __future__ import annotations

import argparse
import json
import random
import ssl
import statistics
import time
import urllib.request
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from logconf import get_logger, setup_logging
from transport.carrier_tunnel import CarrierTunnelClient
from transports import make_client
from tunnel import keys
from tunnel.cli import _carrier_spec

log = get_logger("field.runner")


def _classify(exc: Exception) -> str:
    s = str(exc).lower()
    if "reset" in s or isinstance(exc, ConnectionResetError):
        return "reset"
    if "timed out" in s or "timeout" in s:
        return "timeout"
    if "refused" in s:
        return "refused"
    return "error"


def drive(proxy_url: str, urls: List[str], duration_s: float, interval_s: float,
          ssl_ctx: Optional[ssl.SSLContext] = None, seed: int = 0
          ) -> Tuple[list, list]:
    """Гонять веб через proxy_url; вернуть (samples, events).

    samples — по окну interval_s: {t, speed_bps, rtt_ms, resets, bytes, fetches}.
    events — обрывы/ошибки с timestamp.
    """
    rng = random.Random(seed)
    start = time.monotonic()
    samples: list = []
    events: list = []
    b_start = start
    b_bytes = 0
    b_rtts: list = []
    b_resets = 0
    b_fetch = 0

    def flush(now):
        nonlocal b_bytes, b_rtts, b_resets, b_fetch, b_start
        elapsed = now - b_start
        speed = (b_bytes * 8 / elapsed) if elapsed > 0 else 0.0
        samples.append({
            "t": round(b_start - start, 1),
            "speed_bps": round(speed),
            "rtt_ms": round(statistics.mean(b_rtts), 1) if b_rtts else 0.0,
            "resets": b_resets, "bytes": b_bytes, "fetches": b_fetch,
        })
        b_bytes = 0; b_rtts = []; b_resets = 0; b_fetch = 0; b_start = now

    while time.monotonic() - start < duration_s:
        now = time.monotonic()
        if now - b_start >= interval_s:
            flush(now)
        url = rng.choice(urls)
        handlers = [urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})]
        if ssl_ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))
        opener = urllib.request.build_opener(*handlers)
        t0 = time.perf_counter()
        try:
            with opener.open(url, timeout=15) as r:
                ttfb = (time.perf_counter() - t0) * 1000
                data = r.read()
            b_bytes += len(data); b_rtts.append(ttfb); b_fetch += 1
        except Exception as exc:  # noqa: BLE001
            kind = _classify(exc)
            events.append({"t": round(time.monotonic() - start, 1),
                           "type": kind, "url": url, "detail": str(exc)[:120]})
            if kind == "reset":
                b_resets += 1
            log.warning("fetch %s -> %s: %s", url, kind, str(exc)[:80])
    flush(time.monotonic())
    return samples, events


def run(config: str, transport: str, operator: str, urls: List[str],
        duration_s: float, interval_s: float, out: str,
        ssl_ctx: Optional[ssl.SSLContext] = None):
    with open(config, encoding="utf-8") as f:
        cfg = json.load(f)
    spec, _ = _carrier_spec(transport, "client", cfg)
    c = cfg["client"]
    client = CarrierTunnelClient(
        local_bind=c["local_bind"],
        carrier_client=make_client(spec, c["server_addr"]),
        static_private=keys.from_hex(c["static_private"]),
        server_public=keys.from_hex(c["server_public"])).start()
    proxy_url = f"http://127.0.0.1:{client.address[1]}"
    log.info("раннер: transport=%s operator=%s -> server=%s, %.0f мин",
             transport, operator, c["server_addr"], duration_s / 60)
    try:
        samples, events = drive(proxy_url, urls, duration_s, interval_s, ssl_ctx)
    finally:
        client.stop()
    result = {
        "transport": transport, "operator": operator,
        "start": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_s": duration_s, "interval_s": interval_s,
        "samples": samples, "events": events,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    log.info("записано %d окон, %d событий -> %s", len(samples), len(events), out)
    return result


def _main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", required=True)
    p.add_argument("--transport", required=True,
                   choices=["plain", "padded", "reality", "quic"])
    p.add_argument("--operator", required=True, help="метка сети: rostelecom/mobile/work/...")
    p.add_argument("--urls", required=True)
    p.add_argument("--duration", type=float, default=10, help="минут")
    p.add_argument("--interval", type=float, default=30, help="секунд на окно")
    p.add_argument("--out", required=True)
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args(argv)
    setup_logging(args.log_level)
    with open(args.urls, encoding="utf-8") as f:
        urls = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    run(args.config, args.transport, args.operator, urls,
        args.duration * 60, args.interval, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
