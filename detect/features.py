"""Экстрактор фич потока V1–V7 из pcap (dpkt, офлайн — без Npcap).

Признаки соответствуют векторам детекции Этапа 1 (§2). Один pcap = один пример
(сессия туннеля ИЛИ набор фоновых потоков). Фичи плоские (имя -> float), чтобы
скормить классификатору атакующего на Этапе 4.

ВАЖНО (§0 Этапа 1): для V4 (энтропия) цель НЕ «чем выше, тем лучше», а близость
к донор-профилю. Здесь мы лишь ИЗМЕРЯЕМ энтропию как фичу; интерпретация (похоже
ли на фон) — на стороне сравнения распределений, не в знаке фичи.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import dpkt
import numpy as np

# dpkt datalink -> декодер канального уровня
_DLT_EN10MB = 1
_DLT_NULL = 0
_DLT_LOOP = 108
_DLT_RAW = (101, 12, 14)
_DLT_SLL = 113


@dataclass
class Packet:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: str       # "tcp" | "udp"
    length: int      # длина кадра на проводе
    payload: bytes   # L4-payload (для энтропии/ClientHello)


def _l3_from_link(datalink: int):
    if datalink == _DLT_EN10MB:
        return lambda buf: dpkt.ethernet.Ethernet(buf).data
    if datalink in (_DLT_NULL, _DLT_LOOP):
        return lambda buf: dpkt.loopback.Loopback(buf).data
    if datalink in _DLT_RAW:
        return lambda buf: dpkt.ip.IP(buf)
    if datalink == _DLT_SLL:
        return lambda buf: dpkt.sll.SLL(buf).data
    # дефолт: пытаемся Ethernet
    return lambda buf: dpkt.ethernet.Ethernet(buf).data


def read_packets(pcap_path: str) -> List[Packet]:
    out: List[Packet] = []
    with open(pcap_path, "rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        decode = _l3_from_link(reader.datalink())
        for ts, buf in reader:
            try:
                ip = decode(buf)
            except Exception:
                continue
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            l4 = ip.data
            if isinstance(l4, dpkt.tcp.TCP):
                proto = "tcp"
            elif isinstance(l4, dpkt.udp.UDP):
                proto = "udp"
            else:
                continue
            try:
                src = _ipstr(ip.src)
                dst = _ipstr(ip.dst)
            except Exception:
                continue
            out.append(Packet(ts=float(ts), src=src, dst=dst,
                              sport=int(l4.sport), dport=int(l4.dport),
                              proto=proto, length=len(buf), payload=bytes(l4.data)))
    return out


def _ipstr(raw: bytes) -> str:
    import socket
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw)
    return socket.inet_ntop(socket.AF_INET6, raw)


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


def _stats(values: List[float], prefix: str) -> Dict[str, float]:
    if not values:
        return {f"{prefix}_{k}": 0.0 for k in ("mean", "std", "min", "max", "n")}
    a = np.asarray(values, dtype=float)
    return {
        f"{prefix}_mean": float(a.mean()),
        f"{prefix}_std": float(a.std()),
        f"{prefix}_min": float(a.min()),
        f"{prefix}_max": float(a.max()),
        f"{prefix}_n": float(len(a)),
    }


def _autocorr_lag1(values: List[float]) -> float:
    if len(values) < 3:
        return 0.0
    a = np.asarray(values, dtype=float)
    a = a - a.mean()
    denom = float((a * a).sum())
    if denom == 0:
        return 0.0
    return float((a[:-1] * a[1:]).sum() / denom)


def _clienthello_features(payload: bytes) -> Tuple[float, float, float]:
    """(n_cipher_suites, n_extensions, sni_len) из TLS ClientHello; нули если нет."""
    try:
        if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x01:
            return (0.0, 0.0, 0.0)
        pos = 5 + 4 + 2 + 32
        sid = payload[pos]; pos += 1 + sid
        cs_len = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
        n_cs = cs_len // 2
        pos += cs_len
        comp = payload[pos]; pos += 1 + comp
        ext_total = int.from_bytes(payload[pos:pos + 2], "big"); pos += 2
        end = pos + ext_total
        n_ext = 0
        sni_len = 0
        while pos + 4 <= end and pos + 4 <= len(payload):
            etype = int.from_bytes(payload[pos:pos + 2], "big")
            elen = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += 4
            n_ext += 1
            if etype == 0x0000 and pos + 5 <= len(payload):
                sni_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
            pos += elen
        return (float(n_cs), float(n_ext), float(sni_len))
    except Exception:
        return (0.0, 0.0, 0.0)


def _flow_key(p: Packet):
    a = (p.src, p.sport)
    b = (p.dst, p.dport)
    lo, hi = sorted([a, b])
    return (lo, hi, p.proto)


def extract_features(pcap_path: str) -> Dict[str, float]:
    """Вектор фич V1–V7 для одного pcap. Пустой/битый pcap -> нули."""
    pkts = read_packets(pcap_path)
    feats: Dict[str, float] = {}
    if not pkts:
        return _empty_features()

    pkts.sort(key=lambda p: p.ts)
    client = pkts[0].src  # инициатор = src первого пакета
    sizes = [p.length for p in pkts]
    up = [p for p in pkts if p.src == client]
    down = [p for p in pkts if p.src != client]

    # V1 — размеры пакетов (особенно первые 10)
    feats.update(_stats(sizes, "v1_size"))
    first10 = sizes[:10] + [0] * max(0, 10 - len(sizes))
    for i, s in enumerate(first10):
        feats[f"v1_size_first{i}"] = float(s)

    # V2 — тайминги (IAT) + бёрстность/автокорреляция
    iats = list(np.diff([p.ts for p in pkts])) if len(pkts) > 1 else []
    feats.update(_stats([x * 1000 for x in iats], "v2_iat_ms"))
    feats["v2_iat_autocorr1"] = _autocorr_lag1(iats)
    # бёрстность: доля межпакетных интервалов < 1мс
    feats["v2_burst_frac"] = (float(np.mean([1.0 if x < 1e-3 else 0.0 for x in iats]))
                              if iats else 0.0)

    # V3 — up/down симметрия
    up_bytes = sum(p.length for p in up)
    down_bytes = sum(p.length for p in down)
    total_bytes = up_bytes + down_bytes or 1
    feats["v3_up_byte_frac"] = up_bytes / total_bytes
    feats["v3_down_byte_frac"] = down_bytes / total_bytes
    feats["v3_up_pkt_frac"] = len(up) / len(pkts)
    feats["v3_updown_byte_ratio"] = up_bytes / (down_bytes or 1)

    # V4 — энтропия полезной нагрузки (первый payload + средняя)
    payloads = [p.payload for p in pkts if p.payload]
    first_payload = payloads[0][:256] if payloads else b""
    feats["v4_entropy_first"] = _shannon(first_payload)
    feats["v4_entropy_mean"] = (float(np.mean([_shannon(pl[:256]) for pl in payloads[:50]]))
                                if payloads else 0.0)

    # V5 — отпечаток хендшейка (proxy: первый client→server payload + ClientHello)
    first_up_payload = next((p.payload for p in up if p.payload), b"")
    n_cs, n_ext, sni_len = _clienthello_features(first_up_payload)
    feats["v5_first_up_payload_len"] = float(len(first_up_payload))
    feats["v5_ch_cipher_suites"] = n_cs
    feats["v5_ch_extensions"] = n_ext
    feats["v5_ch_sni_len"] = sni_len

    # V6 — длина соединения / число потоков
    flows = defaultdict(list)
    for p in pkts:
        flows[_flow_key(p)].append(p)
    feats["v6_duration_s"] = pkts[-1].ts - pkts[0].ts
    feats["v6_num_packets"] = float(len(pkts))
    feats["v6_num_flows"] = float(len(flows))

    # V7 — граф соединений / fan-out. ВАЖНО (ревью Этапа 4): подфичи разные:
    #  - v7_unique_dests: структурно 1 для одноэндпоинтного туннеля; mux НЕ лечит,
    #    только многоэндпоинтность (fronting).
    #  - v7_max_concurrent_flows: надувается параллельными коннектами, но бьёт в
    #    фильтр >3 параллельных TLS к одному серверу.
    dests = {(p.dst, p.dport) for p in up}  # адресаты со стороны клиента
    feats["v7_unique_dests"] = float(len(dests))
    feats["v7_max_concurrent_flows"] = float(_max_concurrent(flows))
    feats["v7_flows_per_dest"] = len(flows) / (len(dests) or 1)

    return feats


def _max_concurrent(flows: Dict) -> int:
    """Максимум одновременно живущих потоков (грубо: по перекрытию [start,end])."""
    intervals = []
    for ps in flows.values():
        ts = [p.ts for p in ps]
        intervals.append((min(ts), max(ts)))
    if not intervals:
        return 0
    events = []
    for s, e in intervals:
        events.append((s, 1)); events.append((e, -1))
    events.sort()
    cur = peak = 0
    for _, d in events:
        cur += d
        peak = max(peak, cur)
    return peak


def _empty_features() -> Dict[str, float]:
    # один проход по реальному извлечению на синтетике дал бы имена; чтобы не
    # плодить рассинхрон, держим явный нулевой вектор тех же ключей.
    keys = (
        [f"v1_size_{k}" for k in ("mean", "std", "min", "max", "n")]
        + [f"v1_size_first{i}" for i in range(10)]
        + [f"v2_iat_ms_{k}" for k in ("mean", "std", "min", "max", "n")]
        + ["v2_iat_autocorr1", "v2_burst_frac",
           "v3_up_byte_frac", "v3_down_byte_frac", "v3_up_pkt_frac", "v3_updown_byte_ratio",
           "v4_entropy_first", "v4_entropy_mean",
           "v5_first_up_payload_len", "v5_ch_cipher_suites", "v5_ch_extensions", "v5_ch_sni_len",
           "v6_duration_s", "v6_num_packets", "v6_num_flows",
           "v7_unique_dests", "v7_max_concurrent_flows", "v7_flows_per_dest"]
    )
    return {k: 0.0 for k in keys}


FEATURE_NAMES = sorted(_empty_features().keys())


def feature_vector(feats: Dict[str, float]) -> List[float]:
    """Упорядоченный вектор по FEATURE_NAMES (стабильный порядок для классификатора)."""
    return [float(feats.get(name, 0.0)) for name in FEATURE_NAMES]
