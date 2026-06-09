"""Тесты Этапа 4.5 (поле) на loopback — проверяют МЕХАНИКУ, не само удушение.

Удушение требует реального ТСПУ (клиент РФ, сервер заграница). Здесь:
- раннер собирает корректный timeseries через loopback-туннель;
- server_log даёт СЫРЫЕ факты по соединениям из pcap (+ совместимость с
  detect.features), без вердикта «зонд»;
- correlate.detect_throttle отличает устойчивую просадку от одиночного провала;
- selfprobe помечает quic как INCONCLUSIVE.

Запуск: python tests/test_field.py
"""
from __future__ import annotations

import os
import socket
import ssl
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dpkt

from detect.connect_proxy import ConnectProxy
from detect.features import extract_features
from field.correlate import detect_throttle
from field.runner import drive
from field.server_log import connections_from_pcap
from transport.carrier_tunnel import CarrierTunnelClient, CarrierTunnelServer
from transport.reality import ControlTlsDonor
from transport.tls_util import generate_self_signed
from transports import TransportSpec, make_client, make_server
from tunnel import keys


def _astr(addr):
    return f"{addr[0]}:{addr[1]}"


# --------------------------- 1. раннер: timeseries ----------------------------

def test_runner_collects_timeseries():
    cert, key = generate_self_signed("localhost")
    site = ControlTlsDonor("127.0.0.1:0", cert, key, body=b"FIELD-BODY-" + b"x" * 500).start()
    proxy = ConnectProxy(("127.0.0.1", 0)).start()
    s, c = keys.generate(), keys.generate()
    spec = TransportSpec(name="plain")
    server = CarrierTunnelServer(make_server=lambda h: make_server(spec, "127.0.0.1:0", h),
                                 target=_astr(proxy.addr), static_private=s.private).start()
    client = CarrierTunnelClient("127.0.0.1:0", make_client(spec, _astr(server.address)),
                                 static_private=c.private, server_public=s.public).start()
    proxy_url = f"http://127.0.0.1:{client.address[1]}"
    url = f"https://127.0.0.1:{site.address[1]}/"
    try:
        samples, events = drive(proxy_url, [url], duration_s=2.0, interval_s=1.0,
                                ssl_ctx=ssl._create_unverified_context())
        assert samples, "timeseries пуст"
        assert any(s_["bytes"] > 0 for s_ in samples), "ни одного байта не скачано"
        assert all({"t", "speed_bps", "rtt_ms", "resets"} <= set(s_) for s_ in samples)
        print(f"OK test_runner_collects_timeseries ({len(samples)} окон, "
              f"max speed={max(s_['speed_bps'] for s_ in samples)} bps)")
    finally:
        client.stop(); server.stop(); proxy.stop(); site.stop()


# ------------------ 2. server_log: сырые факты + совместимость -----------------

def _frame(src, dst, sport, dport, flags, payload=b""):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=1, ack=1, off=5, flags=flags, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=b"\x00\x11\x22\x33\x44\x55",
                                 dst=b"\x66\x77\x88\x99\xaa\xbb",
                                 type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


def test_connections_raw_facts_and_features_compat():
    d = tempfile.mkdtemp(prefix="field_")
    pcap = os.path.join(d, "t.pcap")
    SRV, PORT = "10.0.0.2", 5555
    recs = []
    t = 1000.0
    # conn1: клиент 10.0.0.1 -> сервер:5555 (SYN, данные туда-обратно)
    recs.append((t, _frame("10.0.0.1", SRV, 40000, PORT, dpkt.tcp.TH_SYN))); t += 0.01
    recs.append((t, _frame("10.0.0.1", SRV, 40000, PORT, dpkt.tcp.TH_ACK, b"hello" * 50))); t += 0.01
    recs.append((t, _frame(SRV, "10.0.0.1", PORT, 40000, dpkt.tcp.TH_ACK, b"resp" * 60))); t += 0.5
    # conn2: посторонний 10.9.9.9 -> сервер:5555 (SYN, затем RST)
    recs.append((t, _frame("10.9.9.9", SRV, 50000, PORT, dpkt.tcp.TH_SYN))); t += 0.01
    recs.append((t, _frame("10.9.9.9", SRV, 50000, PORT, dpkt.tcp.TH_RST))); t += 0.01
    with open(pcap, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, raw in recs:
            w.writepkt(raw, ts=ts)

    conns = connections_from_pcap(pcap, PORT, client_ip="10.0.0.1")
    by_src = {c["src"]: c for c in conns}
    assert set(by_src) == {"10.0.0.1", "10.9.9.9"}, by_src
    assert by_src["10.0.0.1"]["from_client_ip"] is True
    assert by_src["10.0.0.1"]["bytes_up"] > 0 and by_src["10.0.0.1"]["bytes_down"] > 0
    assert by_src["10.9.9.9"]["from_client_ip"] is False
    assert by_src["10.9.9.9"]["rst"] is True
    # СЫРЫЕ факты: никакого вердикта "probe"
    assert all("probe" not in c for c in conns), "сырые факты не должны содержать вердикт"
    # совместимость: тот же pcap ест detect.features без изменений
    feats = extract_features(pcap)
    assert feats["v6_num_packets"] > 0 and "v1_size_n" in feats
    print("OK test_connections_raw_facts_and_features_compat "
          "(сырые факты + features-совместимость, без вердикта)")


# --------------------- 3. correlate: порог удушения ---------------------------

def test_throttle_detection_params():
    def ts(speeds):
        return [{"t": i, "speed_bps": v, "resets": 0} for i, v in enumerate(speeds)]

    sustained = ts([100_000, 100_000, 100_000, 100_000, 100_000, 40_000, 40_000, 40_000])
    r = detect_throttle(sustained, warmup_skip=1, baseline_window=3, drop_pct=50, consecutive=3)
    assert r["throttled"] is True and r["t_degraded_s"] is not None, r

    single_dip = ts([100_000, 100_000, 100_000, 100_000, 40_000, 100_000, 100_000, 100_000])
    r2 = detect_throttle(single_dip, warmup_skip=1, baseline_window=3, drop_pct=50, consecutive=3)
    assert r2["throttled"] is False, r2
    print("OK test_throttle_detection_params (устойчивая просадка != одиночный провал)")


# --------------------------- 4. selfprobe quic --------------------------------

def test_selfprobe_quic_inconclusive():
    from field import selfprobe
    rc = selfprobe._main(["--host", "127.0.0.1", "--port", "1", "--transport", "quic"])
    assert rc == 0
    # TCP-зонд на закрытый порт не падает, а возвращает факт
    res = selfprobe.probe_tls("127.0.0.1", 1, timeout=1.0)
    assert res["tls_completed"] is False and res["error"]
    print("OK test_selfprobe_quic_inconclusive (quic помечен; TCP-зонд не падает)")


def test_remote_bench_fetch_via_real_server():
    """RemoteBench: клиент к ОТДЕЛЬНОМУ carrier-серверу (как VPS), фетч через него."""
    from detect.generate import RemoteBench
    cert, key = generate_self_signed("localhost")
    site = ControlTlsDonor("127.0.0.1:0", cert, key, body=b"REMOTE-OK" * 100).start()
    proxy = ConnectProxy(("127.0.0.1", 0)).start()
    s, c = keys.generate(), keys.generate()
    spec = TransportSpec(name="plain")
    server = CarrierTunnelServer(make_server=lambda h: make_server(spec, "127.0.0.1:0", h),
                                 target=_astr(proxy.addr), static_private=s.private).start()
    cfg = {"client": {"static_private": c.private_hex, "server_public": s.public_hex,
                      "server_addr": _astr(server.address), "local_bind": "127.0.0.1:0"}}
    bench = RemoteBench("plain", cfg)
    try:
        body = bench.fetch(f"https://127.0.0.1:{site.address[1]}/",
                           ssl_ctx=ssl._create_unverified_context(), timeout=10)
        assert b"REMOTE-OK" in body, "RemoteBench не дотянулся через carrier-сервер"
        print("OK test_remote_bench_fetch_via_real_server")
    finally:
        bench.stop(); server.stop(); proxy.stop(); site.stop()


def _run_all():
    tests = [test_runner_collects_timeseries,
             test_connections_raw_facts_and_features_compat,
             test_throttle_detection_params,
             test_selfprobe_quic_inconclusive,
             test_remote_bench_fetch_via_real_server]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {t.__name__}: {exc!r}")
    print(f"\n{len(tests) - failed}/{len(tests)} прошло")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
