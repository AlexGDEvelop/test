"""Тесты лаборатории обнаружения (Этап 4), на СИНТЕТИЧЕСКИХ pcap.

Проверяем аналитический конвейер end-to-end без tshark: синтезируем два
различимых класса pcap (туннель-подобный одиночный flow vs фон с веером
потоков), извлекаем V1–V7, обучаем детектор, считаем TPR@FPR. Реальный
negative-класс (живой браузинг через tshark) — стенд-сайд, см. stage4 runbook.

Запуск: python tests/test_detection.py
"""
from __future__ import annotations

import os
import random
import socket
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dpkt

from detect.classifier import feature_importances, train_eval
from detect.cost_curve import CostPoint, render_table
from detect.features import extract_features, feature_vector
from detect.metrics import evaluate, min_negatives_for_fpr, tpr_at_fpr


# ----------------------- синтез pcap (dpkt, linktype EN10MB) -------------------

def _frame(src, dst, sport, dport, payload):
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=1, ack=1, off=5,
                       flags=dpkt.tcp.TH_ACK, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(src=b"\x00\x11\x22\x33\x44\x55",
                                 dst=b"\x66\x77\x88\x99\xaa\xbb",
                                 type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    return bytes(eth)


def _write(path, records):
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, raw in records:
            w.writepkt(raw, ts=ts)


def _payload(n):
    return bytes(random.getrandbits(8) for _ in range(max(0, n - 54)))


def _tunnel_pcap(path, rng: random.Random):
    """Одиночный flow, ~единый размер пакета, регулярный тайминг, один адресат."""
    recs = []
    t = 1000.0
    client, server = "10.0.0.1", "10.0.0.2"
    for i in range(40):
        size = 1400 + rng.randint(-20, 20)
        if i % 2 == 0:
            recs.append((t, _frame(client, server, 50000, 443, _payload(size))))
        else:
            recs.append((t, _frame(server, client, 443, 50000, _payload(size))))
        t += 0.005 + rng.uniform(-0.0005, 0.0005)
    _write(path, recs)


def _background_pcap(path, rng: random.Random):
    """Веер: несколько потоков к разным адресатам, разнобой размеров, бёрстность."""
    recs = []
    t = 1000.0
    client = "10.0.0.1"
    dests = [f"93.184.{rng.randint(1,254)}.{rng.randint(1,254)}" for _ in range(rng.randint(3, 5))]
    for _ in range(60):
        dst = rng.choice(dests)
        sport = rng.randint(40000, 60000)
        size = rng.choice([90, 200, 500, 1200, 1400])
        if rng.random() < 0.5:
            recs.append((t, _frame(client, dst, sport, 443, _payload(size))))
        else:
            recs.append((t, _frame(dst, client, 443, sport, _payload(size))))
        t += rng.choice([0.0002, 0.0003, 0.02, 0.05])  # бёрсты + паузы
    recs.sort(key=lambda r: r[0])
    _write(path, recs)


# ------------------------------- unit: метрики --------------------------------

def test_tpr_at_fpr_toy():
    y = [0, 0, 0, 1, 1, 1]
    sep = [0.1, 0.2, 0.3, 0.8, 0.9, 0.95]  # идеально разделимо
    assert tpr_at_fpr(y, sep, 0.0) == 1.0, "при идеальном разделении TPR@FPR=0 = 1.0"
    mixed = [0.1, 0.9, 0.3, 0.4, 0.85, 0.95]
    assert tpr_at_fpr(y, mixed, 0.0) < 1.0
    assert min_negatives_for_fpr(1e-4) == 10000
    print("OK test_tpr_at_fpr_toy")


# --------------------------- интеграция: конвейер -----------------------------

def test_feature_extraction_distinguishes_classes():
    d = tempfile.mkdtemp(prefix="stage4_")
    rng = random.Random(42)
    tp = os.path.join(d, "tunnel0.pcap")
    bp = os.path.join(d, "bg0.pcap")
    _tunnel_pcap(tp, rng)
    _background_pcap(bp, rng)
    ft = extract_features(tp)
    fb = extract_features(bp)
    # туннель: один адресат, фон: несколько
    assert ft["v7_unique_dests"] == 1.0
    assert fb["v7_unique_dests"] >= 3.0
    # туннель: малый разброс размеров; фон: большой
    assert ft["v1_size_std"] < fb["v1_size_std"]
    print(f"OK test_feature_extraction_distinguishes_classes "
          f"(tunnel dests=1 std={ft['v1_size_std']:.0f}; bg dests={fb['v7_unique_dests']:.0f} std={fb['v1_size_std']:.0f})")


def test_detector_pipeline_end_to_end():
    d = tempfile.mkdtemp(prefix="stage4_")
    X, y, order = [], [], []
    t = 0.0
    for i in range(30):
        rng = random.Random(1000 + i)
        tp = os.path.join(d, f"t{i}.pcap"); _tunnel_pcap(tp, rng)
        bp = os.path.join(d, f"b{i}.pcap"); _background_pcap(bp, rng)
        X.append(feature_vector(extract_features(tp))); y.append(1); order.append(t); t += 1
        X.append(feature_vector(extract_features(bp))); y.append(0); order.append(t); t += 1
    result, clf = train_eval(X, y, label="synthetic-plain", time_order=order)
    s = result.summary()
    assert s["roc_auc"] > 0.9, f"детектор не отделил различимые классы: AUC={s['roc_auc']}"
    top = feature_importances(clf, top=5)
    print(f"OK test_detector_pipeline_end_to_end (AUC={s['roc_auc']}, "
          f"TPR@1e-3={s['tpr_at_fpr']['1e-03']}; топ-фича={top[0][0]})")
    # кривая стоимости рендерится
    pts = [CostPoint(label="synthetic-plain", overhead_ratio=0.0, detection=result)]
    assert "synthetic-plain" in render_table(pts)


def _padded_pcap(path, rng: random.Random):
    """Туннель-подобный, но крупнее кадры (имитация паддинга) -> выше overhead."""
    recs = []
    t = 1000.0
    client, server = "10.0.0.1", "10.0.0.2"
    for i in range(40):
        size = 2000 + rng.randint(-20, 20)
        if i % 2 == 0:
            recs.append((t, _frame(client, server, 50000, 443, _payload(size))))
        else:
            recs.append((t, _frame(server, client, 443, 50000, _payload(size))))
        t += 0.005
    _write(path, recs)


def test_run_experiment_assembles_curve():
    from detect.run_experiment import run_experiment
    base = tempfile.mkdtemp(prefix="stage4_exp_")
    dirs = {"plain": os.path.join(base, "plain"),
            "padded": os.path.join(base, "padded"),
            "bg": os.path.join(base, "bg")}
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
    for i in range(12):
        rng = random.Random(7000 + i)
        _tunnel_pcap(os.path.join(dirs["plain"], f"p{i}.pcap"), rng)
        _padded_pcap(os.path.join(dirs["padded"], f"d{i}.pcap"), rng)
        _background_pcap(os.path.join(dirs["bg"], f"b{i}.pcap"), rng)
    points, importances = run_experiment(
        {"plain": dirs["plain"], "padded": dirs["padded"]}, dirs["bg"])
    table = render_table(points)
    assert "plain" in table and "padded" in table
    padded_pt = next(p for p in points if p.label == "padded")
    assert padded_pt.overhead_ratio > 0.2, f"overhead паддинга не виден: {padded_pt.overhead_ratio}"
    print(f"OK test_run_experiment_assembles_curve (padded overhead={padded_pt.overhead_ratio:.2f})")
    print(table)


def _run_all():
    tests = [
        test_tpr_at_fpr_toy,
        test_feature_extraction_distinguishes_classes,
        test_detector_pipeline_end_to_end,
        test_run_experiment_assembles_curve,
    ]
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
