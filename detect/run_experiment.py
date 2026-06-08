"""Финальный артефакт Этапа 4: прогнать каждый транспорт-режим через детектор и
собрать кривую «детектируемость vs цена».

Вход — директории pcap (по директории на модуль + директория фона), снятые ОДНИМ
захватчиком. Для каждого модуля: обучаем детектор «модуль vs фон», считаем
TPR@FPR; overhead берём из pcap (суммарные байты на сессию) относительно базлайна
plain — это строгий pcap-overhead, обещанный для (b).

Запуск:
    python -m detect.run_experiment --background data/background \
        plain=data/tunnel_plain padded=data/tunnel_padded \
        reality=data/tunnel_reality quic=data/tunnel_quic
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from typing import Dict, List, Tuple

import numpy as np

from .classifier import feature_importances, train_eval
from .cost_curve import CostPoint, render_table, to_dict
from .features import extract_features, feature_vector


def _load_dir(d: str) -> List[Dict[str, float]]:
    feats = []
    for path in sorted(glob.glob(os.path.join(d, "*.pcap"))):
        feats.append(extract_features(path))
    if not feats:
        raise SystemExit(f"нет .pcap в {d}")
    return feats


def _mean_total_bytes(feats: List[Dict[str, float]]) -> float:
    # суммарные байты на проводе на сессию ≈ средний размер кадра * число кадров
    return float(np.mean([f["v1_size_mean"] * f["v1_size_n"] for f in feats]))


def run_experiment(module_dirs: Dict[str, str], background_dir: str
                   ) -> Tuple[List[CostPoint], Dict[str, list]]:
    bg = _load_dir(background_dir)
    bg_X = [feature_vector(f) for f in bg]

    module_feats = {label: _load_dir(d) for label, d in module_dirs.items()}
    plain_total = (_mean_total_bytes(module_feats["plain"])
                   if "plain" in module_feats else None)

    points: List[CostPoint] = []
    importances: Dict[str, list] = {}
    for label, feats in module_feats.items():
        mod_X = [feature_vector(f) for f in feats]
        X = mod_X + bg_X
        y = [1] * len(mod_X) + [0] * len(bg_X)
        # Временной сплит против утечки: индекс сессии внутри своего класса
        # (файлы отсортированы по порядку захвата) -> ранние сессии в train,
        # поздние в test, стратифицированно по обоим классам.
        time_order = list(range(len(mod_X))) + list(range(len(bg_X)))
        result, clf = train_eval(X, y, label=label, time_order=time_order)
        importances[label] = feature_importances(clf, top=8)
        mean_total = _mean_total_bytes(feats)
        overhead = (mean_total / plain_total - 1.0) if plain_total else float("nan")
        note = "" if plain_total else "overhead требует модуля 'plain' как базлайна"
        points.append(CostPoint(label=label, overhead_ratio=overhead,
                                detection=result, notes=note))
    return points, importances


def _main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--background", required=True)
    p.add_argument("--json-out")
    p.add_argument("modules", nargs="+", help="label=dir, напр. padded=data/tunnel_padded")
    args = p.parse_args(argv)

    module_dirs = {}
    for spec in args.modules:
        label, _, d = spec.partition("=")
        if not d:
            p.error(f"ожидался label=dir, получено {spec!r}")
        module_dirs[label] = d

    points, importances = run_experiment(module_dirs, args.background)
    print(render_table(points))
    print("\nТоп-фичи детектора (для measure-first по V7):")
    for label, imp in importances.items():
        top3 = ", ".join(f"{n}={v:.2f}" for n, v in imp[:3])
        print(f"  {label}: {top3}")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({"curve": to_dict(points), "importances": importances},
                      f, ensure_ascii=False, indent=2)
        print(f"\nJSON -> {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
