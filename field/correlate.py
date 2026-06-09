"""4.5.4 Сопоставление поле <-> лаборатория. НЕ делает выводов — печатает маппинг.

Вход: полевые JSON раннера (по транспорту) + лабораторный curve.json Этапа 4.
Удушение определяется ПАРАМЕТРАМИ (не магия): baseline = медиана первых
--baseline-window окон после --warmup-skip (прогрев congestion control), порог =
--drop-pct% от baseline, удушение = --consecutive окон ПОДРЯД ниже порога.
Печатается сам timeseries — отличить реальную просадку от шума глазами.

Логика маппинга (§5.5), как ПОДСКАЗКА, вывод за человеком:
  лаб «чисто» + поле «душит» -> вектор вне фич (вероятно IP/ASN-репутация);
  лаб «палит» + поле «душит» -> согласовано (та фича, что в топе);
  лаб «палит» + поле «не душит» -> окно затишья.

Запуск:
    python -m field.correlate --curve curve.json --runner field_plain.json field_reality.json
"""
from __future__ import annotations

import argparse
import json
import statistics
from typing import List, Optional


def detect_throttle(samples: list, warmup_skip: int, baseline_window: int,
                    drop_pct: float, consecutive: int) -> dict:
    speeds = [s["speed_bps"] for s in samples]
    times = [s["t"] for s in samples]
    usable = speeds[warmup_skip:]
    if len(usable) < baseline_window + consecutive:
        return {"throttled": None, "reason": "недостаточно окон", "baseline_bps": None}
    baseline = statistics.median(usable[:baseline_window])
    thresh = baseline * drop_pct / 100.0
    run = 0
    t_deg = None
    for i, sp in enumerate(usable):
        if sp < thresh:
            run += 1
            if run >= consecutive and t_deg is None:
                t_deg = times[warmup_skip + i - consecutive + 1]
        else:
            run = 0
    return {"throttled": t_deg is not None, "baseline_bps": round(baseline),
            "thresh_bps": round(thresh), "t_degraded_s": t_deg}


def _spark(samples, thresh_bps) -> str:
    """Строка скоростей (kbps), ниже порога помечены '*'."""
    parts = []
    for s in samples:
        kbps = s["speed_bps"] / 1000
        mark = "*" if (thresh_bps and s["speed_bps"] < thresh_bps) else " "
        parts.append(f"{kbps:6.0f}{mark}")
    return "".join(parts)


def _load_curve(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = {}
    imp = data.get("importances", {})
    for entry in data.get("curve", []):
        label = entry["label"]
        det = entry.get("detection", {})
        tpr = det.get("tpr_at_fpr", {})
        top = imp.get(label, [])
        out[label] = {
            "tpr_1e3": tpr.get("1e-03"), "tpr_1e4": tpr.get("1e-04"),
            "roc_auc": det.get("roc_auc"),
            "top_feat": top[0][0] if top else None,
        }
    return out


def _interpretation(lab: Optional[dict], throttled, lab_flag_tpr: float) -> str:
    if throttled is None:
        return "поле: недостаточно данных"
    if lab is None:
        return "нет лабораторных данных по этому транспорту (curve.json)"
    flags = lab["tpr_1e3"] is not None and lab["tpr_1e3"] >= lab_flag_tpr
    if flags and throttled:
        return f"СОГЛАСОВАНО: лаб палит (top={lab['top_feat']}), поле душит"
    if flags and not throttled:
        return "ОКНО ЗАТИШЬЯ: лаб палит, но поле пока не душит"
    if (not flags) and throttled:
        return "ВЕКТОР ВНЕ ФИЧ: лаб чисто, а поле душит -> вероятно IP/ASN-репутация"
    return "чисто и в лаборатории, и в поле"


def _main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runner", nargs="+", required=True, help="JSON-файлы раннера")
    p.add_argument("--curve", help="curve.json Этапа 4 (опционально)")
    p.add_argument("--warmup-skip", type=int, default=1, help="окон прогрева в начале")
    p.add_argument("--baseline-window", type=int, default=3, help="окон для baseline")
    p.add_argument("--drop-pct", type=float, default=50, help="порог = X%% от baseline")
    p.add_argument("--consecutive", type=int, default=3, help="окон подряд ниже порога = удушение")
    p.add_argument("--lab-flag-tpr", type=float, default=0.5,
                   help="подсказка: TPR@1e-3 >= этого = 'лаб палит' (только для маппинга)")
    args = p.parse_args(argv)

    lab = _load_curve(args.curve) if args.curve else {}

    print(f"Пороги: warmup_skip={args.warmup_skip} baseline_window={args.baseline_window} "
          f"drop={args.drop_pct}% consecutive={args.consecutive}\n")
    for path in args.runner:
        with open(path, encoding="utf-8") as f:
            r = json.load(f)
        tr = r["transport"]
        d = detect_throttle(r["samples"], args.warmup_skip, args.baseline_window,
                            args.drop_pct, args.consecutive)
        labrow = lab.get(tr)
        print(f"=== {tr} (operator={r.get('operator')}) ===")
        print(f"  поле: throttled={d['throttled']} baseline={d['baseline_bps']}bps "
              f"thresh={d['thresh_bps']}bps t_degraded={d.get('t_degraded_s')}s "
              f"resets={sum(s['resets'] for s in r['samples'])}")
        print(f"  timeseries kbps ('*'=ниже порога): {_spark(r['samples'], d.get('thresh_bps'))}")
        if labrow:
            print(f"  лаб: TPR@1e-3={labrow['tpr_1e3']} TPR@1e-4={labrow['tpr_1e4']} "
                  f"top_feat={labrow['top_feat']}")
        print(f"  интерпретация (вывод за тобой): "
              f"{_interpretation(labrow, d['throttled'], args.lab_flag_tpr)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
