"""Финальный артефакт Этапа 4: кривая «детектируемость vs цена».

Каждая точка = один транспорт-режим (модуль + конфиг крутилок):
  x = стоимость (overhead_ratio из CostStats; для (b) строгий overhead — по pcap),
  y = детектируемость (TPR атакующего при FPR=1e-3 / 1e-4).
Цель эксперимента — режимы в левом-нижнем углу: низкая цена И низкая
детектируемость. Идеал недостижим (необнаружимых протоколов нет, §0 Этапа 1) —
ищем приемлемый компромисс.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .metrics import DetectionResult


@dataclass
class CostPoint:
    label: str
    overhead_ratio: float          # цена (доля накладных расходов полосы)
    detection: DetectionResult     # детектируемость (TPR@FPR + AUC)
    injected_delay_s: float = 0.0  # дополнительная цена: внесённая задержка
    notes: str = ""


def render_table(points: List[CostPoint]) -> str:
    rows = sorted(points, key=lambda p: (p.overhead_ratio, p.detection.roc_auc))
    head = (f"{'режим':<22} {'overhead':>9} {'delay_s':>8} "
            f"{'TPR@1e-3':>9} {'TPR@1e-4':>9} {'AUC':>6}")
    lines = [head, "-" * len(head)]
    for p in rows:
        t3 = p.detection.tpr_at.get("1e-03", float("nan"))
        t4 = p.detection.tpr_at.get("1e-04", float("nan"))
        lines.append(
            f"{p.label:<22} {p.overhead_ratio:>9.3f} {p.injected_delay_s:>8.3f} "
            f"{t3:>9.3f} {t4:>9.3f} {p.detection.roc_auc:>6.3f}"
        )
    return "\n".join(lines)


def to_dict(points: List[CostPoint]) -> List[dict]:
    return [
        {
            "label": p.label,
            "overhead_ratio": round(p.overhead_ratio, 4),
            "injected_delay_s": round(p.injected_delay_s, 4),
            "detection": p.detection.summary(),
            "notes": p.notes,
        }
        for p in sorted(points, key=lambda p: p.overhead_ratio)
    ]
