"""Метрики обнаружимости в рабочей точке противника.

Главная метрика (Этап 1, §2): TPR при фиксированном низком FPR, а не средний
ROC-AUC. Цензор работает при крошечном допустимом collateral damage, поэтому
важно, сколько нашего трафика он ловит, удерживая ложные срабатывания на фоне
около нуля.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Sequence

import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve


def tpr_at_fpr(y_true: Sequence[int], scores: Sequence[float],
               fpr_target: float) -> float:
    """Максимальный TPR при FPR <= fpr_target.

    y_true: 1 = наш туннель (positive), 0 = фон (negative).
    scores: оценка детектора «это туннель» (выше = увереннее в туннеле).
    """
    y = np.asarray(y_true)
    s = np.asarray(scores, dtype=float)
    if len(np.unique(y)) < 2:
        return float("nan")
    fpr, tpr, _ = roc_curve(y, s)
    mask = fpr <= fpr_target
    if not mask.any():
        return 0.0
    return float(tpr[mask].max())


@dataclass
class DetectionResult:
    """Сводка по одному прогону детектора против одного транспорт-режима."""
    label: str
    n_pos: int
    n_neg: int
    roc_auc: float                          # вспомогательно
    tpr_at: Dict[str, float] = field(default_factory=dict)  # {"1e-3":.., "1e-4":..}

    def summary(self) -> dict:
        return {
            "label": self.label,
            "n_pos": self.n_pos,
            "n_neg": self.n_neg,
            "roc_auc": round(self.roc_auc, 4),
            "tpr_at_fpr": {k: round(v, 4) for k, v in self.tpr_at.items()},
        }


def evaluate(label: str, y_true: Sequence[int], scores: Sequence[float],
             fpr_targets: Sequence[float] = (1e-3, 1e-4)) -> DetectionResult:
    y = np.asarray(y_true)
    s = np.asarray(scores, dtype=float)
    auc = float(roc_auc_score(y, s)) if len(np.unique(y)) > 1 else float("nan")
    tpr = {f"{f:.0e}": tpr_at_fpr(y, s, f) for f in fpr_targets}
    return DetectionResult(
        label=label, n_pos=int((y == 1).sum()), n_neg=int((y == 0).sum()),
        roc_auc=auc, tpr_at=tpr,
    )


def min_negatives_for_fpr(fpr_target: float) -> int:
    """Сколько негативов нужно, чтобы FPR такого порядка вообще был измерим.

    При N негативах минимальный измеримый ненулевой FPR = 1/N. Для FPR=1e-4
    нужно >=10 000 фоновых примеров, иначе метрика упрётся в гранулярность —
    это предупреждение против ложно-оптимистичного «TPR=0 при FPR=1e-4».
    """
    return int(np.ceil(1.0 / fpr_target))
