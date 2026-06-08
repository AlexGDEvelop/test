"""Классификатор атакующего: намеренно простой RandomForest.

Дисциплина Этапа 1: если ПРОСТОЙ детектор отделяет наш туннель от фона при низком
FPR — сложный тем более. Поэтому берём дешёвый cost-bounded классификатор, как у
реального цензора, и не тюним его в нашу пользу.

Сплит — временной (по порядку захвата), чтобы исключить утечку: модель не должна
видеть «будущее» той же сессии. Это прямое следствие контроля конфаундов (§3
Этапа 1).
"""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from .features import FEATURE_NAMES
from .metrics import DetectionResult, evaluate


def _split(n: int, test_size: float, time_order: Optional[Sequence[float]]):
    idx = np.arange(n)
    if time_order is not None:
        idx = idx[np.argsort(np.asarray(time_order))]
        cut = int(round(n * (1 - test_size)))
        return idx[:cut], idx[cut:]
    rng = np.random.default_rng(0)
    rng.shuffle(idx)
    cut = int(round(n * (1 - test_size)))
    return idx[:cut], idx[cut:]


def train_eval(X: Sequence[Sequence[float]], y: Sequence[int], label: str,
               *, n_estimators: int = 200, test_size: float = 0.3, seed: int = 0,
               time_order: Optional[Sequence[float]] = None
               ) -> Tuple[DetectionResult, RandomForestClassifier]:
    """Обучить детектор и оценить TPR@FPR (positive=туннель)."""
    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=int)
    tr, te = _split(len(y), test_size, time_order)
    clf = RandomForestClassifier(n_estimators=n_estimators, random_state=seed,
                                 class_weight="balanced", n_jobs=-1)
    clf.fit(X[tr], y[tr])
    scores = clf.predict_proba(X[te])[:, 1]
    result = evaluate(label, y[te], scores)
    return result, clf


def feature_importances(clf: RandomForestClassifier, top: int = 10
                        ) -> List[Tuple[str, float]]:
    """Топ-фич, по которым ловят. Нужен для measure-first решения по V7:
    если fan-out (v7_*) в топе — мультиплексирование оправдано данными."""
    imp = clf.feature_importances_
    order = np.argsort(imp)[::-1][:top]
    return [(FEATURE_NAMES[i], float(imp[i])) for i in order]
