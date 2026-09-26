"""Pruebas de las piezas que definen los resultados: métricas, pares y tramos del protocolo rodante."""
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from ueba_ts.detectors import loo_median, segments
from ueba_ts.evaluate import budget_alerts, weighted_ap


def test_weighted_ap_matches_sklearn_with_ties():
    rng = np.random.default_rng(1)
    s = np.round(rng.random(5000) * 5, 1)          # muchos empates, como A = 0 en días sin actividad
    s[rng.random(5000) < 0.4] = 0.0
    y = (rng.random(5000) < 0.02).astype(int)
    assert np.isclose(weighted_ap(s, y), average_precision_score(y, s))


def test_weighted_ap_with_weights_equals_duplication():
    rng = np.random.default_rng(2)
    s, y = rng.random(300), (rng.random(300) < 0.1).astype(int)
    w = rng.integers(0, 3, 300)
    rep = np.repeat(np.arange(300), w)
    assert np.isclose(weighted_ap(s, y, w.astype(float)), average_precision_score(y[rep], s[rep]))


def test_budget_alerts_top_k_per_day():
    A = np.array([[5, 0, 1], [4, 2, 0], [3, 1, 0], [0, 3, 0]], float)
    mask = np.ones_like(A, bool)
    al = budget_alerts(A, mask, 2)
    assert al[:, 0].tolist() == [True, True, False, False]
    assert al[:, 1].tolist() == [False, True, False, True]
    assert al[:, 2].tolist() == [True, False, False, False]   # solo un valor positivo ese día


def test_loo_median_excludes_self():
    Z = np.array([[[1.0]], [[2.0]], [[10.0]]])       # 3 usuarios, 1 día, 1 señal
    active = np.ones((3, 1), bool)
    peer = loo_median(Z, active, np.array(["g", "g", "g"]))
    assert peer[:, 0, 0].tolist() == [6.0, 5.5, 1.5]


def test_rolling_segments_are_monthly_and_contiguous():
    days = pd.date_range("2010-01-02", "2011-05-16")
    segs = segments(days, "2010-06-10", 182)
    assert days[segs[0][1]] == pd.Timestamp("2010-06-10")
    assert all(days[s].day == 1 for _, s, _ in segs[1:])
    assert all(segs[i][2] == segs[i + 1][1] for i in range(len(segs) - 1))
    assert segs[-1][2] == len(days)
    assert all(s - w0 <= 182 for w0, s, _ in segs)
