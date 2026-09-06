"""Statistics: verified against closed-form / known values."""
import numpy as np

from boundsec.analysis.metrics import (
    average_precision,
    bootstrap_ci,
    calibration_bins,
    compare_strategies,
    mann_whitney_u,
    roc_auc,
    vargha_delaney_a12,
)


def test_roc_auc_perfect_separation():
    y = np.r_[np.ones(20), np.zeros(20)]
    s = np.r_[np.ones(20) * 0.9, np.ones(20) * 0.1]
    assert roc_auc(s, y) == 1.0


def test_roc_auc_random_is_half():
    rng = np.random.default_rng(0)
    y = np.r_[np.ones(500), np.zeros(500)]
    s = rng.random(1000)
    assert abs(roc_auc(s, y) - 0.5) < 0.05


def test_a12_symmetry():
    a = np.array([5, 6, 7, 8]); b = np.array([1, 2, 3, 4])
    assert vargha_delaney_a12(a, b) == 1.0
    assert vargha_delaney_a12(b, a) == 0.0
    assert abs(vargha_delaney_a12(a, a) - 0.5) < 1e-9


def test_mann_whitney_detects_difference():
    a = np.array([10, 11, 12, 13, 14, 15])
    b = np.array([1, 2, 3, 4, 5, 6])
    res = mann_whitney_u(a, b)
    assert res["p"] < 0.01
    assert abs(res["rank_biserial"]) > 0.9


def test_average_precision_perfect():
    y = np.r_[np.ones(10), np.zeros(10)]
    s = np.r_[np.ones(10) * 0.9, np.ones(10) * 0.1]
    assert average_precision(s, y) == 1.0


def test_bootstrap_ci_contains_mean():
    x = np.arange(50.0)
    m, lo, hi = bootstrap_ci(x, seed=0)
    assert lo <= m <= hi


def test_calibration_ece_zero_when_perfect():
    # scores exactly equal to empirical rate within each bin
    scores = np.r_[np.zeros(50), np.ones(50)]
    labels = np.r_[np.zeros(50), np.ones(50)]
    cal = calibration_bins(scores, labels)
    assert cal["ece"] < 1e-9


def test_compare_strategies_reports_lift():
    a = [12, 13, 14, 15]; b = [6, 7, 8, 9]
    cmp = compare_strategies(a, b, "guided", "static")
    assert cmp.lift_pct > 50 and cmp.a12 == 1.0
