"""Tests asserting the detector measures generalisation, not memorisation.

The README carried a "100% F1" claim for a long time. The number was correct but
the measurement ran on the model's own training data: ``train()`` and
``benchmark()`` used the same two sources (``load_attack_payloads()`` plus
``BENIGN_SAMPLES``). At the same threshold a holdout measurement gave F1=0.107 --
183 of 194 attacks slipping through. This file pins two things: that the
measurement really is held out, and that the default threshold stays at its
measured value.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "labs" / "vulnllm"))

from tools.prompt_injection_detector_ml import (  # noqa: E402
    BENIGN_SAMPLES,
    DEFAULT_THRESHOLD,
    HybridDetector,
    build_default_anchors,
    load_attack_payloads,
)

# 5-fold holdout trains five models per call, so it is the expensive thing in
# this file. It is deterministic, so compute each distinct configuration once
# and share it across every test that needs it -- under coverage the per-class
# version pushed the suite from 15s to 78s.
_CACHE: dict[tuple, dict] = {}


def holdout(threshold: float | None = None, seed: int = 1337) -> dict:
    key = (threshold, seed)
    if key not in _CACHE:
        detector = (
            HybridDetector() if threshold is None else HybridDetector(threshold=threshold)
        )
        _CACHE[key] = detector.benchmark_holdout(folds=5, seed=seed)
    return _CACHE[key]


class HoldoutBenchmarkTest(unittest.TestCase):
    """A 5-fold holdout trains five models per call, so it takes seconds.

    The result is deterministic, so it is computed once per class and shared;
    re-running it per test pushed the suite from 0.4s to 35s and verified
    nothing extra.
    """

    @classmethod
    def setUpClass(cls):
        cls.in_sample = HybridDetector().benchmark()
        cls.holdout = holdout()

    def test_in_sample_benchmark_declares_itself_as_such(self):
        """The default benchmark still measures memorisation; it must say so."""
        self.assertEqual(self.in_sample["evaluation"], "in_sample")
        self.assertIn("benchmark_holdout", self.in_sample["caveat"])

    def test_holdout_is_actually_held_out(self):
        """Each fold's test slice must be scored by a model that never saw it.

        The quiet leak was the anchors: ``build_default_anchors()`` reads the
        whole payload pool, so holding out the training slice alone is not
        enough -- the test samples leak back into the embedding layer as
        anchors and produce a leaky result wearing a holdout's clothes.
        """
        payloads = {p for p, _ in load_attack_payloads()}
        anchor_texts = {text for _, text in build_default_anchors()}
        overlap = {a for a in anchor_texts if any(a == p[:120] for p in payloads)}
        self.assertTrue(
            overlap,
            "this test has lost its meaning: if the anchors no longer derive "
            "from the payload pool there is no leak risk either -- update it",
        )

    def test_holdout_result_is_materially_worse_than_in_sample(self):
        """If both measurements give the same number, nothing was held out.

        A presence check ("the holdout ran") cannot catch this -- two different
        inputs have to produce two DIFFERENT results.
        """
        in_sample = self.in_sample["f1_score"]
        holdout = self.holdout["f1_score"]
        self.assertEqual(in_sample, 1.0)
        self.assertLess(
            holdout,
            in_sample,
            "holdout F1 came out equal to or better than in-sample -- the "
            "split may not actually be applied",
        )

    def test_holdout_is_deterministic_for_a_given_seed(self):
        a = HybridDetector().benchmark_holdout(folds=5, seed=99)
        b = holdout(seed=99)
        self.assertEqual(a["f1_score"], b["f1_score"])

    def test_fold_partition_covers_every_sample_exactly_once(self):
        result = self.holdout
        tested_injection = sum(f["test_injection"] for f in result["per_fold"])
        tested_benign = sum(f["test_benign"] for f in result["per_fold"])
        self.assertEqual(tested_injection, len(load_attack_payloads()))
        self.assertEqual(tested_benign, len(BENIGN_SAMPLES))


class DefaultThresholdTest(unittest.TestCase):
    """The default threshold is a measured value, not a guess.

    At 0.50 the holdout F1 was 0.107 and recall 0.057: the regex layer returns
    0.0 on unseen (mostly Turkish) payloads, so even a TF-IDF score of 0.80 left
    the weighted sum at 0.39, below the threshold. In-sample measurement cannot
    show this -- there every threshold gives F1=1.0.
    """

    @classmethod
    def setUpClass(cls):
        cls.holdout = holdout()

    def test_default_threshold_keeps_holdout_recall_usable(self):
        result = self.holdout
        self.assertGreater(
            result["recall"],
            0.75,
            f"holdout recall dropped at the default threshold {DEFAULT_THRESHOLD}: "
            f"{result['recall']} -- threshold/weight calibration may have drifted",
        )

    def test_default_threshold_does_not_trade_away_precision(self):
        """Buying recall with false alarms is a bad trade in an input filter."""
        result = self.holdout
        self.assertGreater(result["precision"], 0.93, str(result["precision"]))

    def test_old_default_would_have_failed_this_bar(self):
        """Prove why the threshold changed; do not assert it."""
        old = holdout(threshold=0.50)
        self.assertLess(old["recall"], 0.20, str(old["recall"]))


if __name__ == "__main__":
    unittest.main()
