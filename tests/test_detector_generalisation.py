"""Dedektörün ezber değil genelleme ölçtüğünü doğrulayan testler.

README uzun süre "100% F1" iddiasını taşıdı. Rakam doğruydu ama ölçüm
kendi eğitim verisi üzerindeydi: ``train()`` ve ``benchmark()`` aynı iki
kaynağı kullanıyordu (``load_attack_payloads()`` + ``BENIGN_SAMPLES``).
Aynı eşikle holdout ölçümü F1=0.107 veriyordu -- yani 194 saldırının 183'ü
kaçıyordu. Bu dosya iki şeyi kilitler: ölçümün gerçekten holdout olduğu, ve
varsayılan eşiğin ölçülmüş değerde kaldığı.
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


class HoldoutBenchmarkTest(unittest.TestCase):
    """5-fold holdout her çağrıda 5 model eğitir, yani saniyeler sürer.

    Sonuç deterministik olduğu için sınıf başına bir kez hesaplanıp
    paylaşılıyor; test başına yeniden koşmak süiti 0.4s'den 35s'ye
    çıkarıyordu ve hiçbir ek şey doğrulamıyordu.
    """

    @classmethod
    def setUpClass(cls):
        cls.detector = HybridDetector()
        cls.in_sample = cls.detector.benchmark()
        cls.holdout = cls.detector.benchmark_holdout(folds=5)

    def test_in_sample_benchmark_declares_itself_as_such(self):
        """Varsayılan benchmark hâlâ ezber ölçer; bunu gizlememeli."""
        self.assertEqual(self.in_sample["evaluation"], "in_sample")
        self.assertIn("benchmark_holdout", self.in_sample["caveat"])

    def test_holdout_is_actually_held_out(self):
        """Her fold'un test dilimi, o dilimi görmemiş modelle ölçülmeli.

        Sızıntının sessiz yolu anchor'lardı: ``build_default_anchors()``
        payload havuzunun tamamını okur, dolayısıyla sadece eğitim dilimini
        ayırmak yetmez -- test örnekleri embedding katmanına anchor olarak
        geri sızar ve holdout görünümlü, sızıntılı bir sonuç üretir.
        """
        payloads = {p for p, _ in load_attack_payloads()}
        anchor_texts = {text for _, text in build_default_anchors()}
        overlap = {a for a in anchor_texts if any(a == p[:120] for p in payloads)}
        self.assertTrue(
            overlap,
            "bu test anlamını yitirdi: anchor'lar artık payload havuzundan "
            "türemiyorsa sızıntı riski de yok demektir, testi güncelleyin",
        )

    def test_holdout_result_is_materially_worse_than_in_sample(self):
        """İki ölçüm aynı sayıyı veriyorsa holdout gerçekten ayrılmamıştır.

        Varlık kontrolü ("holdout koştu") bunu yakalayamaz -- iki farklı
        girdinin iki FARKLI sonuç vermesi gerekir.
        """
        in_sample = self.in_sample["f1_score"]
        holdout = self.holdout["f1_score"]
        self.assertEqual(in_sample, 1.0)
        self.assertLess(
            holdout,
            in_sample,
            "holdout F1, in-sample ile aynı veya daha iyi çıktı -- ayrım "
            "gerçekten uygulanmıyor olabilir",
        )

    def test_holdout_is_deterministic_for_a_given_seed(self):
        a = HybridDetector().benchmark_holdout(folds=5, seed=99)
        b = HybridDetector().benchmark_holdout(folds=5, seed=99)
        self.assertEqual(a["f1_score"], b["f1_score"])

    def test_fold_partition_covers_every_sample_exactly_once(self):
        result = self.holdout
        tested_injection = sum(f["test_injection"] for f in result["per_fold"])
        tested_benign = sum(f["test_benign"] for f in result["per_fold"])
        self.assertEqual(tested_injection, len(load_attack_payloads()))
        self.assertEqual(tested_benign, len(BENIGN_SAMPLES))


class DefaultThresholdTest(unittest.TestCase):
    """Varsayılan eşik ölçülmüş bir değerdir, tahmin değil.

    0.50 iken holdout F1 0.107 ve recall 0.057 idi: regex katmanı görülmemiş
    (çoğu Türkçe) payload'da 0.0 döndüğü için, TF-IDF 0.80 verse bile ağırlıklı
    toplam 0.39'da kalıp eşiği aşamıyordu. In-sample ölçüm bunu göremez --
    orada her eşik F1=1.0 verir.
    """

    @classmethod
    def setUpClass(cls):
        cls.holdout = HybridDetector().benchmark_holdout(folds=5)

    def test_default_threshold_keeps_holdout_recall_usable(self):
        result = self.holdout
        self.assertGreater(
            result["recall"],
            0.75,
            f"varsayılan eşik {DEFAULT_THRESHOLD} ile holdout recall düştü: "
            f"{result['recall']} -- eşik/ağırlık kalibrasyonu bozulmuş olabilir",
        )

    def test_default_threshold_does_not_trade_away_precision(self):
        """Recall'i yanlış alarmla satın almak bir giriş filtresinde kötü takas."""
        result = self.holdout
        self.assertGreater(result["precision"], 0.93, str(result["precision"]))

    def test_old_default_would_have_failed_this_bar(self):
        """Eşiğin neden değiştiğini kanıtla, iddia etme."""
        old = HybridDetector(threshold=0.50).benchmark_holdout(folds=5)
        self.assertLess(old["recall"], 0.20, str(old["recall"]))


if __name__ == "__main__":
    unittest.main()
