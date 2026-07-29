"""README'nin sayılabilir iddiaları koda uyuyor mu.

README "21 defense modules" diyordu; koddaki gerçek sayı 27'ydi. Kimse
hata yapmamıştı -- savunma eklendi, düzyazıdaki sayı yerinde kaldı. Elle
yazılan sayılar bunu yapar, ve bu depo aynı şeyi daha önce de yaşadı.

Bu test damgalayıcıyı `--check` kipinde çalıştırır: bir sayı koddan
ayrıştığı anda süit kırmızıya döner, README'yi kimsenin fark etmesine
gerek kalmaz.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "scripts"))

import readme_stamp as rs  # noqa: E402


class ReadmeMetricsTest(unittest.TestCase):
    def test_stamped_files_match_the_code(self):
        """Her damgalanan dosya, taşıması beklenen metriklerle.

        Tek dosya değil: `tools/README.md` uzun süre damganın dışındaydı ve
        altında sessizce sürüklendi (geri çekilmiş "100% F1", 9 kurallık
        motor için "17 rules", 80 örnek için "88"). Düzeltme, kusurun bir
        tablo ötesine uygulanmıştı.
        """
        for path, names in rs.TARGETS.items():
            with self.subTest(file=path.name, parent=path.parent.name):
                _, drift = rs.stamp_text(rs._read(path), rs.REPO_ROOT, names)
                self.assertEqual(
                    drift,
                    [],
                    f"{path.name} sayıları koddan ayrışmış -- "
                    f"`python scripts/readme_stamp.py` çalıştırın: {drift}",
                )

    def test_a_deleted_marker_counts_as_drift(self):
        """Marker silmek metriği sessizce kapatmamalı.

        Eskiden stderr'e uyarı basıp drift listesini boş bırakıyordu, yani
        `--check` 0 dönüyordu: bir marker'ı silmek o sayıyı denetimden
        çıkarmanın en kolay yoluydu ve iş yeşil kalıyordu.
        """
        text = rs._read(rs.README)
        names = rs.TARGETS[rs.README]
        victim = names[0]
        stripped = rs._marker_re(victim).sub("(silindi)", text)

        _, drift = rs.stamp_text(stripped, rs.REPO_ROOT, names)
        self.assertTrue(
            any(name == victim and old == "<marker yok>" for name, old, _ in drift),
            f"{victim} marker'i silindi ama drift olarak raporlanmadi: {drift}",
        )

    def test_defense_count_excludes_bases_and_helpers(self):
        """Sayım bir yargı içeriyor; yargının kendisi test edilmeli.

        İlk sürüm yalnızca veri taşıyıcılarını dışlayıp 27 yerine 31 saydı --
        soyut tabanları (InputGuard/OutputGuard) ve özel yardımcıları
        (_TFIDFModel) savunma sanmıştı. README'deki yanlış bir sayıyı
        başka bir yanlış sayıyla değiştirmek olurdu.
        """
        import ast

        names = []
        for path in sorted((rs.REPO_ROOT / "labs" / "vulnllm" / "defenses").glob("*.py")):
            if path.name == "__init__.py":
                continue
            for node in ast.parse(path.read_text(encoding="utf-8")).body:
                if isinstance(node, ast.ClassDef) and rs._is_defense_class(node):
                    names.append(node.name)

        self.assertNotIn("InputGuard", names, "soyut taban sınıf sayılmamalı")
        self.assertNotIn("OutputGuard", names, "soyut taban sınıf sayılmamalı")
        self.assertNotIn("GuardResult", names, "veri taşıyıcı sayılmamalı")
        self.assertFalse(
            [n for n in names if n.startswith("_")], "özel yardımcı sayılmamalı"
        )
        self.assertIn("PerplexityFilter", names, "gerçek bir guard sayılmalı")
        self.assertEqual(len(names), rs.count_defense_modules(rs.REPO_ROOT))

    def test_attack_payload_count_comes_from_the_loader(self):
        """194 sayısı düzyazıda birkaç yerde geçiyordu ama kodda kaynağı yoktu.

        Sayaç, modelin gerçekten eğitildiği yükleyiciyi çağırır -- bir
        literali sayarsa modelin gördüğünden sapabilir.
        """
        sys.path.insert(0, str(_ROOT / "labs" / "vulnllm"))
        from tools.prompt_injection_detector_ml import load_attack_payloads

        self.assertEqual(
            rs.count_attack_payloads(rs.REPO_ROOT), len(load_attack_payloads())
        )


if __name__ == "__main__":
    unittest.main()
