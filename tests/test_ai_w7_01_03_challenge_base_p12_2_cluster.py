"""AI-W7-01 + AI-W7-03-NEW (P12-2 cluster #1+#2) — BaseChallenge.secrets +
atlas_mapping are now per-instance copies.

Pre-fix:
    labs/vulnllm/challenges/base.py:67-68 declared
        secrets: dict = {}
        atlas_mapping: list = []
    as class-body annotations. Subclasses ch01..ch10 override these at
    class level too -- BUT every instance of a given subclass shared
    the SAME dict/list because Python class-level mutable defaults
    cascade. Mutating one challenge's secrets/atlas_mapping leaked
    into all other instances of the same subclass.

Pattern P12-2 'class-level mutable default cascade' -- 4-vaka graduation
cluster (this file = #1+#2; defenses/guards.py:264 = #3 PIIScanner.PATTERNS;
challenges/ch08_rag_poisoning.py:19 = #4 knowledge_base).

Post-fix:
    BaseChallenge.__init__ now performs
        self.secrets = dict(self.__class__.secrets)
        self.atlas_mapping = list(self.__class__.atlas_mapping)
    so:
      - Subclass override values still resolve (read via self.__class__)
      - Each instance gets its own dict/list (no shared mutation)
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_VULNLLM = Path(__file__).resolve().parents[1] / "labs" / "vulnllm"
if str(_VULNLLM) not in sys.path:
    sys.path.insert(0, str(_VULNLLM))


class ChallengeBaseInstanceIsolation(unittest.TestCase):
    """AI-W7-01 + AI-W7-03-NEW closure guard."""

    def _import_ch01(self):
        from challenges.ch01_prompt_injection import PromptInjectionChallenge
        return PromptInjectionChallenge

    def test_secrets_is_per_instance_dict(self) -> None:
        cls = self._import_ch01()
        a = cls()
        b = cls()
        self.assertIsNot(
            a.secrets, b.secrets,
            "P12-2 #1: a.secrets is b.secrets -- class-level mutable "
            "cascade not closed; instances share the same dict.",
        )

    def test_atlas_mapping_is_per_instance_list(self) -> None:
        cls = self._import_ch01()
        a = cls()
        b = cls()
        self.assertIsNot(
            a.atlas_mapping, b.atlas_mapping,
            "P12-2 #2: a.atlas_mapping is b.atlas_mapping -- class-level "
            "mutable cascade not closed.",
        )

    def test_subclass_secrets_values_preserved(self) -> None:
        """The instance copy must inherit subclass override values."""
        cls = self._import_ch01()
        a = cls()
        # ch01 subclass declared: secrets = {"password": "PHOENIX-2847"}
        self.assertEqual(a.secrets.get("password"), "PHOENIX-2847",
                         "Subclass `secrets` override not preserved by "
                         "instance copy (regression -- would mean we "
                         "wiped values via naive `self.secrets = {}`).")

    def test_subclass_atlas_mapping_values_preserved(self) -> None:
        cls = self._import_ch01()
        a = cls()
        # ch01 subclass declared: atlas_mapping = ["AML.T0051", "AML.T0051.000", "AML.T0051.001"]
        self.assertIn("AML.T0051", a.atlas_mapping)
        self.assertEqual(len(a.atlas_mapping), 3)

    def test_mutation_does_not_bleed_between_instances(self) -> None:
        """End-to-end: mutate one instance, verify other untouched."""
        cls = self._import_ch01()
        a = cls()
        b = cls()
        a.secrets["injected_attack"] = "PWN"
        a.atlas_mapping.append("AML.T9999")
        self.assertNotIn("injected_attack", b.secrets,
                         "P12-2 leak: mutation of a.secrets bled into b.secrets")
        self.assertNotIn("AML.T9999", b.atlas_mapping,
                         "P12-2 leak: mutation of a.atlas_mapping bled into b.atlas_mapping")

    def test_cross_challenge_isolation(self) -> None:
        """Different subclasses should naturally have different values
        AND different identities."""
        from challenges.ch01_prompt_injection import PromptInjectionChallenge
        from challenges.ch02_info_disclosure import InfoDisclosureChallenge
        a = PromptInjectionChallenge()
        b = InfoDisclosureChallenge()
        self.assertIsNot(a.secrets, b.secrets)
        self.assertIsNot(a.atlas_mapping, b.atlas_mapping)


if __name__ == "__main__":
    unittest.main()
