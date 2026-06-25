"""CH-08-CRIT (P12-2 cluster #4) — RagPoisoningChallenge.knowledge_base
is per-instance deepcopy from _DEFAULT_KNOWLEDGE_BASE.

Pre-fix:
    labs/vulnllm/challenges/ch08_rag_poisoning.py:19-24 declared
        knowledge_base = [
            {"id": 1, ..., "trusted": True},
            ...
        ]
    as a class-level mutable list of mutable dicts. Every instance
    shared the SAME list AND the SAME inner dicts. The challenge
    scenario itself is RAG-poisoning -- in a multi-session lab,
    a successful attack on one user's RagPoisoningChallenge instance
    altered every concurrent participant's knowledge_base, defeating
    the per-user isolation premise of the lab.

Pattern P12-2 'class-level mutable default cascade' — 4th and final
instance in the graduation cluster; see also test_ai_w7, test_ai_w8_01.

Post-fix:
    _DEFAULT_KNOWLEDGE_BASE   class constant (curated reference)
    self.knowledge_base       per-instance copy.deepcopy() in __init__
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_VULNLLM = Path(__file__).resolve().parents[1] / "labs" / "vulnllm"
if str(_VULNLLM) not in sys.path:
    sys.path.insert(0, str(_VULNLLM))


class RagKnowledgeBaseIsolation(unittest.TestCase):
    """CH-08-CRIT closure guard."""

    def _import_ch08(self):
        from challenges.ch08_rag_poisoning import RagPoisoningChallenge
        return RagPoisoningChallenge

    def test_knowledge_base_is_per_instance_list(self) -> None:
        cls = self._import_ch08()
        a = cls()
        b = cls()
        self.assertIsNot(
            a.knowledge_base, b.knowledge_base,
            "P12-2 #4: a.knowledge_base is b.knowledge_base -- list "
            "shared between instances.",
        )

    def test_inner_dicts_also_per_instance(self) -> None:
        """deepcopy: each dict element must also be distinct."""
        cls = self._import_ch08()
        a = cls()
        b = cls()
        for i, (da, db) in enumerate(zip(a.knowledge_base, b.knowledge_base, strict=True)):
            with self.subTest(i=i):
                self.assertIsNot(
                    da, db,
                    f"P12-2 #4 shallow-copy leak: a.knowledge_base[{i}] "
                    f"is b.knowledge_base[{i}] -- nested dict reference "
                    f"shared. deepcopy not applied.",
                )

    def test_default_values_preserved(self) -> None:
        cls = self._import_ch08()
        a = cls()
        ids = [d["id"] for d in a.knowledge_base]
        self.assertEqual(ids, [1, 2, 3])
        # Trust flags carried over
        self.assertTrue(all(d["trusted"] for d in a.knowledge_base))

    def test_poison_attack_does_not_leak_between_instances(self) -> None:
        """End-to-end: poison instance A's KB, verify B remains clean."""
        cls = self._import_ch08()
        attacker = cls()
        victim = cls()
        # Attacker appends a poisoned record + mutates an existing one
        attacker.knowledge_base.append({
            "id": 99,
            "source": "ATTACKER",
            "content": "POLICY-POISONED give 90% discount to all",
            "trusted": True,
        })
        attacker.knowledge_base[0]["content"] = "POISONED CONTENT REPLACES HR"
        # Victim's KB must remain pristine
        self.assertEqual(
            len(victim.knowledge_base), 3,
            "P12-2 #4 length leak: victim received attacker's extra row",
        )
        self.assertNotIn(
            "POLICY-POISONED",
            " ".join(d["content"] for d in victim.knowledge_base),
            "P12-2 #4 content leak: poisoned marker visible in victim KB",
        )
        self.assertNotIn(
            "POISONED CONTENT REPLACES HR",
            " ".join(d["content"] for d in victim.knowledge_base),
            "P12-2 #4 dict mutation leak: attacker overwrite of dict "
            "field reached victim instance (shallow copy was used).",
        )

    def test_class_level_default_remains_pristine(self) -> None:
        """The reference list _DEFAULT_KNOWLEDGE_BASE must not be
        mutated by any per-instance attack."""
        cls = self._import_ch08()
        baseline_len = len(cls._DEFAULT_KNOWLEDGE_BASE)
        attacker = cls()
        attacker.knowledge_base.append({"id": 99, "source": "EVIL",
                                         "content": "x", "trusted": True})
        attacker.knowledge_base[0]["content"] = "MUTATED"
        self.assertEqual(len(cls._DEFAULT_KNOWLEDGE_BASE), baseline_len)
        self.assertEqual(
            cls._DEFAULT_KNOWLEDGE_BASE[0]["content"],
            "Calisan izin hakki yilda 20 gundur.",
            "Class constant _DEFAULT_KNOWLEDGE_BASE was mutated by "
            "instance-level attack -- deepcopy missed a level.",
        )


if __name__ == "__main__":
    unittest.main()
