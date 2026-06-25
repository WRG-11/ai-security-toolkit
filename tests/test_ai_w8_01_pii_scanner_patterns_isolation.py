"""AI-W8-01 (P12-2 cluster #3) — PIIScanner.PATTERNS is per-instance.

Pre-fix:
    labs/vulnllm/defenses/guards.py:264-265 invoked
        self.PATTERNS.update(extra_patterns)
    directly on the class-level PATTERNS dict. Any caller passing
    extra_patterns to PIIScanner(...) mutated the dict for EVERY
    subsequent PIIScanner instance across the entire process
    (different users, different threads, different defense pipelines).
    Attacker could poison the pattern set on one path to bypass
    detection on another.

Post-fix:
    self.PATTERNS = dict(self.__class__.PATTERNS)  # instance copy
    if extra_patterns:
        self.PATTERNS.update(extra_patterns)        # update on copy

Pattern P12-2 'class-level mutable default cascade' — 3rd instance in
the four-case graduation cluster (see also test_ai_w7, test_ch_08).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_VULNLLM = Path(__file__).resolve().parents[1] / "labs" / "vulnllm"
if str(_VULNLLM) not in sys.path:
    sys.path.insert(0, str(_VULNLLM))


class PIIScannerPatternsIsolation(unittest.TestCase):
    """AI-W8-01 closure guard."""

    def test_patterns_is_per_instance_dict(self) -> None:
        from defenses.guards import PIIScanner
        a = PIIScanner()
        b = PIIScanner()
        self.assertIsNot(
            a.PATTERNS, b.PATTERNS,
            "P12-2 #3: a.PATTERNS is b.PATTERNS -- class-level dict "
            "shared between instances.",
        )

    def test_extra_patterns_do_not_leak_to_other_instances(self) -> None:
        from defenses.guards import PIIScanner
        attacker = PIIScanner(extra_patterns={
            "evil_pattern": (r"VICTIM_TOKEN", "[REDACTED]"),
        })
        # Other instance instantiated AFTER attacker -- must NOT see
        # the attacker-injected pattern.
        victim = PIIScanner()
        self.assertIn("evil_pattern", attacker.PATTERNS)
        self.assertNotIn(
            "evil_pattern", victim.PATTERNS,
            "P12-2 leak: extra_patterns from attacker PIIScanner "
            "instance bled into victim instance -- class dict "
            "mutation cascade not closed.",
        )

    def test_class_level_patterns_untouched_by_instance_extras(self) -> None:
        """The class-level PATTERNS dict itself must remain pristine."""
        from defenses.guards import PIIScanner
        baseline_keys = set(PIIScanner.PATTERNS.keys())
        _ = PIIScanner(extra_patterns={
            "test_only": (r"ANYTHING", "[X]"),
        })
        post_keys = set(PIIScanner.PATTERNS.keys())
        self.assertEqual(
            baseline_keys, post_keys,
            "Class-level PIIScanner.PATTERNS was mutated by instance "
            "construction -- regression of the original cascade.",
        )

    def test_default_patterns_still_present_in_instances(self) -> None:
        """Sanity: instance copy inherits all class default patterns."""
        from defenses.guards import PIIScanner
        scanner = PIIScanner()
        # Spot-check a few well-known default keys (defined in
        # guards.py class body)
        self.assertIn("ipv4_private", scanner.PATTERNS)
        self.assertIn("iban", scanner.PATTERNS)


if __name__ == "__main__":
    unittest.main()
