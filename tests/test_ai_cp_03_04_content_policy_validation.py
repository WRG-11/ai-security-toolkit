"""AI-CP-03 + AI-CP-04 — ContentPolicyEngine threshold bounds +
malformed-regex non-fatal compile.

Pre-fix:
    defenses/content_policy.py:130-144 ContentPolicyEngine.__init__
      AI-CP-03: any float accepted as threshold (no bounds check).
                threshold=999.0 made every input pass-through.
      AI-CP-04: re.compile() in a list comprehension; any malformed
                regex in any DEFAULT_POLICIES rule aborted the loop
                and prevented ContentPolicyEngine() from constructing
                at all -> the entire defense pipeline failed startup.

Post-fix:
    AI-CP-03: threshold normalized via float(); ValueError if not
              in [0.0, 1.0].
    AI-CP-04: per-pattern try/except re.error; bad patterns logged
              and skipped; other patterns continue to compile.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_VULNLLM = Path(__file__).resolve().parents[1] / "labs" / "vulnllm"
if str(_VULNLLM) not in sys.path:
    sys.path.insert(0, str(_VULNLLM))

from defenses.content_policy import ContentPolicyEngine, PolicyRule  # noqa: E402


class ContentPolicyThresholdValidation(unittest.TestCase):
    """AI-CP-03 closure guard."""

    def test_threshold_above_one_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ContentPolicyEngine(threshold=999.0)

    def test_threshold_below_zero_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ContentPolicyEngine(threshold=-0.5)

    def test_threshold_in_range_accepted(self) -> None:
        eng = ContentPolicyEngine(threshold=0.5)
        self.assertEqual(eng.threshold, 0.5)

    def test_threshold_boundary_zero(self) -> None:
        ContentPolicyEngine(threshold=0.0)  # must not raise

    def test_threshold_boundary_one(self) -> None:
        ContentPolicyEngine(threshold=1.0)  # must not raise

    def test_threshold_non_numeric_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ContentPolicyEngine(threshold="loose")  # type: ignore[arg-type]


class ContentPolicyMalformedRegexNonFatal(unittest.TestCase):
    """AI-CP-04 closure guard."""

    def test_malformed_pattern_does_not_abort_construction(self) -> None:
        """One bad regex must not prevent ContentPolicyEngine startup."""
        good_policy = PolicyRule(
            name="good_rule",
            category="test",
            patterns=[r"\bclassified\b"],
            keywords=[],
            min_keyword_matches=0,
            severity=0.7,
            message="good_rule fired",
        )
        bad_policy = PolicyRule(
            name="bad_rule",
            category="test",
            # ( with no close = malformed
            patterns=[r"(unclosed-group"],
            keywords=[],
            min_keyword_matches=0,
            severity=0.5,
            message="bad_rule fired",
        )
        # Pre-fix: this would raise re.error during __init__.
        eng = ContentPolicyEngine(
            policies=[good_policy, bad_policy],
            threshold=0.5,
        )
        # Engine constructed -- bad policy present but its compiled
        # pattern list is empty (skipped).
        names = {p.name for p, _ in eng._compiled}
        self.assertIn("good_rule", names)
        self.assertIn("bad_rule", names)
        # Good policy compile list non-empty; bad policy compile list empty.
        compiled_by_name = {p.name: c for p, c in eng._compiled}
        self.assertEqual(len(compiled_by_name["good_rule"]), 1)
        self.assertEqual(len(compiled_by_name["bad_rule"]), 0)

    def test_good_policy_continues_to_match_after_bad_neighbor(self) -> None:
        """End-to-end: good rules still fire after a bad rule was
        non-fatally skipped."""
        good_policy = PolicyRule(
            name="exfil",
            category="test",
            patterns=[r"\bAPI_KEY\b"],
            keywords=[],
            min_keyword_matches=0,
            severity=0.9,
            message="exfil fired",
        )
        bad_policy = PolicyRule(
            name="bad_rule2",
            category="test",
            patterns=[r"(unclosed-group"],
            keywords=[],
            min_keyword_matches=0,
            severity=0.5,
            message="bad2 fired",
        )
        eng = ContentPolicyEngine(
            policies=[bad_policy, good_policy],  # bad first
            threshold=0.5,
        )
        result = eng.check("here is the API_KEY for the admin", context=None)
        self.assertTrue(result.blocked,
                        "good policy did not fire after bad-policy skip; "
                        "AI-CP-04 fix may have over-reached")


if __name__ == "__main__":
    unittest.main()
