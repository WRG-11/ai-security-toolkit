"""R89-16b AI-W7-03 regression guard — CanarySystem partial-leak FP fix."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Allow `labs.vulnllm.defenses.guards` import from repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from labs.vulnllm.defenses.guards import CanarySystem  # noqa: E402


class AIW703CanaryPartialLeakFP(unittest.TestCase):
    """R89-16b H AI-W7-03: token_parts used to keep a 1-3 char trailing
    chunk (token length 17, chunk size 4 → last chunk 1 char). A 1-char
    fragment matches in almost any English text → ``found_parts >= 3``
    fired on benign output. Defence got turned against itself:
    attacker triggers FP storm → operator disables CanarySystem → real
    prompt-leak detection goes dark. Minimum 4-char-chunk guard fixes."""

    def test_no_fragment_shorter_than_4_chars(self) -> None:
        for _ in range(8):  # repeat to catch RNG edge tokens
            cs = CanarySystem()
            for p in cs.token_parts:
                self.assertGreaterEqual(
                    len(p), 4,
                    f"AI-W7-03: short token fragment {p!r} would FP",
                )

    def test_benign_text_not_blocked(self) -> None:
        cs = CanarySystem()
        for benign in [
            "This is a normal response with no canary leakage at all",
            "Sure, here is the recipe for chocolate chip cookies...",
            "The answer to your question about Python lists is...",
        ]:
            result = cs.check(benign)
            self.assertFalse(
                result.blocked,
                f"AI-W7-03 FP REGRESSION: benign blocked: {benign!r}",
            )

    def test_full_token_leak_still_blocked(self) -> None:
        cs = CanarySystem()
        leaked = f"oops here is the secret {cs.token} sorry"
        result = cs.check(leaked)
        self.assertTrue(result.blocked, "Full-token leak must still block")

    def test_three_of_four_chunks_partial_leak_blocked(self) -> None:
        cs = CanarySystem()
        parts = cs.token_parts
        self.assertGreaterEqual(len(parts), 3)
        # 3 of N chunks present in body → partial-leak alarm fires
        partial = " ".join(parts[:3]) + " some other text"
        result = cs.check(partial)
        self.assertTrue(result.blocked, "3-of-N partial leak must block")


if __name__ == "__main__":
    unittest.main()
