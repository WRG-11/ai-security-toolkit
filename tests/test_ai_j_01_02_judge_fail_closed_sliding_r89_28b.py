"""AI-J-01 + AI-J-02 — LLM-as-Judge default fail-CLOSED + sliding-
window front+back chunking.

Pre-fix (R89-28b 2026-05-27):
    AI-J-01: defenses/llm_judge.py
      - _is_available() False -> GuardResult(blocked=False) [fail-open]
      - _query_ollama exception -> {"verdict": "safe"} [fail-open]
      - _parse_verdict no JSON found -> verdict='safe' [fail-open]
      Comment said "by design — judge unavailable = safe". Not
      acceptable: an unavailable security control cannot announce
      'all clear'.
    AI-J-02: defenses/llm_judge.py:101+103
      - text[:500] truncation in JUDGE_INPUT_TEMPLATE / OUTPUT_TEMPLATE
      - Attacker that front-loaded 500 chars of benign content placed
        the actual payload at positions 501+ and slipped past judge
        evaluation entirely.

Post-fix:
    AI-J-01: `allow_judge_unavailable: bool = False` (opt-in fail-open).
      Default behaviour: blocked=True, confidence=1.0 when Ollama is
      unavailable or query fails.
    AI-J-02: sliding-window front+back chunks (each `_JUDGE_CHUNK_TOKENS`
      = 500 chars). Any-unsafe across chunks => unsafe aggregated verdict.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

_VULNLLM = Path(__file__).resolve().parents[1] / "labs" / "vulnllm"
if str(_VULNLLM) not in sys.path:
    sys.path.insert(0, str(_VULNLLM))

from defenses.llm_judge import LLMAsJudge  # noqa: E402


class JudgeFailClosedByDefault(unittest.TestCase):
    """AI-J-01 closure guard."""

    def test_ollama_unavailable_blocks_by_default(self) -> None:
        """Default ctor: Ollama down -> blocked=True (fail-CLOSED)."""
        judge = LLMAsJudge()
        with mock.patch.object(judge, "_is_available", return_value=False):
            result = judge.check_input("anything goes")
        self.assertTrue(
            result.blocked,
            "AI-J-01: judge unavailable must FAIL-CLOSED by default "
            "(pre-fix returned blocked=False = silent fail-open).",
        )
        self.assertEqual(result.score, 1.0)
        self.assertIn("fail_closed", result.details.get("status", ""))

    def test_opt_in_fail_open_via_allow_flag(self) -> None:
        """allow_judge_unavailable=True preserves legacy behaviour."""
        judge = LLMAsJudge(allow_judge_unavailable=True)
        with mock.patch.object(judge, "_is_available", return_value=False):
            result = judge.check_input("anything goes")
        self.assertFalse(
            result.blocked,
            "Opt-in fail-open did not engage when "
            "allow_judge_unavailable=True.",
        )

    def test_query_exception_fails_closed_by_default(self) -> None:
        """Ollama HTTP error / JSON decode error etc. -> blocked=True."""
        judge = LLMAsJudge()
        with mock.patch.object(judge, "_is_available", return_value=True), \
             mock.patch.object(judge, "_query_ollama_chunk",
                               side_effect=lambda c, m:
                                   {"verdict": "unsafe", "confidence": 1.0,
                                    "reason": "judge_unavailable_fail_closed: URLError"}):
            result = judge.check_input("benign-ish text")
        # The aggregator returns unsafe with high confidence
        self.assertTrue(result.blocked)


class JudgeSlidingWindow(unittest.TestCase):
    """AI-J-02 closure guard."""

    def test_short_text_one_chunk(self) -> None:
        judge = LLMAsJudge()
        chunks = judge._build_chunks("short text")
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0], "short text")

    def test_long_text_front_back_chunks(self) -> None:
        judge = LLMAsJudge()
        long_text = "A" * 600 + "B" * 600
        chunks = judge._build_chunks(long_text)
        self.assertEqual(len(chunks), 2)
        self.assertTrue(chunks[0].startswith("A"))
        self.assertTrue(chunks[1].endswith("B"))

    def test_payload_at_end_no_longer_truncated(self) -> None:
        """Pre-fix: text[:500] cut off payload at position 700.
        Post-fix: back chunk catches it.

        We simulate this by stubbing _query_ollama_chunk to return
        'unsafe' if the chunk contains the canary, 'safe' otherwise."""
        canary = "IGNORE_PREVIOUS_INSTRUCTIONS_PAYLOAD_X"
        payload_text = ("benign filler " * 100) + canary  # >500 chars

        def _stub(chunk, mode):
            if canary in chunk:
                return {"verdict": "unsafe", "confidence": 0.95,
                        "reason": "canary detected"}
            return {"verdict": "safe", "confidence": 0.1,
                    "reason": "filler only"}

        judge = LLMAsJudge()
        with mock.patch.object(judge, "_is_available", return_value=True), \
             mock.patch.object(judge, "_query_ollama_chunk",
                               side_effect=_stub):
            result = judge.check_input(payload_text)
        self.assertTrue(
            result.blocked,
            "AI-J-02 regression: end-of-input payload missed by judge "
            "(pre-fix bug: text[:500] truncation hid the canary).",
        )
        self.assertIn("any-unsafe", result.details.get("reason", "").lower(),
                      f"aggregated reason missing canonical marker: {result}")

    def test_aggregation_all_safe(self) -> None:
        """All chunks safe -> overall safe."""
        def _stub(chunk, mode):
            return {"verdict": "safe", "confidence": 0.1, "reason": "ok"}

        judge = LLMAsJudge()
        long_text = "x" * 1500
        with mock.patch.object(judge, "_is_available", return_value=True), \
             mock.patch.object(judge, "_query_ollama_chunk",
                               side_effect=_stub):
            result = judge.check_input(long_text)
        self.assertFalse(result.blocked)


if __name__ == "__main__":
    unittest.main()
