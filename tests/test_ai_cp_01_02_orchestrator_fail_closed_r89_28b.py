"""AI-CP-01 + AI-CP-02 — DefenseOrchestrator guard/sanitize/audit
failures NO LONGER crash the pipeline; guards fail-closed, audit
is non-fatal.

Pre-fix (R89-28b 2026-05-27):
    labs/vulnllm/defenses/orchestrator.py:33,62,70 invoked:
        result = guard.check(text)        # raise -> orchestrator crashes
        self.logger.log(...)              # raise -> orchestrator crashes
        result = guard.sanitize(text)     # raise -> orchestrator crashes
    Any exception bubbled to llm_firewall (Wave 11 AI-L2-03) which
    caught it as blocked=False -- double fail-open chain.

Post-fix:
    - guard.check() wrapped: exception -> blocked=True synthetic
      GuardResult (FAIL-CLOSED input; REDACT output).
    - guard.sanitize() wrapped: exception -> [RESPONSE_REDACTED_*]
      fallback (no attacker payload leaks to user verbatim).
    - logger.log() routed through _safe_audit_log() which catches
      and logs a warning (non-fatal; audit gap acceptable, pipeline
      interruption is not).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_VULNLLM = Path(__file__).resolve().parents[1] / "labs" / "vulnllm"
if str(_VULNLLM) not in sys.path:
    sys.path.insert(0, str(_VULNLLM))

from defenses.base import GuardResult, InputGuard, OutputGuard  # noqa: E402
from defenses.orchestrator import DefenseOrchestrator  # noqa: E402


class _ExplodingInputGuard(InputGuard):
    name = "ExplodingInputGuard"

    def check(self, text, context=None):
        raise RuntimeError("synthetic guard failure")


class _ExplodingOutputGuard(OutputGuard):
    name = "ExplodingOutputGuard"

    def check(self, text, context=None):
        raise ValueError("synthetic output guard failure")

    def sanitize(self, text, context=None):
        # Should not even be reached because check() failed first;
        # but if it were, also exploding.
        raise RuntimeError("synthetic sanitize failure")


class _ExplodingSanitizeGuard(OutputGuard):
    """Check fires (blocked=True) but sanitize crashes."""
    name = "ExplodingSanitizeGuard"

    def check(self, text, context=None):
        return GuardResult(blocked=True, reason="forced", score=1.0,
                            guard_name=self.name)

    def sanitize(self, text, context=None):
        raise IndexError("synthetic sanitize crash")


class _PassthroughInputGuard(InputGuard):
    name = "PassthroughInputGuard"

    def check(self, text, context=None):
        return GuardResult(blocked=False, score=0.1, guard_name=self.name)


class OrchestratorFailClosedFailNonFatal(unittest.TestCase):
    """AI-CP-01 + AI-CP-02 closure guard."""

    def test_input_guard_exception_does_not_crash_orchestrator(self) -> None:
        orch = DefenseOrchestrator()
        orch.add_input_guard(_ExplodingInputGuard())
        # No raise -- the pre-fix path raised RuntimeError here.
        result = orch.check_input("hello")
        self.assertTrue(
            result.blocked,
            "AI-CP-01: guard exception must fail-CLOSED (block), not crash.",
        )
        self.assertIn("internal error", result.reason.lower())

    def test_input_guard_exception_fails_closed_not_fails_open(self) -> None:
        """The key fix: exception -> blocked=True (CLOSED), NOT
        blocked=False (OPEN double-fail-open chain pre-fix)."""
        orch = DefenseOrchestrator()
        orch.add_input_guard(_ExplodingInputGuard())
        result = orch.check_input("attacker payload")
        self.assertTrue(result.blocked)
        # Score should be high (fail-closed = high suspicion)
        self.assertGreaterEqual(result.score, 0.9)

    def test_output_guard_exception_does_not_crash(self) -> None:
        orch = DefenseOrchestrator()
        orch.add_output_guard(_ExplodingOutputGuard())
        sanitized, result = orch.check_output("response from llm")
        self.assertTrue(result.blocked)
        # Attacker-influenced content must NOT leak verbatim.
        self.assertNotEqual(sanitized, "response from llm")
        self.assertIn("REDACTED", sanitized)

    def test_sanitize_exception_falls_back_to_redaction(self) -> None:
        """check() returned blocked=True; sanitize() then crashes ->
        redaction marker, not attacker text."""
        orch = DefenseOrchestrator()
        orch.add_output_guard(_ExplodingSanitizeGuard())
        sanitized, _ = orch.check_output("payload-with-secret")
        self.assertNotIn("payload-with-secret", sanitized)
        self.assertIn("REDACTED", sanitized)

    def test_audit_log_failure_is_non_fatal(self) -> None:
        """AI-CP-02: an exploding AuditLogger must NOT crash the
        check_input pipeline."""
        orch = DefenseOrchestrator()
        orch.add_input_guard(_PassthroughInputGuard())

        # Monkey-patch logger.log to always raise
        def _exploding_log(*a, **kw):
            raise OSError("disk full")

        orch.logger.log = _exploding_log  # type: ignore[method-assign]
        # No crash expected; pipeline completes with non-blocked result.
        result = orch.check_input("hello")
        self.assertFalse(result.blocked)

    def test_passthrough_guards_still_work(self) -> None:
        """Sanity: regression check that the wrapper does not break
        the happy path."""
        orch = DefenseOrchestrator()
        orch.add_input_guard(_PassthroughInputGuard())
        orch.add_input_guard(_PassthroughInputGuard())
        result = orch.check_input("benign text")
        self.assertFalse(result.blocked)


if __name__ == "__main__":
    unittest.main()
