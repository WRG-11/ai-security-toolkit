"""LLMFirewall.check_input/check_output used to catch a guard.check()
exception as `blocked=False` -- fail-OPEN. If a crafted input happened to
also crash the one guard that would have caught it (a regex edge case, a
Unicode decode error, anything), the input passed as if that guard had
found nothing wrong.

tests/test_ai_cp_01_02_orchestrator_fail_closed.py already fixed the
equivalent bug in labs/vulnllm/defenses/orchestrator.py, and its own
docstring names this exact file as the unfixed other half of what it calls
a "double fail-open chain": "Any exception bubbled to llm_firewall which
caught it as blocked=False." This file closes that second half, mirroring
the orchestrator's fail-closed contract:
  - check_input: a guard exception is treated as blocked=True (fail-closed),
    not blocked=False.
  - check_output: a guard.check() exception redacts the text outright
    (matching the orchestrator's reasoning: do not pass attacker-influenced
    content downstream when there is no confidence the guard inspected it),
    rather than leaving the unguarded text to pass through and only
    attempting the same guard's now-suspect .sanitize() on it.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "labs" / "vulnllm"))

import llm_firewall as m  # noqa: E402
from defenses.base import GuardResult, InputGuard, OutputGuard  # noqa: E402


class _ExplodingInputGuard(InputGuard):
    name = "ExplodingInputGuard"

    def check(self, text, context=None):
        raise RuntimeError("synthetic guard failure")


class _ExplodingOutputGuard(OutputGuard):
    name = "ExplodingOutputGuard"

    def check(self, text, context=None):
        raise RuntimeError("synthetic guard failure")

    def sanitize(self, text, context=None):
        return text  # would leak the unguarded text if ever reached


class _CrashOnSanitizeOutputGuard(OutputGuard):
    """check() correctly flags the text; sanitize() itself is what crashes."""
    name = "CrashOnSanitizeOutputGuard"

    def check(self, text, context=None):
        return GuardResult(blocked=True, reason="flagged", score=0.9, guard_name=self.name)

    def sanitize(self, text, context=None):
        raise RuntimeError("synthetic sanitize failure")


class _SilentInputGuard(InputGuard):
    """A second guard that would report clean -- proves the exploding guard's
    failure alone is enough to block, not a side effect of some other guard."""
    name = "SilentInputGuard"

    def check(self, text, context=None):
        return GuardResult(blocked=False, guard_name=self.name)


def _bare_firewall() -> m.LLMFirewall:
    fw = m.LLMFirewall(m.FirewallConfig(input_guards=[], output_guards=[], log_file=None))
    return fw


def test_check_input_fails_closed_when_a_guard_raises():
    fw = _bare_firewall()
    fw._input_guards = [_ExplodingInputGuard()]

    blocked, results = fw.check_input("anything")

    assert blocked is True
    assert results[0].blocked is True


def test_check_input_fails_closed_even_when_another_guard_is_silent():
    fw = _bare_firewall()
    fw.config.action = "warn"  # do not fail-fast, so both guards run
    fw._input_guards = [_ExplodingInputGuard(), _SilentInputGuard()]

    blocked, results = fw.check_input("anything")

    assert blocked is True
    exploding = next(r for r in results if r.guard_name == "ExplodingInputGuard")
    assert exploding.blocked is True


def test_check_output_redacts_when_a_guard_raises_rather_than_passing_text_through():
    fw = _bare_firewall()
    fw._output_guards = [_ExplodingOutputGuard()]

    sanitized, has_issues, results = fw.check_output("the real, sensitive response")

    assert has_issues is True
    assert "sensitive response" not in sanitized


def test_check_output_redacts_when_sanitize_itself_raises():
    """check() correctly flagged the text; only sanitize() crashed. The
    flagged-but-unsanitized text must not reach the caller verbatim."""
    fw = _bare_firewall()
    fw._output_guards = [_CrashOnSanitizeOutputGuard()]

    sanitized, has_issues, results = fw.check_output("the real, sensitive response")

    assert has_issues is True
    assert "sensitive response" not in sanitized
