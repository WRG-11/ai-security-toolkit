"""Regression — llm_firewall INPUT_GUARD_REGISTRY wires
MultiTurnTracker + SlidingWindowRateLimiter.

Pre-fix:
    Both classes were:
      - Exported from labs/vulnllm/defenses/__init__.py
      - Defined as InputGuard subclasses (multi_turn.py + guards.py)
    BUT absent from tools/llm_firewall.py INPUT_GUARD_REGISTRY.
    Result: any config naming "MultiTurnTracker" or
    "SlidingWindowRateLimiter" silently fell through the unknown-input-guard
    branch — the guards were registered for export but invisible to the
    firewall that consumes them. (That warning read "[UYARI] Bilinmeyen input
    guard" at the time; it is English now, and the tests below read the literal
    out of the source rather than repeating it here.)

"registered-but-not-wired" pattern.

Post-fix:
    Both classes added to INPUT_GUARD_REGISTRY (opt-in via config; not
    added to DEFAULT_CONFIG.input_guards to preserve BC and because
    MultiTurnTracker requires session_id context to function correctly,
    handled in the context-piping fix — requires session_id context).
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))


class FirewallRegistryWireup(unittest.TestCase):
    """Firewall registry wire-up closure guard."""

    def setUp(self) -> None:
        import llm_firewall  # noqa: E402
        self.module = llm_firewall

    def test_multi_turn_tracker_in_registry(self) -> None:
        """MultiTurnTracker must be addressable via config string."""
        self.assertIn(
            "MultiTurnTracker",
            self.module.INPUT_GUARD_REGISTRY,
            "MultiTurnTracker exported but not wired to consumer "
            "registry — config opt-in falls through 'Bilinmeyen input "
            "guard' fallback.",
        )

    def test_sliding_window_rate_limiter_in_registry(self) -> None:
        """SlidingWindowRateLimiter must be addressable via config string."""
        self.assertIn(
            "SlidingWindowRateLimiter",
            self.module.INPUT_GUARD_REGISTRY,
            "SlidingWindowRateLimiter exported but not wired to "
            "consumer registry.",
        )

    def test_registry_classes_instantiable(self) -> None:
        """Sanity: classes resolved from registry must instantiate."""
        mtt_cls = self.module.INPUT_GUARD_REGISTRY["MultiTurnTracker"]
        rl_cls = self.module.INPUT_GUARD_REGISTRY["SlidingWindowRateLimiter"]

        mtt = mtt_cls()
        rl = rl_cls()
        self.assertEqual(mtt.name, "MultiTurnTracker")
        self.assertEqual(rl.name, "SlidingWindowRateLimiter")

    def test_registry_classes_check_method(self) -> None:
        """Both must expose .check(text, context) per InputGuard contract."""
        for name in ("MultiTurnTracker", "SlidingWindowRateLimiter"):
            cls = self.module.INPUT_GUARD_REGISTRY[name]
            instance = cls()
            self.assertTrue(callable(getattr(instance, "check", None)),
                            f"{name} must implement .check()")

    def test_config_with_new_guards_does_not_warn(self) -> None:
        """A config naming these guards must NOT hit the unknown-guard fallback.

        The sentinel is read from the source rather than written out here. When
        the message was translated Turkish -> English, this assertion kept
        matching on the old Turkish text: it still passed, because a string that
        no longer exists can never appear -- a guard that survives its own
        subject being renamed is not a guard.
        """
        from io import StringIO

        sentinel = self._unknown_guard_sentinel()
        old_stderr = sys.stderr
        sys.stderr = captured = StringIO()
        try:
            cfg = self.module.FirewallConfig(
                input_guards=["MultiTurnTracker", "SlidingWindowRateLimiter"],
                output_guards=[],
            )
            self.module.LLMFirewall(cfg)
        finally:
            sys.stderr = old_stderr
        self.assertNotIn(sentinel, captured.getvalue())

    def test_unknown_guard_still_warns(self) -> None:
        """The positive half: an unknown name must reach the fallback.

        Without this, the assertion above passes on a firewall that never warns
        at all -- including one whose warning was deleted.
        """
        from io import StringIO

        sentinel = self._unknown_guard_sentinel()
        old_stderr = sys.stderr
        sys.stderr = captured = StringIO()
        try:
            cfg = self.module.FirewallConfig(
                input_guards=["NoSuchGuardName"], output_guards=[],
            )
            self.module.LLMFirewall(cfg)
        finally:
            sys.stderr = old_stderr
        self.assertIn(sentinel, captured.getvalue())

    def _unknown_guard_sentinel(self) -> str:
        """The literal the firewall actually prints, taken from its source."""
        src = Path(self.module.__file__).read_text(encoding="utf-8")
        match = re.search(r'print\(f"(\[[A-Z]+\] [^:"{]*input guard)', src)
        self.assertIsNotNone(
            match, "the unknown-input-guard warning was not found in llm_firewall.py",
        )
        return match.group(1)


if __name__ == "__main__":
    unittest.main()
