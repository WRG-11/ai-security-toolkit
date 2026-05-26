"""AI-L2-01 regression — llm_firewall INPUT_GUARD_REGISTRY wires
MultiTurnTracker + SlidingWindowRateLimiter.

Pre-fix (R89-26b 2026-05-27):
    Both classes were:
      - Exported from labs/vulnllm/defenses/__init__.py
      - Defined as InputGuard subclasses (multi_turn.py + guards.py)
    BUT absent from tools/llm_firewall.py INPUT_GUARD_REGISTRY.
    Result: any config naming "MultiTurnTracker" or
    "SlidingWindowRateLimiter" silently fell through the
    "[UYARI] Bilinmeyen input guard" branch (line 208) — the guards
    were registered for export but blind to the firewall consumer.

Pattern P11-1 "registered-but-not-wired" — 1st instance in this batch.

Post-fix:
    Both classes added to INPUT_GUARD_REGISTRY (opt-in via config; not
    added to DEFAULT_CONFIG.input_guards to preserve BC and because
    MultiTurnTracker requires session_id context to function correctly,
    handled in AI-L2-02 / R89-26b Fix 4).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


_TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))


class FirewallRegistryWireup(unittest.TestCase):
    """AI-L2-01 closure guard."""

    def setUp(self) -> None:
        import llm_firewall  # noqa: E402
        self.module = llm_firewall

    def test_multi_turn_tracker_in_registry(self) -> None:
        """MultiTurnTracker must be addressable via config string."""
        self.assertIn(
            "MultiTurnTracker",
            self.module.INPUT_GUARD_REGISTRY,
            "P11-1: MultiTurnTracker exported but not wired to consumer "
            "registry — config opt-in falls through 'Bilinmeyen input "
            "guard' fallback.",
        )

    def test_sliding_window_rate_limiter_in_registry(self) -> None:
        """SlidingWindowRateLimiter must be addressable via config string."""
        self.assertIn(
            "SlidingWindowRateLimiter",
            self.module.INPUT_GUARD_REGISTRY,
            "P11-1: SlidingWindowRateLimiter exported but not wired to "
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
        """A config naming these guards must NOT trigger the
        'Bilinmeyen input guard' fallback."""
        from io import StringIO
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
        self.assertNotIn("Bilinmeyen input guard", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
