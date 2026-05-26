"""AI-L2-02 regression — llm_firewall threads `context` through the
input/output guard pipeline so per-session guards see real session_id.

Pre-fix (R89-26b 2026-05-27):
    tools/llm_firewall.py:245 invoked guards as ``guard.check(text)``
    without the optional `context` argument. MultiTurnTracker
    (multi_turn.py:67) read ``(context or {}).get('session_id',
    'default')`` -- so EVERY request, regardless of which end-user
    initiated it, was attributed to a single shared 'default' session.
    Result:
      - All users' multi-turn risk pooled together
      - Cumulative-risk escalation triggered by ANY user could block
        OTHER users
      - Audit attribution unusable (every session_id=default)

Pattern P11-1 sub-class 'wired-but-no-data-flow':
    The guard was wired (post-AI-L2-01 fix) and the InputGuard contract
    defined a context parameter -- but the consumer never threaded
    real per-request state in. Wiring without the data flow = blind
    defense control.

Post-fix:
    check_input / check_output / process_request all accept optional
    `context: dict | None`; `guard.check(text, context)` forwards it.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


_TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))


class FirewallContextPiping(unittest.TestCase):
    """AI-L2-02 closure guard."""

    def _build_firewall(self):
        import llm_firewall  # noqa: E402
        cfg = llm_firewall.FirewallConfig(
            input_guards=["MultiTurnTracker"],
            output_guards=[],
        )
        return llm_firewall, llm_firewall.LLMFirewall(cfg)

    def test_check_input_accepts_context_param(self) -> None:
        """check_input(text, context=...) must not raise TypeError."""
        _mod, fw = self._build_firewall()
        # The pre-fix signature was check_input(self, text) -- the call
        # below would TypeError before the fix.
        blocked, results = fw.check_input(
            "hello",
            context={"session_id": "session-A"},
        )
        self.assertIsInstance(blocked, bool)
        self.assertIsInstance(results, list)

    def test_multi_turn_tracker_sees_real_session_id(self) -> None:
        """The session_id from context must reach MultiTurnTracker."""
        _mod, fw = self._build_firewall()
        fw.check_input("hello", context={"session_id": "alice"})
        mtt = fw._input_guards[0]
        self.assertIn("alice", mtt.sessions,
                      "session_id 'alice' did not propagate to "
                      "MultiTurnTracker -- context piping broken.")
        self.assertNotIn(
            "default", mtt.sessions,
            "default-bucket collapse still happens; context piping "
            "must replace the fallback path for real session_ids.",
        )

    def test_distinct_sessions_isolated(self) -> None:
        """Two distinct session_ids must produce two distinct
        SessionState entries (no cross-session pollution)."""
        _mod, fw = self._build_firewall()
        fw.check_input("how are you", context={"session_id": "alice"})
        fw.check_input("what's the time", context={"session_id": "bob"})
        mtt = fw._input_guards[0]
        self.assertIn("alice", mtt.sessions)
        self.assertIn("bob", mtt.sessions)
        # Each session saw exactly 1 turn -- not 2.
        self.assertEqual(mtt.sessions["alice"].turn_count, 1)
        self.assertEqual(mtt.sessions["bob"].turn_count, 1)

    def test_omitting_context_still_works_bc(self) -> None:
        """Backward compatibility: callers that don't pass context
        must still work (falls through to MultiTurnTracker's
        'default' fallback per its own contract)."""
        _mod, fw = self._build_firewall()
        # No context -- legacy callers.
        blocked, results = fw.check_input("hello")
        self.assertIsInstance(blocked, bool)
        mtt = fw._input_guards[0]
        # MultiTurnTracker's own fallback fires.
        self.assertIn("default", mtt.sessions)

    def test_process_request_signature_accepts_context(self) -> None:
        """Public entry point must accept context (proxy/handler will
        extract session_id from headers/cookies)."""
        import inspect
        import llm_firewall
        sig = inspect.signature(llm_firewall.LLMFirewall.process_request)
        self.assertIn("context", sig.parameters,
                      "process_request must expose context parameter "
                      "for per-request session piping.")


if __name__ == "__main__":
    unittest.main()
