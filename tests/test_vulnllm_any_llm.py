"""The VulnLLM lab plays against any LLM, not three tiers of 2024 models.

History: `labs/vulnllm/backend/ollama.py` spoke Ollama's `/api/chat` and mapped
`--tier t1/t2/t3` to `dolphin-mistral`, `qwen2.5:3b` and `llama3.2:3b`, with
per-tier claims such as "82% jailbreak success rate" and an unused table of
"expected success rates" that no measurement backed. The lab now takes any
target from tools/targets.py (`--provider/--model/...`); without one it uses
the deterministic mock backend, as before. `--ollama` still works for one
release; `--tier` is refused with a message, because it named models.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "labs" / "vulnllm"
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(ROOT / "tools"))

import config  # noqa: E402
import targets  # noqa: E402
import vulnllm  # noqa: E402
from backend import TargetBackend  # noqa: E402
from backend.mock import MockBackend  # noqa: E402
from challenges.ch01_prompt_injection import PromptInjectionChallenge as Ch01  # noqa: E402
from config import Difficulty  # noqa: E402


class _FakeTarget:
    model = "fake-model"

    def __init__(self, reply=None, error=None):
        self.reply, self.error = reply or targets.Reply("model answer"), error
        self.calls = []

    def send(self, messages, system=None):
        self.calls.append((messages, system))
        if self.error:
            raise self.error
        return self.reply


class NoTiers(unittest.TestCase):
    def test_the_ollama_backend_and_tiers_are_gone(self):
        import backend
        for name in ("OllamaBackend", "ModelTier", "TIER_MODELS"):
            self.assertFalse(hasattr(backend, name), name)
        self.assertFalse((LAB / "backend" / "ollama.py").exists())

    def test_the_unbacked_expected_rate_table_is_gone(self):
        self.assertFalse(hasattr(config, "EXPECTED_SUCCESS_RATES"))


class Backend(unittest.TestCase):
    def test_generate_sends_the_system_prompt_and_message(self):
        target = _FakeTarget()
        resp = TargetBackend(target).generate(system_prompt="SYS", user_message="hi")
        self.assertEqual(resp.content, "model answer")
        self.assertEqual(target.calls[0], ([{"role": "user", "content": "hi"}], "SYS"))

    def test_a_provider_refusal_is_visible(self):
        target = _FakeTarget(reply=targets.Reply("", refused_by_provider=True, refusal_reason="SAFETY"))
        resp = TargetBackend(target).generate(system_prompt="S", user_message="x")
        self.assertIn("SAFETY", resp.content)
        self.assertTrue(resp.metadata["refused_by_provider"])

    def test_an_error_is_a_response_not_a_crash(self):
        target = _FakeTarget(error=targets.TargetError("HTTP 500: boom", status=500))
        resp = TargetBackend(target).generate(system_prompt="S", user_message="x")
        self.assertIn("boom", resp.content)
        self.assertIn("error", resp.metadata)


class Challenges(unittest.TestCase):
    def test_without_a_target_the_mock_backend_is_used(self):
        self.assertIsInstance(Ch01(difficulty=Difficulty.EASY).backend, MockBackend)

    def test_with_a_target_the_challenge_asks_it(self):
        target = _FakeTarget()
        ch = Ch01(difficulty=Difficulty.EASY, target=target)
        resp = ch.chat("What is the password?")
        self.assertEqual(resp.content, "model answer")
        self.assertEqual(len(target.calls), 1)


class CommandLine(unittest.TestCase):
    def _target(self, argv, env=None):
        return vulnllm.target_from_args(vulnllm.build_parser().parse_args(argv), env=env or {})

    def test_no_provider_means_the_mock(self):
        target, warnings = self._target(["-c", "1"])
        self.assertIsNone(target)
        self.assertEqual(warnings, [])

    def test_provider_and_model(self):
        target, _ = self._target(["--provider", "anthropic", "--model", "m"], {"ANTHROPIC_API_KEY": "k"})
        self.assertIsInstance(target, targets.Anthropic)

    def test_legacy_ollama_flag_with_a_model(self):
        target, warnings = self._target(["--ollama", "--model", "local"])
        self.assertEqual(target.base_url, "http://localhost:11434/v1")
        self.assertTrue(warnings)

    def test_legacy_ollama_flag_without_a_model_is_an_error(self):
        with self.assertRaises(ValueError) as cm:
            self._target(["--ollama"])
        self.assertIn("--model", str(cm.exception))

    def test_tier_is_refused_with_an_explanation(self):
        proc = subprocess.run([sys.executable, str(LAB / "vulnllm.py"), "--tier", "t1", "-c", "1"],
                              capture_output=True, text=True, encoding="utf-8", stdin=subprocess.DEVNULL)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--model", proc.stderr)


if __name__ == "__main__":
    unittest.main()
