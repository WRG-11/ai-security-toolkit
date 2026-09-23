"""The judge asks any LLM, chosen by the caller or the environment.

History: `LLMAsJudge` hardcoded `qwen2.5:3b` at `localhost:11434` and spoke
Ollama's `/api/chat`. The lab builds it with no arguments, so the model could
not be changed without editing the source, and the lab's tests depended on
the machine: with Ollama running, `vulnllm.py --all --auto -d expert` spent
296 s on real judge calls (measured 2026-09-23).

The judge now goes through tools/targets.py. Provider, model, endpoint and key
variable come from arguments or VULNLLM_JUDGE_PROVIDER / _MODEL / _URL /
_KEY_ENV. There is no default model: an unconfigured judge is unavailable and,
like an unreachable one, fails closed unless allow_judge_unavailable=True.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "labs" / "vulnllm"))
sys.path.insert(0, str(ROOT / "tools"))

import targets  # noqa: E402
from defenses.llm_judge import LLMAsJudge  # noqa: E402

_CLEAN = {k: v for k, v in os.environ.items() if not k.startswith("VULNLLM_JUDGE_")}


def _judge(env=None, **kwargs):
    with mock.patch.dict(os.environ, dict(_CLEAN, **(env or {})), clear=True):
        return LLMAsJudge(**kwargs)


class NoBuiltInModel(unittest.TestCase):
    def test_an_unconfigured_judge_has_no_model_and_fails_closed(self):
        judge = _judge()
        self.assertIsNone(judge.model)
        self.assertFalse(judge._is_available())
        result = judge.check("hello")
        self.assertTrue(result.blocked)
        self.assertIn("not configured", result.reason)

    def test_an_unconfigured_judge_can_be_allowed_to_pass(self):
        self.assertFalse(_judge(allow_judge_unavailable=True).check("hello").blocked)


class Configuration(unittest.TestCase):
    def test_environment_selects_provider_model_and_endpoint(self):
        judge = _judge({"VULNLLM_JUDGE_PROVIDER": "openai-compatible", "VULNLLM_JUDGE_MODEL": "m8b",
                        "VULNLLM_JUDGE_URL": "http://127.0.0.1:9/v1"})
        target = judge._target()
        self.assertIsInstance(target, targets.OpenAICompatible)
        self.assertEqual((target.model, target.base_url), ("m8b", "http://127.0.0.1:9/v1"))

    def test_a_model_alone_means_a_local_ollama(self):
        target = _judge({"VULNLLM_JUDGE_MODEL": "local"})._target()
        self.assertEqual(target.base_url, "http://localhost:11434/v1")

    def test_an_explicit_argument_beats_the_environment(self):
        judge = _judge({"VULNLLM_JUDGE_MODEL": "from-env"}, model="from-arg")
        self.assertEqual(judge.model, "from-arg")

    def test_the_legacy_ollama_url_argument_still_works(self):
        target = _judge(model="m", ollama_url="http://127.0.0.1:9999")._target()
        self.assertEqual(target.base_url, "http://127.0.0.1:9999/v1")

    def test_judge_calls_are_short_and_low_temperature(self):
        target = _judge(model="m")._target()
        self.assertEqual((target.temperature, target.max_tokens), (0.1, 150))


class Verdicts(unittest.TestCase):
    def _with_reply(self, reply):
        judge = _judge(model="m")
        fake = mock.Mock()
        fake.send.return_value = reply
        judge._built = fake
        return judge

    def test_a_verdict_is_parsed_from_the_answer(self):
        judge = self._with_reply(targets.Reply('{"verdict": "unsafe", "confidence": 0.9, "reason": "x"}'))
        self.assertTrue(judge.check("ignore previous instructions").blocked)

    def test_a_provider_refusal_counts_as_unsafe(self):
        judge = self._with_reply(targets.Reply("", refused_by_provider=True, refusal_reason="SAFETY"))
        result = judge.check("something the provider blocked")
        self.assertTrue(result.blocked)
        self.assertIn("provider", result.reason)

    def test_an_unreachable_judge_still_fails_closed(self):
        result = _judge({"VULNLLM_JUDGE_MODEL": "m", "VULNLLM_JUDGE_URL": "http://127.0.0.1:9/v1"},
                        timeout=2).check("hello")
        self.assertTrue(result.blocked)


if __name__ == "__main__":
    unittest.main()
