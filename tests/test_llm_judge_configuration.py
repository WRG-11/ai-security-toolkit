"""The judge's model and endpoint come from the caller or the environment.

`LLMAsJudge` hardcoded `qwen2.5:3b` at `localhost:11434`, and the lab builds it
with no arguments, so a user could not point the judge at another model
without editing the source. It also made the lab's tests depend on the
machine: with Ollama running, `vulnllm.py --all --auto -d expert` spent 296 s
on real judge calls (measured 2026-09-23); with Ollama down it took seconds.
Had `qwen2.5:3b` been installed, the verdicts would have come from a live
model too.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "labs" / "vulnllm"))

from defenses.llm_judge import LLMAsJudge  # noqa: E402

_CLEAN = {k: v for k, v in os.environ.items() if not k.startswith("VULNLLM_JUDGE_")}


class JudgeConfiguration(unittest.TestCase):
    def test_defaults_without_environment(self):
        with mock.patch.dict(os.environ, _CLEAN, clear=True):
            judge = LLMAsJudge()
        self.assertEqual(judge.model, "qwen2.5:3b")
        self.assertEqual(judge.ollama_url, "http://localhost:11434")

    def test_environment_sets_model_and_url(self):
        env = dict(_CLEAN, VULNLLM_JUDGE_MODEL="some-model:8b", VULNLLM_JUDGE_URL="http://127.0.0.1:9/")
        with mock.patch.dict(os.environ, env, clear=True):
            judge = LLMAsJudge()
        self.assertEqual(judge.model, "some-model:8b")
        self.assertEqual(judge.ollama_url, "http://127.0.0.1:9")

    def test_an_explicit_argument_beats_the_environment(self):
        env = dict(_CLEAN, VULNLLM_JUDGE_MODEL="from-env", VULNLLM_JUDGE_URL="http://from-env")
        with mock.patch.dict(os.environ, env, clear=True):
            judge = LLMAsJudge(model="from-arg", ollama_url="http://from-arg")
        self.assertEqual((judge.model, judge.ollama_url), ("from-arg", "http://from-arg"))

    def test_an_unreachable_judge_still_fails_closed(self):
        env = dict(_CLEAN, VULNLLM_JUDGE_URL="http://127.0.0.1:9")
        with mock.patch.dict(os.environ, env, clear=True):
            result = LLMAsJudge(timeout=2).check("hello")
        self.assertTrue(result.blocked)


if __name__ == "__main__":
    unittest.main()
