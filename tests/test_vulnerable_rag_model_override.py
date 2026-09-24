"""The RAG lab generates answers with any LLM, chosen on the command line.

History: `vulnerable_rag.py` first hardcoded MODEL = "llama3.2:3b" with no
override; a `--model` flag was then added, still for Ollama only. Generation
now goes through tools/targets.py (`--provider/--model/--base-url/
--api-key-env`) and there is no default model. `--model` without
`--provider` still means Ollama for one release, with a warning.

No chromadb and no network here: generation is exercised with a fake target
on an instance whose vector store is never built.
"""
from __future__ import annotations

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "labs" / "rag-security"))
sys.path.insert(0, str(_ROOT / "tools"))

import targets  # noqa: E402
import vulnerable_rag as rag  # noqa: E402


class _FakeTarget:
    model = "fake-model"

    def __init__(self):
        self.calls = []

    def send(self, messages, system=None):
        self.calls.append(messages)
        return targets.Reply("an answer")


def _bare(target):
    """A VulnerableRAG without its vector store: only generate() is used."""
    instance = rag.VulnerableRAG.__new__(rag.VulnerableRAG)
    instance.defend = False
    instance.target = target
    return instance


class NoBuiltInModel(unittest.TestCase):
    def test_there_is_no_model_constant(self):
        self.assertFalse(hasattr(rag, "MODEL"))
        self.assertFalse(hasattr(rag, "OLLAMA_URL"))

    def test_help_offers_provider_and_model(self):
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", ["vulnerable_rag.py", "--help"]), \
                contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            rag.main()
        self.assertIn("--provider", buf.getvalue())
        self.assertIn("--model", buf.getvalue())


class Generation(unittest.TestCase):
    def test_generate_sends_the_context_and_question_to_the_target(self):
        target = _FakeTarget()
        answer = _bare(target).generate("What is X?", [{"id": "doc_about", "text": "X is Y."}])
        self.assertEqual(answer, "an answer")
        prompt = target.calls[0][-1]["content"]
        self.assertIn("[Document: doc_about]", prompt)
        self.assertIn("X is Y.", prompt)
        self.assertIn("What is X?", prompt)

    def test_generate_without_a_target_says_what_to_set(self):
        with self.assertRaises(ValueError) as cm:
            _bare(None).generate("q", [])
        self.assertIn("--provider", str(cm.exception))


class CommandLine(unittest.TestCase):
    def _target(self, argv, env=None):
        return rag.target_from_args(rag.build_parser().parse_args(argv), env=env or {})

    def test_provider_and_model(self):
        target, warnings = self._target(["--provider", "openai", "--model", "m"], {"OPENAI_API_KEY": "k"})
        self.assertEqual((target.model, target.base_url), ("m", "https://api.openai.com/v1"))
        self.assertEqual(warnings, [])

    def test_answers_stay_bounded_by_default(self):
        # The old Ollama call capped answers at 256 tokens; keep that bound.
        target, _ = self._target(["--provider", "ollama", "--model", "m"])
        self.assertEqual(target.max_tokens, 256)

    def test_a_bare_model_is_ollama_with_a_warning(self):
        target, warnings = self._target(["--model", "local-model"])
        self.assertEqual((target.model, target.base_url), ("local-model", "http://localhost:11434/v1"))
        self.assertTrue(warnings)

    def test_no_model_means_no_target(self):
        target, _ = self._target(["--setup"])
        self.assertIsNone(target)


if __name__ == "__main__":
    unittest.main()
