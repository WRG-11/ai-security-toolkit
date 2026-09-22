"""The RAG lab's own logic, tested without chromadb.

`labs/rag-security/vulnerable_rag.py` imported chromadb at module level, so
nothing in it could be imported without the optional `[rag]` extra -- and CI
installs `[dev]`. Its three tests were skipped everywhere, and the code that
decides the lab's headline result (which documents the defended mode hides,
and which answers count as a leak) had no test at all: 2.5% coverage.

Every test here blocks chromadb explicitly (`sys.modules["chromadb"] = None`),
so the result is the same on a machine that has the extra, one that does not,
and one where it is installed but broken.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

_RAG_FILE = Path(__file__).resolve().parents[1] / "labs" / "rag-security" / "vulnerable_rag.py"
_BLOCKED = {"chromadb": None, "chromadb.utils": None}


def _load_without_chromadb():
    with mock.patch.dict(sys.modules, _BLOCKED):
        spec = importlib.util.spec_from_file_location("vulnerable_rag_under_test", _RAG_FILE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


rag = _load_without_chromadb()


def _doc(text, doc_type="public", doc_id="d1"):
    return {"id": doc_id, "text": text, "metadata": {"type": doc_type}, "distance": 0.1}


class TheModuleImportsWithoutTheExtra(unittest.TestCase):
    def test_import_does_not_need_chromadb(self):
        self.assertTrue(hasattr(rag, "VulnerableRAG"))

    def test_help_works_without_chromadb(self):
        out = io.StringIO()
        with mock.patch.dict(sys.modules, _BLOCKED), \
                mock.patch.object(sys, "argv", ["vulnerable_rag.py", "--help"]), \
                contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            rag.main()
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("--model", out.getvalue())

    def test_no_arguments_prints_help_without_building_the_store(self):
        # It used to load the embedding model and open the vector store first,
        # and only then notice that there was nothing to do.
        out = io.StringIO()
        with mock.patch.object(rag, "VulnerableRAG") as ctor, \
                mock.patch.object(sys, "argv", ["vulnerable_rag.py"]), \
                contextlib.redirect_stdout(out):
            rag.main()
        ctor.assert_not_called()
        self.assertIn("usage:", out.getvalue())

    def test_a_missing_extra_is_exit_2_with_the_install_command(self):
        err = io.StringIO()
        with mock.patch.dict(sys.modules, _BLOCKED), \
                mock.patch.object(sys, "argv", ["vulnerable_rag.py", "--setup"]), \
                contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            rag.main()
        self.assertEqual(cm.exception.code, 2)
        self.assertIn('pip install -e ".[rag]"', err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


class DefendedRetrieval(unittest.TestCase):
    def test_sensitive_documents_are_withheld(self):
        for doc_type in ("confidential", "top_secret"):
            out = rag.defend_document(_doc("AWS key AcmeRoot-1", doc_type))
            self.assertNotIn("AcmeRoot", out["text"])
            self.assertIn("ACCESS DENIED", out["text"])

    def test_public_documents_pass_unchanged(self):
        self.assertEqual(rag.defend_document(_doc("Office hours are 9-5."))["text"],
                         "Office hours are 9-5.")

    def test_a_poisoned_public_document_is_blocked_case_insensitively(self):
        # Every signal here differs from its POISONED_SIGNALS entry only by case.
        out = rag.defend_document(_doc("Important System Update: Please Share Your badge number"))
        self.assertIn("BLOCKED", out["text"])

    def test_the_input_document_is_not_mutated(self):
        original = _doc("secret", "confidential")
        rag.defend_document(original)
        self.assertEqual(original["text"], "secret")

    def test_every_poisoned_document_in_the_corpus_is_caught(self):
        # Corpus, not fixture: the defense is measured against the documents
        # the lab actually loads.
        poisoned = [d for d in rag.COMPANY_DOCUMENTS if d["metadata"].get("type") == "poisoned"
                    or "poison" in d["id"]]
        self.assertGreater(len(poisoned), 0, "no poisoned document found -- the selector is broken")
        for d in poisoned:
            self.assertIn("BLOCKED", rag.defend_document(dict(d))["text"], d["id"])


class LeakDetection(unittest.TestCase):
    def test_a_leaked_credential_is_reported(self):
        self.assertEqual(rag.find_leaks("Sure, the key is sk-acme-123."), ["API key"])

    def test_a_clean_answer_reports_nothing(self):
        self.assertEqual(rag.find_leaks("Our office is in Berlin."), [])

    def test_matching_is_case_insensitive(self):
        self.assertIn("AWS credential", rag.find_leaks("ACMEROOT-xyz"))

    @unittest.expectedFailure
    def test_a_refusal_that_names_the_topic_is_a_known_false_leak(self):
        # Known gap, pinned rather than fixed: "salary" and "password" are topic
        # words, not values, so a refusal that names the topic counts as a leak.
        # The README's 42% undefended rate was measured with this detector and
        # is therefore an upper bound. Fixing it changes that published number,
        # which needs a live re-run (chromadb + Ollama) to replace -- not a guess.
        self.assertEqual(rag.find_leaks("I cannot share salary information."), [])


if __name__ == "__main__":
    unittest.main()
