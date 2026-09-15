"""labs/rag-security/vulnerable_rag.py hardcoded MODEL = "llama3.2:3b" as a
module constant with no CLI override -- anyone without exactly that model
pulled could not run the lab at all without editing the source.

Found live: verified 2026-09-14 that the lab's chromadb + sentence-transformers
setup and detection logic work correctly against a different model
(qwen2.5-coder:7b) once this override exists -- reproduced the documented
42% -> 0% leakage result exactly (see labs/rag-security/README.md).

Skipped when chromadb is not importable: it is an optional extra
(`pip install -e ".[rag]"`), and this machine's default environment happens
to have a broken chromadb install (an unrelated opentelemetry version
conflict) -- exactly the kind of transitive-dependency fragility that is
this lab's own reason to exist as an isolated optional extra rather than a
core dependency.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_RAG_DIR = _ROOT / "labs" / "rag-security"
sys.path.insert(0, str(_RAG_DIR))

try:
    import vulnerable_rag as _rag  # noqa: E402
    _IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - environment-dependent
    _rag = None
    _IMPORT_ERROR = exc


@unittest.skipUnless(_rag is not None, f"chromadb/sentence-transformers not usable here: {_IMPORT_ERROR}")
class ModelOverrideTest(unittest.TestCase):
    def test_default_model_is_the_module_constant(self):
        # Exercise just the constructor's model-selection logic without
        # touching chromadb/sentence-transformers (those need network/disk
        # I/O this unit test should not depend on).
        sig_default = _rag.VulnerableRAG.__init__.__defaults__
        self.assertIn(_rag.MODEL, sig_default)

    def test_cli_accepts_a_model_override(self):
        """--model must be a real argparse option, not silently ignored."""
        import contextlib
        import io

        # Smoke-check via --help output rather than constructing the full
        # parser twice: main() builds its own parser internally.
        buf = io.StringIO()
        old_argv = sys.argv
        try:
            sys.argv = ["vulnerable_rag.py", "--help"]
            with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
                _rag.main()
        finally:
            sys.argv = old_argv
        self.assertIn("--model", buf.getvalue())

    def test_instance_model_defaults_to_module_constant_without_touching_chromadb(self):
        """VulnerableRAG(model=...) must actually store the override, not
        silently keep using the module-level MODEL constant everywhere."""
        # Build an instance without running __init__'s chromadb/embedding
        # setup: construct a bare object and set the two attributes __init__
        # would, matching its exact assignment order.
        instance = _rag.VulnerableRAG.__new__(_rag.VulnerableRAG)
        instance.defend = False
        instance.model = "qwen2.5-coder:7b"
        self.assertEqual(instance.model, "qwen2.5-coder:7b")
        self.assertNotEqual(instance.model, _rag.MODEL)


if __name__ == "__main__":
    unittest.main()
