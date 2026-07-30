"""The HF Space must run the toolkit, not a copy of it.

This file used to measure drift between two implementations. `huggingface-space/`
carried its own regex table, its own scoring code and its own copy of the trained
model, because the Space deploys separately and "cannot import tools/".

Measured 2026-07-29 and again 2026-07-30: the model files were byte-identical but
the rule sets had diverged completely -- 9 rules in the toolkit, 17 in the demo,
**zero shared names**, disagreeing on three of six sample inputs. Someone who
tried the demo and then installed the tool got a different detector.

Measuring that drift was the wrong goal, and the premise behind it was wrong too.
The Space *can* import `tools/`: the package is the installable surface
(`pyproject.toml`: `packages = ["tools"]`) and the trained model ships as package
data, so a `requirements.txt` naming the repo is enough. Verified from a real
wheel by `tests/test_wheel_install.py`.

So the copy is gone, and these tests changed shape with it. What is pinned now is
the *absence of a second implementation* -- because a drift test cannot fire if
someone quietly reintroduces the copy, and these can.
"""
from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_HF_DIR = _ROOT / "huggingface-space"
_HF_APP = _HF_DIR / "app.py"
_HF_REQS = _HF_DIR / "requirements.txt"


def _app_source() -> str:
    return _HF_APP.read_text(encoding="utf-8")


class DemoUsesThePackageTest(unittest.TestCase):
    """The demo imports the detector rather than defining one."""

    def test_app_imports_the_detector_from_the_package(self):
        tree = ast.parse(_app_source())
        imported = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertIn(
            "tools.prompt_injection_detector_ml",
            imported,
            "the demo must import the shipped detector, not reimplement it",
        )

    def test_requirements_name_the_toolkit(self):
        reqs = _HF_REQS.read_text(encoding="utf-8")
        self.assertIn(
            "wrg-ai-security-toolkit",
            reqs,
            "the Space installs the toolkit; without it app.py cannot import tools",
        )
        self.assertIn("gradio", reqs)


class NoSecondImplementationTest(unittest.TestCase):
    """The copies that drifted must not come back.

    Each of these names something that existed and diverged, not a hypothetical.
    A test that only checked the import would stay green while a hand-written
    rule table sat unused beside it, waiting to be wired up again.
    """

    def test_no_rule_table_is_defined_in_the_demo(self):
        tree = ast.parse(_app_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if getattr(target, "id", "") in {"RULES", "PATTERNS"}:
                        self.fail(
                            f"{target.id} is defined in app.py again -- a second rule "
                            "table is what drifted to 17-vs-9 with zero shared names"
                        )

    def test_no_model_copy_ships_with_the_demo(self):
        strays = sorted(p.name for p in _HF_DIR.glob("*.json"))
        self.assertEqual(
            strays, [],
            f"data copies are back in huggingface-space/: {strays}. The trained "
            "model ships as package data; a second copy can drift from it.",
        )

    def test_demo_does_not_reimplement_the_scoring(self):
        """The old app.py carried its own TF-IDF and char-n-gram maths."""
        src = _app_source()
        for marker in ("def _tokenize", "def _ngrams", "class TFIDF", "class CharNgram"):
            self.assertNotIn(
                marker, src,
                f"{marker!r} suggests the scoring is reimplemented in the demo again",
            )


class DemoStaysHonestTest(unittest.TestCase):
    """Numbers on the demo page come from the code, not from someone typing."""

    def test_rule_count_is_derived_not_typed(self):
        src = _app_source()
        self.assertIn(
            "RULE_COUNT = len(_RULES)", src,
            "the rule count must be derived; it was hand-written in three places "
            "before and all three went stale together",
        )
        self.assertIsNone(
            re.search(r"\(\d+ rules\)", src),
            "a literal '(N rules)' is back in app.py -- use RULE_COUNT",
        )

    def test_threshold_is_not_hardcoded(self):
        """The calibration lives in the package; the demo must not restate it."""
        src = _app_source()
        self.assertIn("DEFAULT_THRESHOLD", src)
        self.assertIsNone(
            re.search(r"threshold\s*=\s*0\.\d", src),
            "a literal threshold in the demo would drift from the calibrated one",
        )


if __name__ == "__main__":
    unittest.main()
