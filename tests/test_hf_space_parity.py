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
_HF_INDEX = _HF_DIR / "index.html"
_HF_REQS = _HF_DIR / "requirements.txt"
_HF_README = _HF_DIR / "README.md"


def _app_source() -> str:
    return _HF_APP.read_text(encoding="utf-8")


def _index_source() -> str:
    return _HF_INDEX.read_text(encoding="utf-8")


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
            "app.py cannot import tools without it",
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


class DeployedEntryPointTest(unittest.TestCase):
    """index.html is what the Space actually serves, so it needs its own guards.

    The tests above read app.py, which is now the *local* variant. Checking only
    that file would leave the deployed page unguarded -- the same shape of gap as
    the drift these tests replaced.
    """

    def test_readme_frontmatter_declares_a_static_space_pointing_at_index(self):
        """The frontmatter is the Space's configuration; if it lies, HF obeys it.

        It said `sdk: gradio` / `app_file: app.py` while the repo also claimed
        the Space was not deployed. Gradio Spaces are a paid plan now, so a
        Static Space serving index.html is both the free path and the true one.
        """
        head = _HF_README.read_text(encoding="utf-8").split("---")[1]
        self.assertIn("sdk: static", head)
        self.assertIn("app_file: index.html", head)
        self.assertNotIn("sdk: gradio", head)

    def test_index_installs_the_package_from_pypi(self):
        src = _index_source()
        self.assertIn('micropip.install("wrg-ai-security-toolkit")', src)

    def test_index_imports_the_detector_rather_than_defining_one(self):
        src = _index_source()
        self.assertIn("from tools.prompt_injection_detector_ml import", src)
        for marker in ("def _tokenize", "def _ngrams", "RULES = [", "injection_profile"):
            self.assertNotIn(
                marker, src,
                f"{marker!r} suggests scoring is being reimplemented in the page",
            )

    def test_index_derives_the_numbers_it_displays(self):
        """Rule count, threshold and layer weights come off the detector.

        The old demo typed "17 rules" and "30% / 40% / 30%" into its results
        table. Both were wrong, and neither could fail a test.
        """
        src = _index_source()
        self.assertIn("RULE_COUNT = len(_RULES)", src)
        self.assertIn("THRESHOLD = DEFAULT_THRESHOLD", src)
        self.assertIn("WEIGHTS = dict(_detector.weights)", src)
        self.assertIsNone(
            re.search(r"(?:30|40)%\s*/\s*\d+%", src),
            "hardcoded layer weights are back in the page",
        )

    def test_index_does_not_load_gradio_lite(self):
        """Recorded because it was tried and does not work.

        @gradio/lite@5.45.0 cannot boot: micropip fails to resolve
        huggingface-hub, which has no pure-Python wheel. Confirmed as gradio's
        own bootstrap by loading a gradio-lite page with an empty requirements
        list -- identical failure. 5.38.0 fails differently.

        Matches on a `src=`/`href=` that loads it, not on the string anywhere:
        the page *explains* why gradio-lite is absent, and a naive substring
        check failed on that explanation. A guard that forbids naming the thing
        it guards against also forbids documenting it.
        """
        src = _index_source()
        self.assertIsNone(
            re.search(r'(?:src|href)\s*=\s*["\'][^"\']*@gradio/lite', src),
            "index.html is loading gradio-lite again; it cannot boot (see docstring)",
        )
        self.assertNotIn("<gradio-lite", src)


if __name__ == "__main__":
    unittest.main()
