"""The Python versions the package claims are the ones CI tests.

pyproject's classifiers and the CI test matrix are two hand-kept lists of the
same fact. When a version is added to one and not the other, the package
either claims a version nothing tests, or tests one it does not claim.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def classifier_versions() -> set[str]:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return set(re.findall(r'"Programming Language :: Python :: (3\.\d+)"', text))


def ci_matrix_versions() -> set[str]:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    match = re.search(r"^\s*python-version:\s*\[([^\]]*)\]", text, re.MULTILINE)
    if not match:
        raise AssertionError("no python-version matrix list found in ci.yml")
    return set(re.findall(r"3\.\d+", match.group(1)))


class PythonVersionClaims(unittest.TestCase):
    def test_both_lists_are_read(self):
        # Canary: an empty set on both sides would compare equal and pass.
        self.assertGreaterEqual(len(classifier_versions()), 3)
        self.assertGreaterEqual(len(ci_matrix_versions()), 3)

    def test_classifiers_match_the_ci_matrix(self):
        self.assertEqual(classifier_versions(), ci_matrix_versions())

    def test_requires_python_is_the_lowest_tested_version(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        floor = re.search(r'requires-python\s*=\s*">=(3\.\d+)"', text).group(1)
        lowest = min(ci_matrix_versions(), key=lambda v: int(v.split(".")[1]))
        self.assertEqual(floor, lowest)


if __name__ == "__main__":
    unittest.main()
