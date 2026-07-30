"""The distribution name must stay prefixed.

`ai-security-toolkit` on PyPI belongs to a different author and is the same kind
of thing -- "a red-team AI security framework with adversarial attack modules",
v1.1.2, checked 2026-07-30. Publishing under that name is impossible, and *using*
it in install instructions sends people to somebody else's security tooling.

The prefix is therefore load-bearing, and it is one word in one line. Nothing
else in the repo would notice it being changed back: the imports are `tools.*`,
the console scripts are unprefixed, and the clone directory is unprefixed too.
Hence this test.

It is offline on purpose. Asserting against live PyPI would make the suite fail
when the network is down and would quietly stop checking anything if the other
project were ever deleted -- the point is not "is the name taken today", it is
"do we still ship under our own name".

No `tomllib`: it landed in 3.11 and this package supports 3.10, so importing it
turns the whole module into a collection error on the oldest supported
interpreter. (Measured the hard way -- the first version of this file did
exactly that and only CI's 3.10 job noticed.) Reading the literal line is a
better fit anyway: what this guards is one line of text that someone could edit.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _ROOT / "pyproject.toml"

COLLIDING_NAME = "ai-security-toolkit"
EXPECTED_NAME = "wrg-ai-security-toolkit"

_NAME_LINE = re.compile(r'^name\s*=\s*"([^"]+)"', re.M)


def _distribution_name() -> str:
    """The `name` of the [project] table, read as text.

    Anchored at column zero so it cannot match a `name = ...` nested inside
    another table -- `[project.authors]` has one.
    """
    match = _NAME_LINE.search(_PYPROJECT.read_text(encoding="utf-8"))
    assert match is not None, "no top-level name = \"...\" line in pyproject.toml"
    return match.group(1)


class DistributionNameTest(unittest.TestCase):
    def test_name_is_prefixed(self):
        name = _distribution_name()
        self.assertEqual(
            name, EXPECTED_NAME,
            f"the distribution is named {name!r}; {COLLIDING_NAME!r} on PyPI is a "
            "different author's red-team AI security framework",
        )

    def test_name_is_not_the_colliding_one(self):
        """Stated separately from the equality check above.

        The equality test would also fail on a deliberate future rename, and
        whoever does that rename should have to think specifically about whether
        they are walking into the collision.
        """
        self.assertNotEqual(_distribution_name(), COLLIDING_NAME)


class InstallInstructionsTest(unittest.TestCase):
    """Wherever the README tells someone to install by name, it must be ours."""

    def test_readme_never_says_pip_install_the_colliding_name(self):
        readme = (_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn(
            f"pip install {COLLIDING_NAME}", readme,
            "the README would be sending readers to a different author's package",
        )

    def test_readme_warns_about_the_collision(self):
        readme = (_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            EXPECTED_NAME, readme,
            "the README must name the distribution, since it differs from the "
            "repository name and from the console scripts",
        )


if __name__ == "__main__":
    unittest.main()
