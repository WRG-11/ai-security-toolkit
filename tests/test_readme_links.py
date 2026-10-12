"""Do the README's links still point at something.

The README is short on purpose: the dependency map, the threshold sweep and
the framework comparison live in `docs/`, and the README links to them. A
link is the only thing holding the two together, so a renamed file or a
reworded heading would leave the README pointing at nothing while every
other test stayed green.

What this checks: every relative link in the root README and in `docs/`
resolves to a file in the repository, every in-page anchor the README uses
names one of its own headings, and every link into the root README from
this repository's other Markdown names a heading that exists.

What it does not check: external URLs, and anchors inside files other than
the root README.
"""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_README = _ROOT / "README.md"
_REPO_URL = "https://github.com/WRG-11/ai-security-toolkit#"
_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
_FENCE = re.compile(r"^```.*?^```", re.S | re.M)
_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*:")


def _prose(path: Path) -> str:
    """The file without its fenced code blocks: a link inside one is sample text."""
    return _FENCE.sub("", path.read_text(encoding="utf-8"))


def _links(path: Path) -> list[str]:
    return _LINK.findall(_prose(path))


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lower-case, punctuation dropped, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    return {_slug(h) for h in re.findall(r"^#{1,6} +(.+?) *$", _prose(path), re.M)}


class ReadmeLinksTest(unittest.TestCase):
    def test_relative_links_in_the_readme_and_docs_resolve(self):
        sources = [_README, *sorted((_ROOT / "docs").glob("*.md"))]
        self.assertGreater(len(sources), 1, "docs/ holds no Markdown, so nothing there was checked")
        checked = 0
        for source in sources:
            for target in _links(source):
                if _SCHEME.match(target) or target.startswith("#"):
                    continue
                checked += 1
                with self.subTest(source=source.name, link=target):
                    self.assertTrue(
                        (source.parent / target.split("#", 1)[0]).exists(),
                        f"{source.name} links to {target}, which does not exist",
                    )
        self.assertGreater(checked, 10, "too few relative links found; the pattern may have stopped matching")

    def test_in_page_anchors_name_a_readme_heading(self):
        have = _anchors(_README)
        used = [t[1:] for t in _links(_README) if t.startswith("#")]
        self.assertTrue(used, "the README no longer links to one of its own headings; update this test")
        for anchor in used:
            with self.subTest(anchor=anchor):
                self.assertIn(anchor, have, f"the README links to #{anchor} but has no such heading")

    def test_links_into_the_readme_name_a_real_heading(self):
        have = _anchors(_README)
        listed = subprocess.run(
            ["git", "ls-files", "*.md"], cwd=_ROOT, capture_output=True, text=True, check=True,
        ).stdout.split()
        found = 0
        for name in listed:
            path = _ROOT / name
            if path == _README:
                continue
            for target in _links(path):
                anchor = None
                if target.startswith(_REPO_URL):
                    anchor = target[len(_REPO_URL):]
                elif "#" in target and not _SCHEME.match(target):
                    rel, fragment = target.split("#", 1)
                    if rel and (path.parent / rel).resolve() == _README.resolve():
                        anchor = fragment
                if anchor is None:
                    continue
                found += 1
                with self.subTest(source=name, anchor=anchor):
                    self.assertIn(anchor, have, f"{name} links to README.md#{anchor}, which is not a heading")
        self.assertGreaterEqual(found, 2, "no link into the README was found; the pattern may have stopped matching")


if __name__ == "__main__":
    unittest.main()
