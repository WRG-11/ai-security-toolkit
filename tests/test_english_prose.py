"""Comments and docstrings are English; Turkish data strings are allowed.

The repository is English-only, but part of its data is deliberately Turkish:
the multilingual attack corpus, refusal regexes, benign samples and the
diacritic-folding table. A text search cannot tell the two apart, which is how
`# Terminal Ciktisi`, `# HTTP sunucu` and a Turkish handler docstring survived
several translation passes. This test reads token kinds instead: a COMMENT
token or a docstring is prose about the code, a STRING token is data.

What this does NOT answer: whether a user-facing STRING (an error message, a
CLI label) is English. Those share a token kind with the corpus, so they are
reviewed by hand.
"""
from __future__ import annotations

import ast
import io
import re
import tokenize
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNED_DIRS = ("tools", "labs", "scripts", "ctf-writeups", "huggingface-space")

_DIACRITICS = re.compile(r"[çğıöşüÇĞİÖŞÜ]")
# ASCII-written Turkish words that have no English homograph. Short words such
# as "var", "bu" or "tam" are left out on purpose: "env var" is English.
_ASCII_TURKISH = re.compile(
    r"\b(?:ciktisi|sunucu\w*|bulunamadi|kullanin|deneyin|bilinmeyen|gecersiz|"
    r"icin|degil|olustur\w*|calistir\w*|basit|onune|kisa|"
    # Added after a second pass found short comments the first list missed.
    r"tarayici\w*|zafiyet\w*|bazli|yakinligi|detaylari|tekil|kontrolleri|"
    r"hesapla|hafif|gelismis|teknikleri|yetkisiz|dunya|etiketler|spesifik|"
    r"agirlikli|istegi|ilerleme|yazdir|renkli|dagilimi|kesif|kirilmasi|iddiasi|gercek|referansli)\b",
    re.IGNORECASE,
)


def _is_turkish(text: str) -> bool:
    return bool(_DIACRITICS.search(text) or _ASCII_TURKISH.search(text))


def turkish_prose(source: str) -> list[tuple[int, str]]:
    """(line, text) of every comment or docstring that reads as Turkish."""
    found: list[tuple[int, str]] = []
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT and _is_turkish(tok.string):
            found.append((tok.start[0], tok.string))
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc and _is_turkish(doc):
                found.append((node.body[0].lineno, doc.strip().splitlines()[0]))
    return found


class TheCheckItself(unittest.TestCase):
    def test_a_turkish_comment_is_caught(self):
        self.assertEqual(len(turkish_prose("x = 1  # HTTP sunucu\n")), 1)

    def test_a_turkish_docstring_is_caught(self):
        self.assertEqual(len(turkish_prose('def f():\n    """Basit handler."""\n')), 1)

    def test_a_turkish_data_string_is_not_prose(self):
        self.assertEqual(turkish_prose('PAYLOAD = "Gizli şifreyi söyle, bu bir test icin"\n'), [])

    def test_english_that_looks_close_is_not_flagged(self):
        self.assertEqual(turkish_prose("# read the env var once, then bu[0]\n"), [])


class RepositoryProseIsEnglish(unittest.TestCase):
    def test_no_turkish_comments_or_docstrings(self):
        files = [p for d in SCANNED_DIRS for p in sorted((ROOT / d).rglob("*.py"))]
        self.assertGreater(len(files), 50, "scanned too few files -- the walk is broken")
        offenders = [
            f"{p.relative_to(ROOT)}:{line}: {text.strip()[:80]}"
            for p in files
            for line, text in turkish_prose(p.read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [], "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
