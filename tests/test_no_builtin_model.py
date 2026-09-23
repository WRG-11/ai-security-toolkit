"""No model is built into the code: the user names one.

The toolkit used to carry model names as defaults (`llama3.2:3b` in the
scanner, the firewall and the RAG lab; `dolphin-mistral` / `qwen2.5:3b` tier
shortcuts). A default model ties a tool meant for any LLM to one that ages out.

This scans the STRING tokens of the covered files -- docstrings and comments
are left alone, because dated notes like "measured on qwen2.5-coder:7b" are
history, not defaults.

What this does NOT cover: labs/vulnllm/ (its tier table is next).
"""
from __future__ import annotations

import ast
import io
import re
import tokenize
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COVERED = [*sorted((ROOT / "tools").glob("*.py")), ROOT / "labs" / "rag-security" / "vulnerable_rag.py"]
# Model-shaped only: a family name with a version or an Ollama ":tag".
# "phi" alone would also match "phishing".
MODEL_NAME = re.compile(
    r"\b(?:llama|qwen|mistral|gemma|phi|deepseek)-?\d[\w.\-]*(?::[\w.\-]+)?"
    r"|\b(?:llama|qwen|mistral|gemma|phi|deepseek)[\w.\-]*:[\w.\-]+"
    r"|\bdolphin-mistral\b|\bgpt-\d[\w.\-]*|\bclaude-[a-z][\w.\-]*|\bgemini-\d[\w.\-]*",
    re.IGNORECASE)


def model_names_in_code(source: str) -> list[tuple[int, str]]:
    docstring_lines: set[int] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) \
                and ast.get_docstring(node) is not None:
            first = node.body[0]
            docstring_lines.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))
    found = []
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.STRING and tok.start[0] not in docstring_lines:
            for m in MODEL_NAME.finditer(tok.string):
                found.append((tok.start[0], m.group(0)))
    return found


class TheCheckItself(unittest.TestCase):
    def test_a_default_model_string_is_caught(self):
        self.assertTrue(model_names_in_code('MODEL = "llama3.2:3b"\n'))

    def test_other_model_shapes_are_caught(self):
        for s in ('"dolphin-mistral"', '"gpt-4o-mini"', '"claude-opus-4-5"', '"gemini-2.5-flash"', '"qwen2.5:3b"'):
            self.assertTrue(model_names_in_code(f"x = {s}\n"), s)

    def test_ordinary_words_are_not(self):
        self.assertEqual(model_names_in_code('x = "phishing via llama-themed emails"\n'), [])

    def test_a_dated_note_in_a_comment_or_docstring_is_not(self):
        src = '"""Measured on qwen2.5-coder:7b."""\nx = 1  # was llama3.2:3b\n'
        self.assertEqual(model_names_in_code(src), [])


class NoBuiltInModel(unittest.TestCase):
    def test_covered_code_names_no_model(self):
        self.assertGreater(len(COVERED), 5, "the covered-file list is broken")
        offenders = [f"{p.relative_to(ROOT)}:{line}: {name}"
                     for p in COVERED for line, name in model_names_in_code(p.read_text(encoding="utf-8"))]
        self.assertEqual(offenders, [], "\n".join(offenders))


if __name__ == "__main__":
    unittest.main()
