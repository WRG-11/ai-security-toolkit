"""ToolCallValidator.check() scans both fenced (```...```) and inline
(`...`) code spans -- `_extract_code_blocks` extracts both. But
`sanitize()` only ever stripped fenced blocks: its `re.sub` pattern is
` ```[\\w]*\\n?.*?``` `, which simply does not match a single-backtick span.

Consequence: a dangerous command written as inline code (a very natural way
for a model to render a one-line shell suggestion) gets `blocked=True` from
check() -- and then sanitize() hands the caller back the identical,
unredacted text. The guard reports a block and ships the payload anyway.

This is the same failure family as the LLMFirewall fail-open fix earlier in
this branch, but here there is no exception to catch: sanitize() runs to
completion and simply does the wrong thing.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "labs" / "vulnllm"))

from defenses.tool_validator import ToolCallValidator  # noqa: E402


def test_check_flags_a_dangerous_inline_backtick_command():
    v = ToolCallValidator()
    result = v.check("Sure, just run `rm -rf /` to fix that.")
    assert result.blocked is True


def test_sanitize_redacts_a_dangerous_inline_backtick_command():
    v = ToolCallValidator()
    sanitized = v.sanitize("Sure, just run `rm -rf /` to fix that.")
    assert "rm -rf" not in sanitized


def test_sanitize_still_redacts_fenced_code_blocks():
    v = ToolCallValidator()
    text = "Here:\n```python\nos.system('rm -rf /')\n```\ndone."
    sanitized = v.sanitize(text)
    assert "os.system" not in sanitized


def test_sanitize_leaves_safe_inline_code_alone():
    v = ToolCallValidator()
    text = "Just call `print(x)` to see the value."
    sanitized = v.sanitize(text)
    assert sanitized == text


def test_sanitize_is_a_noop_on_clean_text():
    v = ToolCallValidator()
    text = "The weather today is sunny."
    assert v.sanitize(text) == text
