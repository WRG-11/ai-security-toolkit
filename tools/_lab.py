"""Find the labs/vulnllm tree, and when it is absent say WHY.

All three tools under ``tools/`` import from the lab tree: the attack corpus
(``attacks.*``) and the guard implementations (``defenses.*``). ``labs/`` is
deliberately not packaged (the reasoning lives in ``pyproject.toml``). Together
that means these tools need a **repository checkout**; they cannot run from
inside a wheel on their own.

That may well be correct -- what was wrong was how it got communicated. Measured
2026-07-29, after ``pip install .`` into a clean venv:

    llm-scanner  --help  -> ModuleNotFoundError: No module named 'attacks'
    llm-firewall --help  -> ModuleNotFoundError: No module named 'defenses'

Even ``--help`` failed, and the only clue the user got was the name of a module
that appears nowhere in their own code. This file replaces that error with a
message that says what happened and what to do.

Why CI could not see it is worth recording too: the workflow only ran
``pip install -e .``. An editable install leaves the clone on disk, so
``_PROJECT_ROOT / "labs"`` always resolves -- the one install path CI exercised
was the path that could not break.
"""
from __future__ import annotations

import sys
from pathlib import Path

_TOOLS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _TOOLS_DIR.parent
_VULNLLM_DIR = _PROJECT_ROOT / "labs" / "vulnllm"


class LabTreeMissing(ImportError):
    """The lab tree was not found -- the tool cannot run without a checkout."""


# The message is deliberately free of diacritics so it survives Windows consoles
# on a narrow code page (the same reasoning behind `_console.make_output_safe`).
_MESSAGE = """\
{tool}: labs/vulnllm/ not found -- expected at: {path}

This tool imports its attack corpus and guard implementations from
labs/vulnllm/. labs/ is deliberately not packaged (see pyproject.toml), so
the tool cannot run from inside a wheel on its own; it needs the repository
checkout on disk.

To fix:
    git clone https://github.com/WRG-11/ai-security-toolkit.git
    cd ai-security-toolkit
    pip install -e .        # editable: the clone stays on disk, labs/ resolves

If you already have a clone, replace the non-editable install with
`pip install -e .`."""


def ensure_lab_on_path(tool: str) -> Path:
    """Add ``labs/vulnllm`` to ``sys.path``, or raise an explanatory error.

    Args:
        tool: Tool name to show in the error message.

    Returns:
        Path to the lab tree.

    Raises:
        LabTreeMissing: When the tree is absent. The message is an instruction
            telling you what to do, not a one-line module name.
    """
    if not _VULNLLM_DIR.is_dir():
        raise LabTreeMissing(_MESSAGE.format(tool=tool, path=_VULNLLM_DIR))

    path = str(_VULNLLM_DIR)
    if path not in sys.path:
        sys.path.insert(0, path)
    return _VULNLLM_DIR


def ensure_lab_or_exit(tool: str) -> Path:
    """``ensure_lab_on_path``, but shaped for the user of a CLI.

    ``ensure_lab_on_path`` is called at module level, i.e. before ``main()``
    runs. An exception raised there cannot be caught, and Python prints it with
    a full traceback: measured 2026-07-29, the explanatory message came out
    *below* ten lines of stack trace. If the first thing the user sees is
    ``Traceback (most recent call last)``, fixing the message is only half the
    job -- a bare traceback says "the tool crashed", when the situation is "the
    tool cannot run under this install layout, install it like so".

    This wrapper prints the message to stderr and stops with ``SystemExit(2)``.
    The 2 is deliberate: 1 is reserved for "the tool ran and found something",
    while this is a configuration error.

    Args:
        tool: Tool name to show in the error message.

    Returns:
        Path to the lab tree.

    Raises:
        SystemExit: Code 2 when the tree is absent.
    """
    try:
        return ensure_lab_on_path(tool)
    except LabTreeMissing as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from None


def lab_is_available() -> bool:
    """Is the tree there? Asking without raising -- for tests and fallback paths."""
    return _VULNLLM_DIR.is_dir()


__all__ = [
    "LabTreeMissing",
    "ensure_lab_on_path",
    "ensure_lab_or_exit",
    "lab_is_available",
]
