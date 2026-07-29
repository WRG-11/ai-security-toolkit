"""Output surviving a console with a narrow encoding.

Measured 2026-07-29 on a Windows cp1254 console:

    python tools/llm_scanner.py --list-probes
    ... ~30 lines ...
    UnicodeEncodeError: 'charmap' codec can't encode character '\\u2192'
    exit 1

A successful informational command died halfway through and reported FAILURE,
over a single "->" arrow inside the data.

The encoding comes from the environment, so the test forces the environment:
PYTHONIOENCODING pins cp1254, which reproduces the condition on Linux CI too --
otherwise this regression would only ever show up on one developer's Windows box.
"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SCANNER = _ROOT / "tools" / "llm_scanner.py"


def _run_with_encoding(args: list[str], encoding: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONIOENCODING=encoding)
    return subprocess.run(
        [sys.executable, str(_SCANNER), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(_ROOT),
    )


class NarrowConsoleTest(unittest.TestCase):
    def test_list_probes_survives_a_cp1254_console(self):
        proc = _run_with_encoding(["--list-probes"], "cp1254")
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr[-400:]}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)

    def test_list_probes_prints_every_probe_not_just_the_ascii_prefix(self):
        """A presence check is not enough: the old code also printed the first ~30 lines.

        What is measured is that the output reaches the count promised in the
        kirilma noktasindan sonrasinin da geldigi.
        """
        proc = _run_with_encoding(["--list-probes"], "cp1254")
        lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("  [")]
        header = proc.stdout.splitlines()[0]
        promised = int("".join(ch for ch in header if ch.isdigit()))
        self.assertEqual(
            len(lines),
            promised,
            f"the header promised {promised} probes, {len(lines)} lines were printed",
        )

    def test_utf8_console_is_unaffected(self):
        """Duzeltme dar kodlamayi kurtarirken genis olani bozmamali."""
        proc = _run_with_encoding(["--list-probes"], "utf-8")
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr[-400:]}")


if __name__ == "__main__":
    unittest.main()
