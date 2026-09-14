"""labs/vulnllm/vulnllm.py and defense_demo.py print a box-drawing ASCII-art
banner and colored labels, but neither called tools/_console.make_output_safe()
the way all three tools/*.py CLIs do (tests/test_console_encoding.py covers
those). Reproduced directly on a narrow console:

    PYTHONIOENCODING=cp1254 python labs/vulnllm/vulnllm.py --all --auto -d expert
    UnicodeEncodeError: 'charmap' codec can't encode characters in position 14-16

The default, no-argument invocation (`python vulnllm.py`, the one
labs/vulnllm/README.md's own Quick Start documents) hits the same crash --
print_menu() prints BANNER first thing.

Same pattern as tests/test_console_encoding.py; forcing PYTHONIOENCODING
reproduces the Windows-console condition on any CI runner.
"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_VULNLLM = _ROOT / "labs" / "vulnllm" / "vulnllm.py"
_DEMO = _ROOT / "labs" / "vulnllm" / "defense_demo.py"


def _run_with_encoding(script: Path, args: list[str], encoding: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONIOENCODING=encoding)
    return subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(script.parent),
    )


class NarrowConsoleTest(unittest.TestCase):
    def test_default_menu_survives_a_cp1254_console(self):
        proc = _run_with_encoding(_VULNLLM, [], "cp1254")
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr[-400:]}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)

    def test_all_auto_expert_survives_a_cp1254_console(self):
        """The exact reproduction: this crashed before make_output_safe()."""
        proc = _run_with_encoding(_VULNLLM, ["--all", "--auto", "-d", "expert"], "cp1254")
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr[-400:]}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)

    def test_defense_demo_survives_a_cp1254_console(self):
        proc = _run_with_encoding(_DEMO, [], "cp1254")
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr[-400:]}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)


if __name__ == "__main__":
    unittest.main()
