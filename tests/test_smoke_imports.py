"""Stdlib-only smoke imports for all top-level tools."""
import importlib
import sys
import unittest
from pathlib import Path

# Tools live at repo root, not under a package. Add repo root to path.
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

# prompt_injection_detector_ml depends on the v0.1 regex detector at
# tools/prompt_injection_detector.py. If that file is absent the ML tool
# cannot be imported.
#
# This used to check labs/vulnllm/prompt_injection_detector.py instead --
# a path that has never existed (the v0.1 detector has always lived under
# tools/) -- so _HAS_V01_DETECTOR was always False and
# test_prompt_injection_detector_ml below was always skipped, never once
# actually run.
_HAS_V01_DETECTOR = (_REPO_ROOT / "tools" / "prompt_injection_detector.py").exists()


class SmokeImports(unittest.TestCase):
    """Verify every tool module imports without side-effect crashes."""

    def test_llm_firewall(self) -> None:
        importlib.import_module("tools.llm_firewall")

    def test_llm_scanner(self) -> None:
        importlib.import_module("tools.llm_scanner")

    @unittest.skipUnless(
        _HAS_V01_DETECTOR,
        "prompt_injection_detector v0.1 not present in labs/vulnllm/",
    )
    def test_prompt_injection_detector_ml(self) -> None:
        importlib.import_module("tools.prompt_injection_detector_ml")


if __name__ == "__main__":
    unittest.main()
