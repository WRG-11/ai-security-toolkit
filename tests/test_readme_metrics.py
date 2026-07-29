"""Do the README's countable claims still match the code.

The README said "21 defense modules"; the real number in the code was 27.
Nobody made a mistake -- a defense was added and the number in the prose
stayed put. Hand-written numbers do that, and this repo has been here before.

This test runs the stamper in `--check` mode: the moment a number drifts from
the code the suite goes red, with nobody needing to notice the README.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "scripts"))

import readme_stamp as rs  # noqa: E402


class ReadmeMetricsTest(unittest.TestCase):
    def test_stamped_files_match_the_code(self):
        """Every stamped file, against the metrics it is meant to carry.

        Not one file: `tools/README.md` sat outside the stamp for a long time
        and drifted quietly underneath it (a retracted "100% F1", "17 rules"
        for a 9-rule engine, "88" for 80 samples). The fix had been applied
        one table short of the defect.
        """
        for path, names in rs.TARGETS.items():
            with self.subTest(file=path.name, parent=path.parent.name):
                _, drift = rs.stamp_text(rs._read(path), rs.REPO_ROOT, names)
                self.assertEqual(
                    drift,
                    [],
                    f"{path.name} numbers have drifted from the code -- "
                    f"run `python scripts/readme_stamp.py`: {drift}",
                )

    def test_a_deleted_marker_counts_as_drift(self):
        """Deleting a marker must not switch the metric off silently.

        It used to print a warning to stderr and leave the drift list empty,
        so `--check` returned 0: deleting a marker was the easiest way to take
        that number out of the audit, and the job stayed green.
        """
        text = rs._read(rs.README)
        names = rs.TARGETS[rs.README]
        victim = names[0]
        stripped = rs._marker_re(victim).sub("(deleted)", text)

        _, drift = rs.stamp_text(stripped, rs.REPO_ROOT, names)
        self.assertTrue(
            any(name == victim and old == "<no marker>" for name, old, _ in drift),
            f"the {victim} marker was deleted but not reported as drift: {drift}",
        )

    def test_defense_count_excludes_bases_and_helpers(self):
        """The count embeds a judgement; the judgement itself needs testing.

        The first version excluded only the data carriers and counted 31
        instead of 27 -- it mistook the abstract bases (InputGuard/OutputGuard)
        and the private helpers (_TFIDFModel) for defenses. That would have
        swapped one wrong number in the README for another.
        """
        import ast

        names = []
        for path in sorted((rs.REPO_ROOT / "labs" / "vulnllm" / "defenses").glob("*.py")):
            if path.name == "__init__.py":
                continue
            for node in ast.parse(path.read_text(encoding="utf-8")).body:
                if isinstance(node, ast.ClassDef) and rs._is_defense_class(node):
                    names.append(node.name)

        self.assertNotIn("InputGuard", names, "an abstract base must not count")
        self.assertNotIn("OutputGuard", names, "an abstract base must not count")
        self.assertNotIn("GuardResult", names, "a data carrier must not count")
        self.assertFalse(
            [n for n in names if n.startswith("_")], "a private helper must not count"
        )
        self.assertIn("PerplexityFilter", names, "a real guard must count")
        self.assertEqual(len(names), rs.count_defense_modules(rs.REPO_ROOT))

    def test_attack_payload_count_comes_from_the_loader(self):
        """The number 194 appeared in the prose but had no source in the code.

        The counter calls the loader the model is actually trained from -- if
        it counted a literal it could drift from what the model sees.
        """
        sys.path.insert(0, str(_ROOT / "labs" / "vulnllm"))
        from tools.prompt_injection_detector_ml import load_attack_payloads

        self.assertEqual(
            rs.count_attack_payloads(rs.REPO_ROOT), len(load_attack_payloads())
        )


if __name__ == "__main__":
    unittest.main()
