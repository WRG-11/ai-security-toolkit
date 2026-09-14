"""Every OWASP LLM ID quoted anywhere in this repo must name the same
category tools/llm_scanner.py's own OWASP_MAP/OWASP_NAMES does.

Found this session, all from the same root cause: the OWASP Top 10 for LLM
Applications 2026 edition reordered several categories relative to 2025
(Excessive Agency LLM06 -> LLM03, Misinformation LLM09 -> LLM07, etc.).
tools/llm_scanner.py's OWASP_MAP/OWASP_NAMES were remapped; six other
surfaces that quote an OWASP ID were not, and nothing caught the drift
because each surface is free-form prose or a hand-typed list -- there was
no single source of truth being checked against:

  - labs/vulnllm/challenges/ch0X_*.py's hardcoded `owasp_id` class attribute
    (8 of 10 were wrong)
  - tools/README.md's "Coverage" list (4 of 10 rows wrong)
  - labs/vulnllm/README.md's "OWASP Mapping" table (was 6 of 10 rows under
    the OLD numbering entirely, since fully rewritten)
  - huggingface-space/app.py's "OWASP coverage" line
  - labs/rag-security/vulnerable_rag.py's ATTACK_SCENARIOS "owasp" tags
  - labs/vulnllm/defenses/{hallucination_detector,tool_validator}.py's
    module docstrings

This file makes OWASP_MAP/OWASP_NAMES the single source of truth and checks
every other surface against it mechanically, the same way
tests/test_readme_metrics.py checks the README's countable claims against
the code. A future re-remap (or a new challenge added to the wrong chapter)
now fails a test instead of drifting silently again.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "tools"))
sys.path.insert(0, str(_ROOT / "labs" / "vulnllm"))

import llm_scanner as _scanner  # noqa: E402

OWASP_MAP = _scanner.OWASP_MAP
OWASP_NAMES = _scanner.OWASP_NAMES

# One canonical (module, class) pair per chapter, so importing does not
# require walking the whole challenges/ package.
_CHALLENGE_MODULES = {
    "ch01": ("challenges.ch01_prompt_injection", "PromptInjectionChallenge"),
    "ch02": ("challenges.ch02_info_disclosure", "InfoDisclosureChallenge"),
    "ch03": ("challenges.ch03_supply_chain", "SupplyChainChallenge"),
    "ch04": ("challenges.ch04_data_poisoning", "DataPoisoningChallenge"),
    "ch05": ("challenges.ch05_output_handling", "OutputHandlingChallenge"),
    "ch06": ("challenges.ch06_excessive_agency", "ExcessiveAgencyChallenge"),
    "ch07": ("challenges.ch07_prompt_leakage", "PromptLeakageChallenge"),
    "ch08": ("challenges.ch08_rag_poisoning", "RagPoisoningChallenge"),
    "ch09": ("challenges.ch09_misinformation", "MisinformationChallenge"),
    "ch10": ("challenges.ch10_unbounded_consumption", "UnboundedConsumptionChallenge"),
}


def _normalize(name: str) -> str:
    """Lowercase, drop punctuation/whitespace, so wording variants like
    'Sensitive Information Disclosure' vs 'sensitive-information-disclosure'
    compare equal without demanding byte-identical prose everywhere."""
    return re.sub(r"[^a-z]", "", name.lower())


class ChallengeOwaspIdMatchesScannerMap(unittest.TestCase):
    """labs/vulnllm/challenges/ch0X_*.py's owasp_id vs OWASP_MAP."""

    def test_every_challenge_owasp_id_is_in_the_scanners_map(self):
        import importlib

        for ch_id, (module_path, class_name) in _CHALLENGE_MODULES.items():
            with self.subTest(chapter=ch_id):
                module = importlib.import_module(module_path)
                cls = getattr(module, class_name)
                expected = OWASP_MAP[ch_id]
                self.assertIn(
                    cls.owasp_id, expected,
                    f"{class_name}.owasp_id={cls.owasp_id!r} not in "
                    f"OWASP_MAP[{ch_id!r}]={expected!r}",
                )


class ToolsReadmeCoverageListMatchesOwaspNames(unittest.TestCase):
    """tools/README.md's '- LLMxx: Name' Coverage list vs OWASP_NAMES."""

    def test_every_coverage_line_names_the_right_category(self):
        text = (_ROOT / "tools" / "README.md").read_text(encoding="utf-8")
        lines = re.findall(r"^- (LLM\d{2}): (.+)$", text, re.MULTILINE)
        self.assertEqual(
            len(lines), 10,
            f"expected 10 '- LLMxx: Name' Coverage lines in tools/README.md, found {len(lines)}",
        )
        for llm_id, stated_name in lines:
            with self.subTest(llm_id=llm_id):
                expected = OWASP_NAMES[llm_id]
                self.assertIn(
                    _normalize(expected), _normalize(stated_name),
                    f"tools/README.md says {llm_id} is {stated_name!r}; "
                    f"OWASP_NAMES says {expected!r}",
                )


class VulnllmReadmeOwaspTableMatchesOwaspNames(unittest.TestCase):
    """labs/vulnllm/README.md's 'OWASP Mapping' table vs OWASP_NAMES."""

    def test_every_table_row_names_the_right_category(self):
        text = (_ROOT / "labs" / "vulnllm" / "README.md").read_text(encoding="utf-8")
        rows = re.findall(
            r"^\| ch\d{2} [^|]+ \| (LLM\d{2}) \| ([^|]+) \|", text, re.MULTILINE,
        )
        self.assertEqual(
            len(rows), 10,
            f"expected 10 rows in labs/vulnllm/README.md's OWASP Mapping table, found {len(rows)}",
        )
        for llm_id, stated_category in rows:
            with self.subTest(llm_id=llm_id):
                expected = OWASP_NAMES[llm_id]
                self.assertEqual(
                    _normalize(stated_category), _normalize(expected),
                    f"labs/vulnllm/README.md's table says {llm_id} is "
                    f"{stated_category.strip()!r}; OWASP_NAMES says {expected!r}",
                )


class HuggingFaceAppOwaspLineMatchesOwaspNames(unittest.TestCase):
    """huggingface-space/app.py's 'OWASP coverage' line vs OWASP_NAMES."""

    def test_owasp_coverage_line_names_the_right_categories(self):
        text = (_ROOT / "huggingface-space" / "app.py").read_text(encoding="utf-8")
        match = re.search(r"\*\*OWASP coverage:\*\*(.+?)\"\"\"", text, re.DOTALL)
        self.assertIsNotNone(match, "no '**OWASP coverage:**' line found in app.py")
        claim_text = match.group(1)
        ids_mentioned = re.findall(r"LLM\d{2}", claim_text)
        self.assertTrue(ids_mentioned, "no LLM IDs found in the OWASP coverage line")
        for llm_id in ids_mentioned:
            with self.subTest(llm_id=llm_id):
                expected = OWASP_NAMES[llm_id]
                # A prose line may paraphrase or abbreviate the official name
                # ("information disclosure" for "Sensitive Information
                # Disclosure") -- require at least one distinctive word (not
                # a generic one like "and") from the official name to appear,
                # rather than demanding the exact phrase or a specific word.
                words = [w for w in re.split(r"\s+", expected) if len(w) > 3]
                normalized_claim = _normalize(claim_text)
                self.assertTrue(
                    any(_normalize(w) in normalized_claim for w in words),
                    f"app.py's OWASP coverage line mentions {llm_id} but does not "
                    f"name {expected!r} anywhere near it: {claim_text.strip()!r}",
                )


class RagLabScenariosMatchOwaspNames(unittest.TestCase):
    """labs/rag-security/vulnerable_rag.py's ATTACK_SCENARIOS 'owasp' tags."""

    def test_every_scenario_owasp_tag_names_the_right_category(self):
        text = (_ROOT / "labs" / "rag-security" / "vulnerable_rag.py").read_text(encoding="utf-8")
        tags = re.findall(r'"owasp":\s*"(LLM\d{2})\s*-\s*([^"]+)"', text)
        self.assertGreaterEqual(len(tags), 5, "expected at least 5 'owasp' tags in ATTACK_SCENARIOS")
        for llm_id, stated_name in tags:
            with self.subTest(llm_id=llm_id):
                expected = OWASP_NAMES[llm_id]
                words = [w for w in re.split(r"\s+", expected) if len(w) > 3]
                normalized_stated = _normalize(stated_name)
                self.assertTrue(
                    any(_normalize(w) in normalized_stated for w in words),
                    f"vulnerable_rag.py tags a scenario {llm_id} - {stated_name!r}; "
                    f"OWASP_NAMES says {llm_id} is {expected!r}",
                )


class DefenseModuleDocstringsMatchOwaspNames(unittest.TestCase):
    """Module docstrings in labs/vulnllm/defenses/ that name an OWASP ID."""

    def _owasp_refs_in(self, path: Path) -> list[tuple[str, str]]:
        text = path.read_text(encoding="utf-8")
        # Matches "OWASP LLMxx -- Name" and "(LLMxx)" forms; the latter needs
        # the preceding category words captured separately.
        refs = re.findall(r"OWASP (LLM\d{2})\s*[—-]+\s*([A-Za-z ]+)", text)
        return [(llm_id, name.strip()) for llm_id, name in refs]

    def test_hallucination_detector_docstring(self):
        path = _ROOT / "labs" / "vulnllm" / "defenses" / "hallucination_detector.py"
        refs = self._owasp_refs_in(path)
        self.assertTrue(refs, f"no 'OWASP LLMxx -- Name' reference found in {path.name}")
        for llm_id, stated_name in refs:
            expected = OWASP_NAMES[llm_id]
            self.assertEqual(
                _normalize(stated_name), _normalize(expected),
                f"{path.name} says {llm_id} is {stated_name!r}; OWASP_NAMES says {expected!r}",
            )

    def test_tool_validator_docstring(self):
        path = _ROOT / "labs" / "vulnllm" / "defenses" / "tool_validator.py"
        refs = self._owasp_refs_in(path)
        self.assertTrue(refs, f"no 'OWASP LLMxx -- Name' reference found in {path.name}")
        for llm_id, stated_name in refs:
            expected = OWASP_NAMES[llm_id]
            self.assertEqual(
                _normalize(stated_name), _normalize(expected),
                f"{path.name} says {llm_id} is {stated_name!r}; OWASP_NAMES says {expected!r}",
            )
        # Also pin the parenthetical "(LLMxx)" shorthand used inline.
        text = path.read_text(encoding="utf-8")
        inline = re.findall(r"Excessive Agency \((LLM\d{2})\)", text)
        self.assertTrue(inline, f"no '(LLMxx)' shorthand found near 'Excessive Agency' in {path.name}")
        for llm_id in inline:
            self.assertEqual(
                _normalize(OWASP_NAMES[llm_id]), _normalize("Excessive Agency"),
                f"{path.name} calls {llm_id} Excessive Agency; OWASP_NAMES disagrees",
            )


if __name__ == "__main__":
    unittest.main()
