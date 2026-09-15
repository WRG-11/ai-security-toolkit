"""A third pass over the same "registered but not wired" bug class this
branch already fixed for MultiTurnTracker, SlidingWindowRateLimiter, and
SimilarityChecker: diffing defenses.__all__ against
INPUT_GUARD_REGISTRY | OUTPUT_GUARD_REGISTRY turned up NINE more InputGuard/
OutputGuard subclasses, all confirmed live (used by
labs/vulnllm/challenges/*.py and/or defense_demo.py), all absent from
tools/llm_firewall.py's registries:

  InputGuard:  DangerousActionFilter, EmbeddingClassifier,
               InstructionHierarchyEnforcer, LLMAsJudge
  OutputGuard: AnomalyFilter, CanarySystem, PackageVerifier,
               ResponseConsistencyAnalyzer, ToolCallValidator

Three more exported guards (SecretLeakFilter, SecretPatternFilter,
SecretWordFilter) are deliberately NOT included here: their constructors
require a caller-supplied list (secrets/patterns/blocked_words) with no
sensible default, so a bare `cls()` instantiation via a named-string config
entry cannot work for them -- they are genuinely build-in-code guards, not
a wiring gap. (AuditLogger and DefenseOrchestrator are infrastructure, not
guards, and were never candidates.)

All nine are kept opt-in (not added to DEFAULT_CONFIG) -- LLMAsJudge in
particular makes a real Ollama network call per check(), so a firewall
nobody asked to change should not suddenly start doing that.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "labs" / "vulnllm"))

import llm_firewall as m  # noqa: E402

NEW_INPUT_GUARDS = [
    "DangerousActionFilter",
    "EmbeddingClassifier",
    "InstructionHierarchyEnforcer",
    "LLMAsJudge",
]

NEW_OUTPUT_GUARDS = [
    "AnomalyFilter",
    "CanarySystem",
    "PackageVerifier",
    "ResponseConsistencyAnalyzer",
    "ToolCallValidator",
]


def test_new_input_guards_are_registered():
    for name in NEW_INPUT_GUARDS:
        assert name in m.INPUT_GUARD_REGISTRY, f"{name} missing from INPUT_GUARD_REGISTRY"


def test_new_output_guards_are_registered():
    for name in NEW_OUTPUT_GUARDS:
        assert name in m.OUTPUT_GUARD_REGISTRY, f"{name} missing from OUTPUT_GUARD_REGISTRY"


def test_none_of_the_new_guards_are_enabled_by_default():
    for name in NEW_INPUT_GUARDS:
        assert name not in m.DEFAULT_CONFIG["input_guards"]
    for name in NEW_OUTPUT_GUARDS:
        assert name not in m.DEFAULT_CONFIG["output_guards"]


def test_every_new_guard_builds_cleanly_via_the_config_pipeline():
    """The actual regression: a config naming any of these used to fall
    through the unknown-guard branch and silently build a pipeline without
    it. Build one firewall with all nine opt-in and confirm every guard
    that was asked for is actually present."""
    config = m.FirewallConfig(
        input_guards=list(NEW_INPUT_GUARDS),
        output_guards=list(NEW_OUTPUT_GUARDS),
        log_file=None,
    )
    fw = m.LLMFirewall(config)

    built_input_names = {getattr(g, "name", type(g).__name__) for g in fw._input_guards}
    built_output_names = {getattr(g, "name", type(g).__name__) for g in fw._output_guards}

    for name in NEW_INPUT_GUARDS:
        assert name in built_input_names, f"{name} did not build (would have warned 'Unknown input guard')"
    for name in NEW_OUTPUT_GUARDS:
        assert name in built_output_names, f"{name} did not build (would have warned 'Unknown output guard')"
