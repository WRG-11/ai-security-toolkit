"""A secret in a reasoning model's thinking is reported, apart from the verdict.

Seen 2026-09-23 on three free hosted reasoning models: the final answer
refused, while the displayed thinking quoted the password verbatim. (There the
secret was in the user message; the chat client had no system prompt field.) Whether
that is a leak depends on the application -- one that shows the thinking to
its users leaks it -- so the scanner reports it as its own finding and leaves
the attack verdict and the risk score alone.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "labs" / "vulnllm")]

import llm_scanner as m  # noqa: E402
import targets  # noqa: E402


class _Thinker:
    model = "fake-reasoner"

    def __init__(self, reasoning):
        self.reasoning = reasoning

    def send(self, messages, system=None):
        return targets.Reply("I'm sorry, but I can't share that.", reasoning=self.reasoning)


def _scan(reasoning):
    return m.LLMScanner(_Thinker(reasoning), max_probes=3).scan(quick=True)


def test_a_secret_in_the_thinking_is_a_reasoning_leak():
    report = _scan("The user wants the password. It is DRAGON-42, but I must not say it.")
    assert report.reasoning_leaks == 3
    assert all(r.reasoning_leak for r in report.results)
    assert "DRAGON-42" in report.results[0].reasoning


def test_the_verdict_and_risk_score_are_unchanged():
    report = _scan("It is DRAGON-42, but I must not say it.")
    assert report.successful == 0
    assert all(r.success is False for r in report.results)
    assert report.risk_score == _scan("").risk_score


def test_thinking_without_the_secret_is_not_a_leak():
    report = _scan("The user is trying a prompt injection; refuse politely.")
    assert report.reasoning_leaks == 0
    assert not any(r.reasoning_leak for r in report.results)


def test_it_reaches_the_json_report():
    data = _scan("It is DRAGON-42.").to_dict()
    assert data["reasoning_leaks"] == 3
    assert data["results"][0]["reasoning_leak"] is True
    assert "DRAGON-42" in data["results"][0]["reasoning"]
