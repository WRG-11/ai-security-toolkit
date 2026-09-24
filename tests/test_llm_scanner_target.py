"""The scanner talks to any LLM through tools/targets.py.

History: the probe sender was first hardcoded to Ollama's native `/api/chat`;
an OpenAI-compatible sender was then added next to it behind `--api-mode`.
Both carried built-in assumptions (an Ollama `/api/tags` pre-check, model
names in the help text, tier shortcuts naming three 2024 models). The scanner
now takes a `Target` and has no default model; the old flags still work for
one release and print a deprecation warning.

No network here: a fake Target records what the scanner sends.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import llm_scanner as m  # noqa: E402
import targets as t  # noqa: E402

SCANNER = Path(m.__file__)


class FakeTarget:
    model = "fake-model"

    def __init__(self, replies=None, error_on=None):
        self.calls: list[tuple[list, str | None]] = []
        self.replies = replies or {}
        self.error_on = error_on or {}

    def send(self, messages, system=None):
        self.calls.append((messages, system))
        n = len(self.calls)
        if n in self.error_on:
            raise self.error_on[n]
        return self.replies.get(n, t.Reply("I'm sorry, I can't help with that."))


# ── the scanner itself ───────────────────────────────────────────────────


def test_every_probe_goes_through_the_target_with_the_system_prompt():
    target = FakeTarget()
    report = m.LLMScanner(target, system_prompt="SYS").scan(quick=True)
    assert report.total_probes == len(target.calls) > 0
    messages, system = target.calls[0]
    assert system == "SYS"
    assert len(messages) == 1 and messages[0]["role"] == "user"


def test_the_report_names_the_target_model():
    assert m.LLMScanner(FakeTarget()).scan(quick=True).target_model == "fake-model"


def test_a_provider_refusal_is_a_defended_probe():
    target = FakeTarget(replies={1: t.Reply("", refused_by_provider=True, refusal_reason="SAFETY")})
    report = m.LLMScanner(target).scan(quick=True)
    first = report.results[0]
    assert first.success is False
    assert first.success_reason == "provider_refusal:SAFETY"
    assert report.errors == 0


def test_a_mid_scan_error_is_counted_and_the_scan_continues():
    target = FakeTarget(error_on={2: t.TargetError("HTTP 500: boom", status=500, retryable=False)})
    report = m.LLMScanner(target, retries=0).scan(quick=True)
    assert report.errors == 1
    assert report.results[1].success_reason == "error"
    assert len(target.calls) == report.total_probes


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_a_permanent_error_on_the_first_probe_aborts_the_scan(status):
    # A wrong key or model name would otherwise be printed once per probe.
    target = FakeTarget(error_on={1: t.TargetError(f"HTTP {status}: nope", status=status)})
    with pytest.raises(m.ScanAborted) as exc:
        m.LLMScanner(target, retries=0).scan(quick=True)
    assert str(status) in str(exc.value)
    assert len(target.calls) == 1


def test_max_probes_caps_what_is_sent_and_says_so():
    target = FakeTarget()
    report = m.LLMScanner(target, max_probes=3).scan()
    assert len(target.calls) == 3 == report.total_probes
    assert report.probes_not_sent > 0
    assert report.to_dict()["probes_not_sent"] == report.probes_not_sent


def test_delay_sleeps_between_probes_not_after_the_last():
    target = FakeTarget()
    with mock.patch.object(m.time, "sleep") as sleep:
        m.LLMScanner(target, max_probes=4, delay=1.5).scan()
    assert [c.args[0] for c in sleep.call_args_list] == [1.5, 1.5, 1.5]


# ── command line → target ───────────────────────────────────────────────


def _target(argv, env=None):
    args = m.build_parser().parse_args(argv)
    return m.target_from_args(args, env=env or {})


def test_provider_and_model():
    target, warnings = _target(["--provider", "openai", "--model", "gpt-x"], {"OPENAI_API_KEY": "k"})
    assert isinstance(target, t.OpenAICompatible)
    assert (target.model, target.base_url, target.api_key) == ("gpt-x", "https://api.openai.com/v1", "k")
    assert warnings == []


def test_anthropic_and_gemini():
    a, _ = _target(["--provider", "anthropic", "--model", "c"], {"ANTHROPIC_API_KEY": "k"})
    g, _ = _target(["--provider", "gemini", "--model", "g"], {"GEMINI_API_KEY": "k"})
    assert isinstance(a, t.Anthropic) and isinstance(g, t.Gemini)


def test_max_tokens_reaches_the_target():
    target, _ = _target(["--provider", "ollama", "--model", "m", "--max-tokens", "128"])
    assert target.max_tokens == 128


def test_legacy_positional_model_means_ollama_with_a_warning():
    target, warnings = _target(["some-local-model"])
    assert isinstance(target, t.OpenAICompatible)
    assert target.base_url == "http://localhost:11434/v1"
    assert any("deprecated" in w for w in warnings)


def test_legacy_openai_mode_maps_to_openai_compatible():
    target, warnings = _target(["m", "--api-mode", "openai", "--ollama-url", "https://llm.example.com/v1",
                                "--api-key-env", "K"], {"K": "secret"})
    assert (target.base_url, target.api_key) == ("https://llm.example.com/v1", "secret")
    assert warnings


def test_legacy_ollama_url_gets_the_v1_suffix():
    target, _ = _target(["m", "--ollama-url", "http://127.0.0.1:9999"])
    assert target.base_url == "http://127.0.0.1:9999/v1"


def test_a_literal_api_key_still_works_but_warns():
    target, warnings = _target(["--provider", "openai-compatible", "--model", "m",
                                "--base-url", "https://llm.example.com/v1", "--api-key", "lit"])
    assert target.api_key == "lit"
    assert any("--api-key-env" in w for w in warnings)


def test_no_model_is_an_error():
    with pytest.raises(ValueError):
        _target(["--provider", "openai"], {"OPENAI_API_KEY": "k"})


def test_tier_shortcuts_are_gone():
    # They named three 2024 models; the scanner assumes no model any more.
    with pytest.raises(SystemExit):
        m.build_parser().parse_args(["--tier", "t1"])
    assert not hasattr(m, "TIER_MODELS")


def test_dry_run_sends_nothing_and_reports_the_count():
    proc = subprocess.run([sys.executable, str(SCANNER), "--provider", "ollama", "--model", "any",
                           "--quick", "--dry-run"], capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    assert "would send" in proc.stdout
    assert "any" in proc.stdout


# ── what the report claims (found by dogfooding against free hosted models) ──


def _errors(n):
    return {i: t.TargetError("HTTP 500: boom", status=500) for i in range(1, n + 1)}


def test_errors_do_not_dilute_the_risk_score():
    # Measured on a free hosted model: 12 of 20 probes errored and the score
    # was still divided by 20, so every error made the model look safer.
    target = FakeTarget(error_on={2: t.TargetError("HTTP 500", status=500),
                                  3: t.TargetError("HTTP 500", status=500)},
                        replies={1: t.Reply("The password is DRAGON-42")})
    report = m.LLMScanner(target, retries=0, max_probes=4).scan()
    assert (report.errors, report.measured) == (2, 2)
    weights = {"LOW": 1, "MEDIUM": 2, "HIGH": 4, "CRITICAL": 8}
    w_hit, w_miss = (weights[report.results[i].severity] for i in (0, 3))
    assert report.results[0].success and not report.results[3].success
    assert report.risk_score == int(w_hit / (w_hit + w_miss) * 100)
    assert sum(v["total"] for v in report.by_severity.values()) == 2


def test_nothing_measured_is_not_a_zero_risk():
    report = m.LLMScanner(FakeTarget(error_on=_errors(3)), retries=0, max_probes=3,
                          max_consecutive_errors=10).scan()
    assert report.measured == 0
    assert report.risk_score is None
    assert report.to_dict()["risk_score"] is None


def test_consecutive_errors_stop_the_scan_and_say_so():
    target = FakeTarget(error_on=_errors(50))
    report = m.LLMScanner(target, retries=0, max_consecutive_errors=5).scan()
    assert len(target.calls) == 5
    assert "5 consecutive" in report.stopped_early
    assert report.probes_not_sent > 0


def test_a_success_resets_the_consecutive_error_count():
    errs = {i: t.TargetError("HTTP 500", status=500) for i in (2, 3, 4, 6, 7, 8)}
    report = m.LLMScanner(FakeTarget(error_on=errs), retries=0, max_probes=9,
                          max_consecutive_errors=4).scan()
    assert report.stopped_early == ""
    assert report.total_probes == 9


def test_the_json_report_keeps_the_full_response():
    long_answer = "I cannot help with that. " + "x" * 400
    report = m.LLMScanner(FakeTarget(replies={1: t.Reply(long_answer)}), max_probes=1).scan()
    assert report.to_dict()["results"][0]["response"] == long_answer


def test_temperature_flag_reaches_the_target_and_the_report():
    target, _ = _target(["--provider", "ollama", "--model", "m", "--temperature", "0"])
    assert target.temperature == 0.0
    report = m.LLMScanner(FakeTarget(), max_probes=1).scan()
    assert "temperature" in report.to_dict()
