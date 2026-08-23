"""ch08_attacks.py'nin (RAG Poisoning) 15 probunun 8'i gercek bir RAG
altyapisi (vector DB, embedding modeli, chunking algoritmasi, multi-tenant
izolasyon) gerektiriyor -- payload'lari LLM'e "embedding collision olustur",
"chunking algoritmasini exploit et" gibi dogal-dil talimatlar gonderiyor.

llm_scanner.py yalnizca ciplak bir chat-completion endpoint'ine konusuyor,
hicbir gercek altyapiya erisimi yok -- bu yuzden model bu talimatlari
GERCEKTEN yerine getiremez, yalniz yapiyormus gibi konusabilir. Onceki
check_success() duzeltmesinden SONRA bile bu probler anlamli bir
basari/savunma sonucu URETEMEZ: hangi cevabi verirse versin, hicbir gercek
RAG pipeline'i test edilmis olmuyor.

Bu dosya, AttackTechnique'e eklenen requires_infrastructure alaninin
scan() dongusunde gercekten cikarildigini ve risk_score'u SESSIZCE
etkilemeden ayri, gorunur bir sayacta raporlandigini dogrular -- kirpma
sessiz olamaz (bkz. CLAUDE.md "no silent caps").
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import llm_scanner as m  # noqa: E402


def test_ch08_has_exactly_eight_infrastructure_only_probes():
    """Regression guard on the real corpus this fix targets."""
    from attacks.ch08_attacks import CH08_ATTACKS
    infra = [t for t in CH08_ATTACKS if t.requires_infrastructure]
    assert len(infra) == 8
    assert len(CH08_ATTACKS) == 15


def test_scan_never_sends_an_infrastructure_only_probe(monkeypatch):
    """The whole point: an infra-only probe must never reach send_probe --
    there is nothing meaningful to send it to."""
    sent_payloads = []

    def fake_send(ollama_url, model, system_prompt, payload, timeout):
        sent_payloads.append(payload)
        return "some response text that is long enough to matter here", 1

    monkeypatch.setattr(m, "send_probe", fake_send)

    scanner = m.LLMScanner(model="llama3.2:3b")
    report = scanner.scan(categories=["LLM01", "LLM09"])  # ch08's OWASP ids

    from attacks.ch08_attacks import CH08_ATTACKS
    infra_payloads = {t.payload for t in CH08_ATTACKS if t.requires_infrastructure}
    assert not (infra_payloads & set(sent_payloads)), "an infra-only payload was sent to the model"
    assert report.skipped_infrastructure >= 8


def test_skipped_infrastructure_probes_are_reported_not_silently_dropped():
    """A narrower test scope must be visible in the report, not just a
    smaller total_probes with no explanation."""
    scanner = m.LLMScanner(model="llama3.2:3b")
    with patch.object(m, "send_probe", return_value=("defended, sorry I can't help with that", 1)):
        report = scanner.scan(categories=["LLM01", "LLM09"])

    assert report.skipped_infrastructure > 0
    assert "Adversarial Chunking Exploit" in report.skipped_techniques
    assert "Embedding Collision" in report.skipped_techniques


def test_skipped_probes_do_not_appear_in_results_or_risk_score():
    """Excluding infra-only probes must not distort risk_score in either
    direction -- they simply never enter the weighted-score calculation."""
    scanner = m.LLMScanner(model="llama3.2:3b")
    with patch.object(m, "send_probe", return_value=("I cannot help with that, sorry.", 1)):
        report = scanner.scan(categories=["LLM01", "LLM09"])

    result_names = {r.technique_name for r in report.results}
    assert "Embedding Collision" not in result_names
    assert "Cross-Tenant RAG Poisoning" not in result_names
    # total_probes reflects only what was actually sent/scored
    assert report.total_probes == len(report.results)
