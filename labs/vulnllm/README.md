# VulnLLM Lab

**Intentionally vulnerable LLM application for learning AI security.**

Bilerek savunmasiz birakilan LLM uygulamasi — OWASP LLM Top 10 saldiri ve savunma egitimi.

---

## What is this? / Bu ne?

VulnLLM is a hands-on lab environment where you practice attacking and defending LLM applications. Think of it as "DVWA for LLMs" — it has intentional vulnerabilities you can exploit, and defense modules you can enable to learn how to protect AI systems.

VulnLLM, LLM uygulamalarina saldiri ve savunma pratiği yapabileceginiz bir lab ortamidir. LLM'ler icin DVWA gibi dusunun.

## Features / Ozellikler

### 10 Challenges (4 difficulty levels)
- **EASY:** Basic prompt injection, system prompt extraction
- **MEDIUM:** Encoding bypass, context manipulation
- **HARD:** Multi-step attacks, indirect injection
- **EXPERT:** Chained exploits, defense evasion

### 21 Defense Modules
| # | Guard | Type |
|---|-------|------|
| 1 | Unicode Normalizer | Input |
| 2 | Prompt Firewall | Input |
| 3 | Language Detector | Input |
| 4 | Perplexity Filter | Input |
| 5 | Prompt Injection Classifier | Input |
| 6 | ML Injection Classifier | Input |
| 7 | PII Scanner | Output |
| 8 | Output Sanitizer | Output |
| 9 | Content Policy Engine | Output |
| 10 | Hallucination Detector | Output |
| 11-21 | Additional specialized guards | Mixed |

### 194 Attack Techniques
Covering all OWASP LLM Top 10 categories with real-world attack patterns.

## Quick Start / Hizli Baslangic

```bash
# Mock mode (no external dependencies)
python vulnllm.py

# With Ollama backend
python vulnllm.py --backend ollama --model llama3

# Defense demo (enable all 21 guards)
python defense_demo.py
```

## Requirements / Gereksinimler

- Python 3.10+
- **Mock mode:** No additional dependencies
- **Ollama mode:** Ollama installed with a model (e.g., `ollama pull llama3`)

## OWASP Mapping

| OWASP | Challenge | Attack Type |
|-------|-----------|-------------|
| LLM01 | Prompt Injection | Direct & indirect injection |
| LLM02 | Data Disclosure | System prompt & PII extraction |
| LLM05 | Output Handling | XSS, command injection via LLM |
| LLM06 | Excessive Agency | Unauthorized tool/action access |
| LLM07 | Prompt Leakage | System prompt extraction |
| LLM09 | Misinformation | Hallucination exploitation |

## Results / Sonuclar

- **Undefended:** Most attacks succeed
- **All guards enabled (EXPERT):** 99% block rate (194 attacks, 192 blocked)
