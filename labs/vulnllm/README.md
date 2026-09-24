# VulnLLM Lab

**Intentionally vulnerable LLM application for learning AI security.**

---

## What is this?

VulnLLM is a hands-on lab environment where you practice attacking and defending LLM applications. Think of it as "DVWA for LLMs" — it has intentional vulnerabilities you can exploit, and defense modules you can enable to learn how to protect AI systems.

## Features

### 10 Challenges (4 difficulty levels)
- **EASY:** Basic prompt injection, system prompt extraction
- **MEDIUM:** Encoding bypass, context manipulation
- **HARD:** Multi-step attacks, indirect injection
- **EXPERT:** Chained exploits, defense evasion

### 27 Defense Modules
Counted mechanically from `labs/vulnllm/defenses/` by
[`scripts/readme_stamp.py`](../../scripts/readme_stamp.py)'s
`count_defense_modules()` (concrete guard/filter/detector classes; the
abstract base classes and `DefenseOrchestrator`/`AuditLogger` infrastructure
don't count) — the same number the root README's
[`defense_count`](../../README.md) badge stamps. This file previously said
21; nothing measured that number, and it had drifted six behind. Re-run
`python scripts/readme_stamp.py --check` from the repo root to reproduce.

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
| 11-27 | Additional specialized guards (canary system, multi-turn tracker, sliding-window rate limiter, LLM-as-judge, tool-call validator, embedding classifier, instruction-hierarchy enforcer, response-consistency analyzer, similarity checker, and the per-challenge custom guards in `defenses/custom_guards.py`) | Mixed |

See [`tools/README.md`](../../tools/README.md#3-llm-firewall) for the full
named list of the 22 of these that are also reachable through
`tools/llm_firewall.py`'s config (10 enabled by default, 12 opt-in).

### 193 Attack Techniques
Covering all OWASP LLM Top 10 (2026) categories with real-world attack patterns.

## Quick Start

```bash
# Mock mode (no external dependencies) -- opens the challenge menu
python vulnllm.py

# Run every challenge automatically at a given difficulty (mock mode)
python vulnllm.py --all --auto --difficulty expert

# Single challenge, interactive
python vulnllm.py --challenge 1

# Against a real model instead of the mock backend: any provider
python vulnllm.py --challenge 1 --provider ollama --model <local-model>
python vulnllm.py --all --auto --provider openai --model <model>
python vulnllm.py --all --auto -d expert --provider anthropic --model <model>

# Defense modules demo (exercises each guard individually, then a combined
# orchestrator pipeline of a handful of them together -- not all 27 wired
# into one pipeline at once)
python defense_demo.py
```

Commands checked against `python vulnllm.py --help` and
`python defense_demo.py --help` on 2026-09-23. `--provider` takes `openai`,
`openai-compatible` (with `--base-url`), `ollama`, `anthropic`, `gemini` or
`http`; keys come from the environment (`OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, or `--api-key-env VAR`).

The lab used to offer three model "tiers" (`--ollama --tier t1/t2/t3`). They
named three 2024 models, and each carried a success-rate claim (for example
"82% jailbreak success rate") that nothing in this repository measured. The
tiers are gone and `--tier` now stops with a message. `--ollama --model <m>`
still works for this release, with a deprecation line.

The expert difficulty adds the LLM judge. Point it at a model with
`VULNLLM_JUDGE_MODEL` (plus `VULNLLM_JUDGE_PROVIDER` / `_URL` / `_KEY_ENV`).
Without one, it fails closed and blocks every input, by design.

## Requirements

- Python 3.10+
- **Mock mode:** No additional dependencies
- **Real-model mode:** any model reachable through a provider above, local or hosted

## OWASP Mapping

Matches `tools/llm_scanner.py`'s `OWASP_MAP` (OWASP Top 10 for LLM
Applications 2026 edition) exactly — both are stamped from the same
`owasp_id` values on each challenge class, so they cannot drift apart
silently the way this table and the scanner's mapping did before.

| Challenge | OWASP (2026) | Category | Attack Type |
|-----------|--------------|----------|-------------|
| ch01 Prompt Injection | LLM01 | Prompt Injection | Direct & indirect injection |
| ch02 Sensitive Information Disclosure | LLM02 | Sensitive Information Disclosure | System prompt & PII extraction |
| ch03 Supply Chain Vulnerabilities | LLM04 | Supply Chain | Malicious/typosquatted dependency simulation |
| ch04 Data and Model Poisoning | LLM05 | Data and Model Poisoning | Training/fine-tuning data manipulation |
| ch05 Improper Output Handling | LLM10 | Improper Output Handling | XSS, command injection via LLM output |
| ch06 Excessive Agency | LLM03 | Excessive Agency | Unauthorized tool/action access |
| ch07 System Prompt Leakage | LLM08 | Hidden Context Exposure | System prompt extraction |
| ch08 RAG Poisoning | LLM09 | Vector and Embedding Weaknesses | Knowledge-base poisoning (also LLM01 in the scanner's map, since RAG poisoning is itself a form of injection) |
| ch09 Misinformation | LLM07 | Misinformation | Hallucination exploitation |
| ch10 Unbounded Consumption | LLM06 | Unbounded Consumption | Resource exhaustion |

The 2026 edition reordered and renamed several 2025-edition categories
(e.g. Excessive Agency moved LLM06 → LLM03); this table previously listed 6
of the 10 categories under the old numbering, including a chapter genuinely
absent from it (LLM04 Supply Chain).

## Results

Measured 2026-09-24, mock mode, `python vulnllm.py --all --auto --difficulty <level>`
(193 attacks across all 10 challenges at each level):

| Difficulty | Attacks succeeded | Block rate |
|---|---|---|
| EASY | 148/193 | 23.3% |
| MEDIUM | 32/193 | 83.4% |
| HARD | 5/193 | 97.4% |
| EXPERT | 0/193 | **100%** |

The previous table (2026-09-14: 142, 25, 5 and 0 of 194) went stale when the
attack corpus and the guards' keyword lists became English: re-running the
command on that 194-attack corpus gave 149 and 32 on EASY and MEDIUM. One
probe has left the corpus since; it succeeded on EASY only.

This file previously claimed a flat "99% block rate (194 attacks, 192
blocked)" with no reproducing command and no record of when or how it was
measured. Re-running it produced a different, and more informative, result:
a monotonic difficulty curve rather than one number, fully reproducible with
the command above. Mock-mode numbers measure the challenge/guard logic, not
a real model's behavior. A run against a real model (`--provider`) will
differ by model and prompt.

`defense_demo.py`'s non-interactive run exercises each of the 27 guards
individually (correctness checks, not an attack corpus) plus one combined
`DefenseOrchestrator` pipeline of 5 of them; it is a guard-correctness demo,
not a second measurement of the table above.
