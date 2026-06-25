# Changelog

All notable changes to `ai-security-toolkit` are documented here.

This is a portfolio repository (research + labs + tools + CTF writeups),
not a versioned Python package. Releases are tracked by GitHub commit SHA
rather than semantic versions. This CHANGELOG batches notable additions
and updates by date for readability.

## [2026-06-03] -- CTF writeup hygiene

### Changed

- `ctf-writeups/prompt-airlines/`: scrubbed a personal real name from the
  writeup, replacing it with the `WRG-11` handle, and removed the embedded
  `certificate.png` (which carried the same real name in-image) plus its
  writeup embed. Public-surface privacy cleanup; no tool/lab logic change.
  (`b7537fd` #6, `b5ea550` #7)

## [2026-05-27] -- vulnllm lab defense hardening

### Changed

- `labs/vulnllm/defenses/`: fail-closed and validation hardening across the
  defense modules -- the defense orchestrator and LLM-judge now fail closed,
  the content-policy guard adds input validation, the perplexity guard
  sanitizes common-word inputs, and the firewall registry wiring + multi-turn
  context handling were tightened. (`cb49c2f` #4, `8554bf6` #5)
- `labs/vulnllm/challenges/ch08_rag_poisoning.py`: RAG knowledge-base
  isolation hardening for the RAG-poisoning challenge. (`8554bf6` #5)
- PII-scanner pattern isolation and audit-logger secret redaction added to the
  lab defense set. (`8554bf6` #5)

### Added

- `tools/prompt_injection_detector.py`: standalone prompt-injection detector
  tool. (`cb49c2f` #4)
- Test suites covering the above defense-hardening fixes (orchestrator
  fail-closed, content-policy validation, judge fail-closed, challenge-base,
  PII-scanner isolation, audit-logger redaction, RAG isolation). (`cb49c2f` #4,
  `8554bf6` #5)

## [2026-05-24]

### Changed

- README + `CODE_OF_CONDUCT.md`: documentation accuracy pass -- PII redaction
  and a corrected "zero-dependency" claim. (`606adae`)

## [2026-05-23]

### Added

- `CONTRIBUTING.md` + this `CHANGELOG.md` -- community files
  (portfolio audit closure; sibling-project templates adapted).
- README: NEW section cross-linking sibling WRG-11 projects.

### Changed

- `SECURITY.md`: switched vulnerability-reporting channel from operator
  personal email to GitHub Security Advisories
  (`https://github.com/WRG-11/ai-security-toolkit/security/advisories`).
  Closes Pattern 34 personal-PII surface in a public-repo security policy.

## [2026-05-22] -- WRG-11 brand consolidation

- Repository hosted at `WRG-11/ai-security-toolkit` (this repo was created
  directly under the WRG-11 organization).

## [2026-05-11] -- ASCII Turkish diacritic restoration (Batch 2)

- 3 tools restored to proper TR diacritics (commit `ede9349`).

## Pre-2026-05-23

Initial tool development + lab build-out + CTF writeup collection. See
git log for granular history. Highlights:

- `tools/prompt_injection_detector_ml.py` -- 1000-LOC hybrid ML detector
  (regex + TF-IDF + char n-gram) with 194 attack patterns.
- `tools/llm_scanner.py` -- 743-LOC OWASP LLM Top 10 vulnerability scanner
  with 194 probes.
- `tools/llm_firewall.py` -- 863-LOC 10-guard security middleware with HTTP
  proxy mode.
- `labs/vulnllm/` -- 10 challenges across 4 difficulty levels + 21 defense
  modules + 194 attack techniques.
- `labs/rag-security/` -- 5 attack scenarios (direct extraction, indirect
  injection, context overflow, prompt override, membership inference) with
  ChromaDB + sentence-transformers + Ollama.
- CTF writeups: Gandalf (Lakera) 8/8, Agent ODIN 3/3, Prompt Airlines (Wiz)
  5/5 -- 16/16 total across 3 platforms; novel "Negative Question Bypass"
  technique discovered on Agent ODIN.
- Research: `research/tool-comparison.md` (Garak vs PyRIT vs NeMo Guardrails),
  `research/garak-analysis.md` (vulnerability scan on dolphin-mistral).
