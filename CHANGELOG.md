# Changelog

All notable changes to `ai-security-toolkit` are documented here.

This is a portfolio repository (research + labs + tools + CTF writeups),
not a versioned Python package. Releases are tracked by GitHub commit SHA
rather than semantic versions. This CHANGELOG batches notable additions
and updates by date for readability.

## [2026-05-23]

### Added

- `CONTRIBUTING.md` + this `CHANGELOG.md` -- community files
  (R89-03f portfolio audit closure; sister `instinct` / `wrg-devguard`
  templates adapted).
- README: NEW "Sister WRG-11 packages" section cross-linking the 4 sister
  PyPI packages (instinct-mcp + wrg-devguard + wrg-mcp-server +
  wrg-rule-lab). (R89-03f MED M5.)

### Changed

- `SECURITY.md`: switched vulnerability-reporting channel from operator
  personal email to GitHub Security Advisories
  (`https://github.com/WRG-11/ai-security-toolkit/security/advisories`).
  Closes Pattern 34 personal-PII surface in a public-repo security policy.
  (R89-03f LOW M10.)

## [2026-05-22] -- WRG-11 brand consolidation

- Repository hosted at `WRG-11/ai-security-toolkit` (this repo was created
  directly under the WRG-11 organization; not part of the yakuphanycl ->
  WRG-11 transfer wave that covered `instinct` / `wrg-rule-lab`).

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
