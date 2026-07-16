# Changelog

All notable changes to `ai-security-toolkit` are documented here.

This is a portfolio repository (research + labs + tools + CTF writeups),
not a versioned Python package. Releases are tracked by GitHub commit SHA
rather than semantic versions. This CHANGELOG batches notable additions
and updates by date for readability.

## [2026-07-08] -- CI hardening + publish-prep cleanup

### Changed

- Removed `research/tool-comparison.md` and `research/garak-analysis.md`
  from publish scope (OPSEC redaction pass); the README "Research" section
  linking to them was updated to match. (`16fd893` #9)
- Sister-projects section: replaced 4 dead-PyPI package links with the
  live public GitHub repos (`mcp-objauthz-lab`, `osint-trust-envelope`,
  `wrg-sigma-rules`, `devguard-scan`). (`16fd893` #9)
- RAG Security Lab leakage-rate claim scoped to "on included attack
  scenarios" (README.md + `labs/rag-security/README.md`). (`16fd893` #9)
- `tests/`: genericized an internal pattern-catalog version tag flagged by
  the OPSEC content-audit scanner. (`9cf2f09` #14)

### Added

- CI: coverage measurement wired into the `test` job (`.coveragerc` +
  `coverage run` + `coverage report`). (`d2b9db5` #11)
- CodeQL: advanced setup with explicit `actions: read` permission (default
  setup started failing 2026-06-15 -- managed runner's `GITHUB_TOKEN`
  lacked the scope for the workflow-run telemetry call even though
  autobuild succeeded) + `paths-ignore` for `ctf-writeups/` and
  `labs/vulnllm/` (CTF puzzle-passwords and vuln-lab telemetry are
  synthetic teaching data that trip the clear-text-logging heuristic as
  false positives; `tools/` and `labs/rag-security/` stay scanned).
  (`03b392c` #10)

### Maintenance

- `actions/checkout` 4.3.1 -> 7.0.0, `actions/setup-python` 6.2.0 -> 6.3.0.
  (`b754080` #13, `10d961c` #12)

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
