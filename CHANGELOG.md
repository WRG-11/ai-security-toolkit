# Changelog

All notable changes to `ai-security-toolkit` are documented here.

This is a portfolio repository (research + labs + tools + CTF writeups),
not a versioned Python package. Releases are tracked by GitHub commit SHA
rather than semantic versions. This CHANGELOG batches notable additions
and updates by date for readability.

## [2026-07-30] -- the install name pointed at somebody else's package

### Changed -- breaking, if you were installing by distribution name

- **The distribution is now `wrg-ai-security-toolkit`.** The unprefixed
  `ai-security-toolkit` on PyPI belongs to a different author and is the same
  kind of project — "a red-team AI security framework with adversarial attack
  modules", v1.1.2 as of 2026-07-30. So `pip install ai-security-toolkit`
  installs their security tooling, not this. Nobody was misdirected by our own
  docs, which only ever said `pip install -e .` from a clone, but the name was
  unpublishable and confusable in the one category where confusing two security
  tools matters most.

  The repository, the clone directory and the three console commands
  (`prompt-injection-detect`, `llm-scanner`, `llm-firewall`) are unchanged.
  Only the distribution carries the prefix.

  `tests/test_distribution_name.py` pins it. Renaming back would be a one-word
  edit that nothing else in the repo would notice — the imports are `tools.*`,
  the scripts are unprefixed, and so is the clone directory.

### Fixed

- The HF Space's `requirements.txt` names the prefixed distribution, so the
  Space installs this package rather than resolving to the other one.

## [2026-07-29] -- honest measurement, part 2: the artefact and the wheel

Follow-up to PR #15, which fixed how the detector is *measured*. This round
asked whether those fixes reached the paths a user actually runs. Several did
not.

### Fixed -- the tool gave wrong answers

- **The shipped model overrode the calibration.** PR #15 moved
  `DEFAULT_THRESHOLD` to 0.30 and documented at length why 0.50 was wrong, but
  `injection_model.json` still carried `threshold: 0.5` and `load_model()`
  wrote it back over the constant — and over an explicit `--threshold` from
  the user. The default CLI path therefore ran at 0.50 the whole time.
  Measured: holdout recall 0.840 at 0.30 against **0.057** at 0.50. In-sample
  scoring cannot see this (all three thresholds catch 194/194), which is why
  it survived. The threshold is no longer read from the artefact at all;
  `tests/test_shipped_model.py` locks artefact and constant together and
  separately checks that loading does not move the threshold.
- **`--json` and `--serve` crashed on every detection.** `Severity` is an enum
  and `PredictionResult.to_dict()` passed it through, so any input that
  tripped a regex rule died with `TypeError: Object of type Severity is not
  JSON serializable`. Clean input worked; an attack did not. The machine-
  readable output and the HTTP integration surface both failed exactly when
  they had something to report.
- **Every regex detection printed blank.** The producer's documented contract
  emits `pattern` / `match`; the CLI renderer read `description` / `matched`,
  so findings rendered as a bare `[Severity.CRITICAL]` with no rule name and
  no matched text. Both are normalised once at the boundary now.
- **`--list-probes` crashed on a narrow console.** A probe name contains
  U+2192; on a cp1254 Windows console the command printed ~30 lines and then
  died with `UnicodeEncodeError`, exiting 1 — a successful informational
  command reporting failure. `tools/_console.py` makes stdout/stderr
  UTF-8-safe; `tests/test_console_encoding.py` forces the narrow encoding via
  `PYTHONIOENCODING` so the regression is reproducible on Linux CI.
- The two `[UYARI]` warnings were the only non-ASCII user-facing strings in a
  file that folds everything else to ASCII, and they mojibake'd on the same
  console.
- The score line was labelled `esik:` ("threshold") while printing the three
  layer scores.

### Fixed -- the package installed but did not run

- **Two of the three console scripts died at `--help` from a wheel.**
  `llm-scanner` and `llm-firewall` import their attack corpus and guards from
  `labs/vulnllm/`, which is deliberately not packaged, so a non-editable
  install gave `ModuleNotFoundError: No module named 'attacks'` — a module
  name that appears nowhere in the user's own code. `tools/_lab.py` now stops
  with the directory it looked for and the command that fixes it.
- **That message arrived under a traceback, which undid most of it.**
  `ensure_lab_on_path()` was called at module scope, before `main()`, so the
  exception could not be caught and Python printed the full stack first. The
  user's opening line was `Traceback (most recent call last)`, which reads as
  "this tool crashed" rather than "this tool cannot run from this kind of
  install". `ensure_lab_or_exit()` prints to stderr and exits 2. Two, not one:
  1 means the scan ran and found something, and a CI job treating any non-zero
  exit as findings would report a security result for an install that never
  executed.
- **The message was Turkish in an English repository.** README, badges,
  CHANGELOG and commits are all English, so `pip install` users were told
  `labs/vulnllm/ bulunamadi`. It is English now. Comments and docstrings stay
  Turkish; those are developer notes and the distinction is deliberate. The
  text stays free of diacritics for narrow Windows code pages, same reason
  `_console.make_output_safe` exists, and a test holds all three properties.
- **CI could not have caught it.** The `test` job installs with `-e`, which
  keeps the checkout on disk and makes the lookup succeed every time: the
  install path CI exercised was the one that could not fail. Added a `wheel`
  job and `tests/test_wheel_install.py`, which builds a venv, installs
  non-editable, and asserts the split — detector predicts (the model is
  package data), `--train` exits 2 with an explanation, the other two name the
  missing tree.
- **A guard that could not work.** `train()` fell back to
  `from defenses.ml_classifier import INJECTION_SAMPLES` when the corpus was
  missing — but the only reason it can be missing is that `labs/` is absent,
  and `defenses` is in the same tree. The guard produced a second
  `ModuleNotFoundError` in the exact case it existed for.

### Fixed -- claims that had drifted

- **`tools/README.md` was the unstamped twin of `README.md`** and had drifted
  underneath the stamper added in PR #15: it still advertised the retracted
  "100% F1 score on test set", "17 rules" for a 9-rule engine (17 is the
  Gradio demo's separate table), "88 benign samples" for 80, and line counts
  ~140 short. Six of its documented commands never existed —
  `--target`, `--model`, `--category`, `--full` for the scanner and
  `--check-input`, `--serve` for the firewall. The fix had been applied one
  table away from the defect.
- `scripts/readme_stamp.py` now stamps three files (both READMEs and the Space
  card) and **treats a missing marker as drift**. It used to warn on stderr and
  exit 0, so deleting a marker was the easiest way to switch a metric off
  while the job stayed green.
- Coverage was quoted by hand in two places (README 36%, `.coveragerc` 35%)
  and was really **51%** — the tests added in PR #15 moved it and nobody moved
  the prose. `fail_under` sat at 30, twenty-one points below reality. The
  floor is now 45 and README stamps *that* number, because the measured
  percentage moves every commit and the enforced one is the one that bites.
- The `rag` extra listed `chromadb` while the lab also needs
  `sentence-transformers` (`vulnerable_rag.py:107`), so the documented
  `pip install -e ".[rag]"` produced a lab that died on setup. Added, plus a
  `ctf` extra for the ODIN solvers' `requests` — the one real dependency
  missing from a table that called itself the whole map.
- `SECURITY.md` scope named three files and `labs/`. It predated the Gradio
  demo, the packaged model, `scripts/` and the workflows, and did not say what
  counts as a finding in a detection tool or that solving a lab challenge is
  not one.
- The Gradio demo kept its own `threshold = 0.50` default and three
  hand-typed "17 rules" (four, counting the Space card). The constant now
  mirrors the tool's and is checked by `tests/test_hf_space_parity.py`; the
  counts derive from `len(RULES)` or a stamped marker.

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
  Closes the personal-PII surface in a public-repo security policy.

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
