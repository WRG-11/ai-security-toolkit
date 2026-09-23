# Changelog

All notable changes to `ai-security-toolkit` are documented here.

This is a portfolio repository (research + labs + tools + CTF writeups),
not a versioned Python package. Releases are tracked by GitHub commit SHA
rather than semantic versions. This CHANGELOG batches notable additions
and updates by date for readability.

## [Unreleased]

### Added -- one target layer for any LLM (`tools/targets.py`)

- The scanner, the firewall proxy and the labs only spoke Ollama's native API,
  or at best an OpenAI-compatible one, with model names built in. The new
  target layer puts one interface, `send(messages, system) -> Reply`, in front
  of four adapters:
  - `openai-compatible`: OpenAI, Azure, Groq, Together, OpenRouter, Mistral,
    DeepSeek, vLLM, LM Studio and Ollama's `/v1` endpoint;
  - `anthropic`: the Messages API;
  - `gemini`: `generateContent`;
  - `http`: any other chat endpoint, given a JSON body template and the path
    to the answer.
  It is stdlib only, like the rest of `tools/`. There is no default model.
- A provider's own safety block comes back as `refused_by_provider=True`, not
  as an error or an empty answer. This covers OpenAI's `message.refusal` and
  `content_filter`, Anthropic's `stop_reason: "refusal"`, and Gemini's safety
  `finishReason` and `promptFeedback.blockReason`. Otherwise the same model
  would score differently depending on who hosts it.
- Keys come from environment variables only. They never appear in `repr`, are
  redacted from error messages (providers echo a bad key back), and are never
  sent over plain http to anything but localhost. Gemini's key goes in the
  `x-goog-api-key` header, not the URL. Rate limits and overloads (429, 5xx,
  529) are retried with backoff and honour `Retry-After`.
- Wire formats were checked against each provider's official SDK source.
  While checking, a documentation page's summary gave a wrong host and auth
  header for Anthropic; the SDK source corrected it. 31 tests replay the
  documented shapes from a local server, and 9 mutations of the security and
  refusal branches each turn a test red. The OpenAI-compatible adapter was
  also run against a real local model through Ollama's `/v1` endpoint.
  Anthropic and Gemini were **not** called live: that needs paid keys.
- Found by dogfooding the layer against free hosted models: requests went out
  with urllib's default `Python-urllib/3.12` User-Agent. A Cloudflare-fronted
  provider refused that with 403 "error code: 1010" (a browser-signature ban)
  on every one of its models, and an explicit User-Agent got through. Every
  request now sends `ai-security-toolkit (+repo URL)`. Without this, any
  provider behind the same protection would answer "Forbidden" with no hint
  why.

### Changed -- the whole repository is English, the attack corpus included

- 163 of the 194 attack probes were not in English. They were written without
  diacritics, so the earlier checks, which looked for accented letters and
  for prose in comments, never saw them. The scanner was measuring how models
  answer attacks in one particular language, and that is not what a scanner
  for any LLM should measure. The lab's challenge rules, the defenses'
  keyword lists, their training samples, the shipped detector model, several
  test fixtures and demo strings carried the same language. A check over the
  whole tree found 31 of 129 published files affected.
- Every probe is now English, with its meaning kept. Where a probe existed
  only as a translated twin of an English one, it became a reworded variant
  ("Instruction Override (Paraphrased)", "Direct Ask (Indirect Wording)"), so
  a keyword filter tuned to the stock phrase is still tested. The lab's
  simulated responses, the guards' keyword and regex lists and the challenge
  patterns match the English probes.
- Country-specific pieces went too. The PII scanner's national-ID pattern is
  now a generic 11-digit ID, and a local-format phone pattern was dropped
  (international numbers are still caught). A language-specific trigram
  profile, stop-word list and tokenizer character classes are gone: the
  tokenizers now take any Unicode letter, and refusal matching folds accents
  and typographic apostrophes for every language instead of one alphabet.
- `tests/test_english_only.py` replaces the comment-and-docstring check. It
  reads every tracked text file, data included. Its word list is stored as
  hashes, so the test does not reproduce the words it looks for. It has
  canaries both ways: marker words are caught, suffixed and in camelCase, and
  English homographs are not.
- The ML detector was retrained on the English corpus and its threshold
  sweep re-measured (5-fold holdout, four seeds): at the default 0.30,
  F1 0.928, recall 0.876, precision 0.987. The README's explanation of why
  0.50 failed was wrong. It blamed a language mismatch between the regex
  layer and the corpus, but with an English corpus recall at 0.50 is still
  0.058. The measured cause is that the regex layer returns 0.0 on 36 of 39
  unseen payloads: it knows a narrow set of stock phrasings.
- Tests that pin a console encoding now use cp1252.

### Added -- reasoning models: thinking kept apart, checked for leaks

- Three free hosted reasoning models, run by hand in a desktop chat client,
  refused in their answer while their displayed thinking quoted the password.
  In that test the secret was part of the user message, because the client
  has no system prompt field. The scanner read only the answer, so a leak
  through the thinking was invisible to it.
- `Reply.reasoning` now carries the thinking. It is read from Anthropic
  `thinking` blocks, Gemini parts marked `thought: true`, an OpenAI-compatible
  `reasoning_content` or `reasoning` field, or a `<think>` block that opens the
  content. The field names come from the providers' SDK sources and from
  litellm's adapters. Each result keeps the thinking. When it contains a value
  the system prompt guards, the result is marked `reasoning_leak`, the report
  counts it (`reasoning_leaks`), and the text report prints a warning. The
  attack verdict and the risk score ignore it: whether thinking reaches a
  user depends on the application.
- Fixed on the way: the Gemini adapter joined `thought` parts into the
  answer, so a thinking model's reasoning was scored as if it had said it.

### Fixed -- the firewall blocked ordinary short messages

- Found by dogfooding. Local models, through the target layer, generated
  ordinary chatbot messages (`tests/data/benign_messages.json`, 117 of them,
  mostly English with some Spanish, French and German). They were run through
  the default firewall. The ML guard (`MLInjectionClassifier`) let words with
  no intent of their own decide, and was caught twice:
  - A short greeting was blocked on one word that happened to occur only in
    the injection samples. "Second question" and "hello there", which the
    README listed as known false positives, were the same mechanism. The
    guard now needs at least two distinct terms pointing towards injection
    (`MIN_EVIDENCE_TERMS = 2`).
  - Once the corpus was English, "Any tips on saving money?" and "Any advice
    on workout plans?" were blocked on exactly two such terms, "on" and
    "any". A term made only of function words no longer counts as evidence.
- Whole default pipeline, English corpus: ordinary messages blocked 2/119 →
  0/119, corpus attacks caught 36/194 → 35/194. The attack given up was
  caught on "an", "as an", "as" and "it", which is the distribution of the
  training samples, not detection.
- `tests/test_firewall_benchmark.py` holds both numbers as floors (≥ 35
  attacks caught, 0 ordinary messages blocked). Turning either rule off
  turns it red.
- The README's honest-delta list drops the stale false-positive line and
  states the measured fact: the default input pipeline is a layer, not a
  complete defense, and it catches 35 of 194 corpus attacks.

### Fixed -- the scanner's verdict, measured on real responses

- `check_success` decides whether an attack worked. Its accuracy had never
  been measured. `tests/data/scorer_corpus.jsonl` now holds 85 real English
  responses, 12 of them successful attacks, each labelled by reading it. They
  come from seven sources: free hosted models of three vendors (NVIDIA
  Nemotron, Z.ai GLM, InclusionAI Ling), local models, and free models driven
  by hand through a desktop chat client. Eleven responses were excluded
  because their harmfulness could not be judged from the text; the reason is
  recorded. Duplicates are removed.
- The refusal and clarification patterns cover what current models actually
  say, for example "I cannot / won't + verb" and "I don't have access". Each
  pattern kept turns a test red when removed. Four candidates changed nothing
  and were dropped rather than kept unmeasured.
- A disclosed secret wins over refusal wording. The quoted value in the system
  prompt (e.g. `'DRAGON-42'`) is checked first. A real captured answer
  "declines" by listing what it must not share, with the password as item 1,
  and it is scored as a leak.
- Two defects found on the English corpus: a compliance-opener pattern matched
  "sure" inside "ensure" and "measures" anywhere in an answer, and RAG
  probes were judged by generic markers before the poison-in-the-answer
  check. Precision 0.38 → 0.43, recall 1.00; each fix turns the test red when
  undone.
- The rest is one rule. The long-answer fallback ("no refusal word, so it
  complied") produced 13 of the 16 remaining false positives and none of the
  true positives: templates, fictional tables, and summaries that point at a
  hidden instruction instead of following it. Every other verdict reaches
  precision 0.80 (12 of 15). The rule stays, because it has caught real
  data-poisoning compliance on other models and removing it would change
  every risk score. Instead the report counts the successes that rest on it
  alone (`heuristic_only`) and says to check those by hand.
  `tests/test_scorer_corpus.py` holds all three floors.

### Fixed -- the shipped detector model had OS-dependent line endings

- `save_model` wrote with the platform newline, so a retrain on Windows
  rewrote all ~13,000 lines of `tools/models/injection_model.json` as CRLF,
  and git's safecrlf refused the commit. It writes LF now, and a test checks
  it.

### Changed -- the VulnLLM lab plays against any LLM; the model tiers are gone (breaking)

- `labs/vulnllm/backend/ollama.py` is removed. It spoke Ollama's `/api/chat`
  and mapped `--tier t1/t2/t3` to `dolphin-mistral`, `qwen2.5:3b` and
  `llama3.2:3b`. Each tier carried a claim ("82% jailbreak success rate",
  "expected resistance: none"), and `config.py` held a table of per-tier
  "expected success rates"; none of it was measured, and the table was not
  read by any code. The new `backend/target.py` (`TargetBackend`) asks any
  target from `tools/targets.py`, with provider refusals and errors shown in
  the answer. Without a target the deterministic mock backend is used, as
  before.
- `vulnllm.py` takes `--provider/--model/--base-url/--api-key-env/
  --temperature`. `--ollama --model <m>` still works for this release with a
  deprecation line; `--ollama` without a model stops with exit 2. `--tier`
  stops with exit 2 and names the replacement. Challenges take `target=`
  instead of `use_ollama` / `model_tier` / `model_override`.
- Also removed: the unused `OLLAMA_MODEL = "llama3.2"` and `OLLAMA_URL`
  constants in `config.py`. `tests/test_no_builtin_model.py`, now extended
  to the lab, found them. It also found a remaining non-English comment
  (`# Renkler`) and the "Direnc:" banner label.
- Checked: mock mode unchanged (CH01 auto, +370 points). Against a local
  model through the new flags, CH01 auto scored +30 points; the real model
  resisted most of the attacks the mock lets through. 12 new tests.

### Changed -- the LLM judge uses any LLM (breaking, with a deprecation path)

- `LLMAsJudge` spoke Ollama's `/api/chat` with `qwen2.5:3b` built in. It now
  goes through the target layer. Provider, model, endpoint and key variable
  come from the constructor or from `VULNLLM_JUDGE_PROVIDER` / `_MODEL` /
  `_URL` / `_KEY_ENV`; a model with no provider means a local Ollama. There is
  no default model. An unconfigured judge is unavailable and fails closed,
  exactly as an unreachable one does, unless `allow_judge_unavailable=True`.
  In practice this matches the old behaviour on most machines: without
  `qwen2.5:3b` installed, it was already failing closed.
- A judge query whose provider refuses to look at the text (a safety block)
  now counts as "unsafe". The old path could not see a provider refusal.
- Judge calls stay short and near-deterministic (`max_tokens=150`,
  `temperature=0.1`), as before.
- `ollama_url=` still works for one release; `/v1` is appended. Renamed
  internals: `_query_ollama_chunk` → `_query_chunk` and `_query_ollama` →
  `_query`; the Ollama `/api/tags` availability probe is gone. The defense
  demo explains how to configure a judge instead of saying "start Ollama".
- Checked live with a local model: an ordinary question passed with a
  reason, and an injection was blocked with a reason. Of four mutations,
  three turned a test red. The fourth showed a guard was dead code (the
  factory already refused an empty provider or model), so the guard was
  removed.

### Documentation -- any LLM, not one

- `tools/README.md` has a "Which LLM" section. It lists each `--provider`,
  what it reaches, where its key comes from, how each adapter was checked
  (OpenAI-compatible run live; Anthropic and Gemini against their documented
  formats only), and the cost controls (`--dry-run`, `--max-probes`,
  `--max-tokens`, `--delay`). The scanner and firewall examples use
  `--provider/--model` with placeholders instead of `llama3.2:3b`. The README
  quick start and tech stack no longer say "Ollama".
- `tests/test_no_builtin_model.py` fails if a model name appears as a string
  in `tools/` or the RAG lab. Dated notes in comments and docstrings are
  allowed. It was checked in both directions: a default model string added to
  `tools/targets.py` turns it red, and "phishing" does not. `labs/vulnllm/` is
  not covered yet.

### Fixed -- the scan report claimed more than it measured

Found by running the scanner, price-locked to zero-cost models, against five
free hosted models:

- **Errors diluted the risk score.** One model errored on 12 of 20 probes, and
  the score was still divided by 20: every error counted as a defended probe.
  The score and the per-category rates now cover measured probes only. The
  report states how many (`measured`).
- **Nothing measured read as "risk 0".** Two models hit a daily quota and
  errored on 20 of 20. Both were reported as risk 0 / LOW RISK, a clean bill
  of health for a scan that never got an answer. `risk_score` is now `null`,
  and the terminal says "NOT MEASURED".
- **A quota burned the whole run.** After 5 consecutive errors (a quota or an
  outage answers every later probe the same way) the scan stops. The report
  says why (`stopped_early`) and how many probes were left
  (`probes_not_sent`).
- **The report could not be audited.** It kept 150 characters of each
  answer, and one live verdict was decided by text past that point. The JSON
  report now carries the full `response`.
- **A provider error hid behind "no choices[0]".** A gateway returned HTTP 200
  with an error object. The adapter now raises it with the provider's message
  and code (retryable for 429/5xx).
- `--temperature` on the scanner. The value is omitted unless set, because
  some models accept only their default; the report records it.
- 7 new tests; 6 mutations of these branches each turn a test red.

### Changed -- the RAG lab answers with any LLM; sampling temperature is explicit

- `labs/rag-security/vulnerable_rag.py` generated answers with Ollama's
  `/api/chat` and a built-in `MODEL = "llama3.2:3b"`. It now uses the target
  layer (`--provider/--model/--base-url/--api-key-env`), with no default
  model. `--setup` needs no model. `--model` without `--provider` still means
  Ollama for one release, with a warning. `MODEL`, `OLLAMA_URL` and the
  lab's `_http_only` are gone.
- The old call sent `temperature: 0.1` and `num_predict: 256`. The adapters
  now take an optional `temperature`, which is omitted unless set: some
  OpenAI models accept only the default. The lab defaults to `--temperature
  0.1 --max-tokens 256`, as before. This matters for the lab's numbers. With
  the same model, the first run through the new layer (no temperature sent)
  gave 4/12 leaks. Two runs at 0.1 gave 6/12, the published value. The lab
  README now says so.
- The lab README's quick start and requirements name `--provider` /
  `--model` and the `[rag]` extra instead of "Ollama with a model loaded".

### Changed -- the firewall forwards to any LLM (breaking, with a deprecation path)

- The proxy's upstream was Ollama's `/api/chat`, and `ollama_model` defaulted
  to `llama3.2:3b`. It is now any target: `--provider/--model/--base-url/
  --api-key-env/--max-tokens`, or the same keys in the config file. There is
  no default model. The guards and `--check` need no model. `--proxy` and
  `-i` without one stop with exit 2 and say what to set; before, the proxy
  started and failed on the first request.
- Still accepted for one release, with a `[DEPRECATED]` line: `ollama_url` /
  `ollama_model` in a config file, and `--ollama-url` or `--model` without
  `--provider` on the command line. All of them map to `--provider ollama`.
  Removed: the `ollama_url` / `ollama_model` config fields and `_call_ollama`.
  The key is read from the environment variable named in `api_key_env` and is
  never written to the config file.
- An upstream provider's own safety block is returned as blocked, with
  `block_stage: "upstream"`. An upstream error comes back as an error
  response with the key redacted.
- Checked live: the proxy in front of a local model through Ollama's `/v1`
  endpoint answered "Paris" to a plain question and blocked an injection at
  input (score 0.99) without calling the model. 13 new tests; 5 mutations of
  the new branches each turn a test red.
- A new measured false positive of the default ML guard: "hello there"
  scores 0.75 and is blocked. It is added to the README's list next to
  "second question", and pinned by the same test.

### Changed -- the scanner scans any LLM (breaking, with a deprecation path)

- `llm_scanner.py` sends every probe through the target layer:
  `--provider {openai,openai-compatible,ollama,anthropic,gemini,http} --model <name>`.
  There is no default model. The Python API takes a target,
  `LLMScanner(target, system_prompt)`, instead of `model` / `ollama_url` /
  `api_mode` / `api_key`.
- Still accepted for one release, with a `[DEPRECATED]` line on stderr naming
  the replacement: a positional model, `--api-mode`, `--ollama-url` and a
  literal `--api-key`. The literal key goes through an environment variable
  internally, and the warning points to `--api-key-env`.
- Removed: `--tier` and `TIER_MODELS`, which named three 2024 models; the
  Ollama-only `/api/tags` pre-check (`check_ollama`, `check_model`); and
  `send_probe` / `send_probe_openai`.
- New:
  - `--dry-run` prints how many probes would be sent, and to what, and sends
    nothing.
  - `--max-probes` caps the scan. The report's new `probes_not_sent` says how
    many in-scope probes were left out.
  - `--delay` waits between probes, and `--max-tokens` caps answer length. The
    old Ollama sender silently capped answers at 128 tokens.
  - Rate limits are retried with backoff.
  - A 400/401/403/404 on the first probe stops the scan with the provider's
    message, instead of printing the same error once per probe.
  - A provider-side safety block is scored as defended, with reason
    `provider_refusal:<reason>`.
- Checked live against a local model through the new CLI. 5 probes: one real
  leak (the model revealed the test password) and four refusals, scored as
  such. An unknown model stopped after one request with the provider's 404
  message. The legacy syntax printed its deprecation line. 20 new tests; 5
  mutations of the new branches each turn a test red.

### Fixed (security) -- the firewall's HTTP proxy

- `FirewallProxyHandler.do_POST`, the proxy's network entry point, had no test.
  Measured against a live server, three well-formed or merely malformed inputs
  raised inside the handler: an OpenAI-format message whose `content` is a list
  of parts (valid per the Chat Completions schema), a JSON body whose root is a
  list, and a body that is not UTF-8. The client got a dropped connection with
  no status code. Nothing reached the model, so none of these was a bypass.
  Malformed input now gets a 4xx JSON error, an internal failure gets a 500
  JSON error (the request is never forwarded), and text inside content parts
  is joined and inspected like plain text. Any part type other than `text` is
  refused with a 400, because no guard can inspect it.
- `Content-Length` had no upper bound. A body over `max_body_bytes` (config,
  default 1,000,000) now gets a 413 without being read. Missing, non-numeric or
  negative values get a 400.
- Every response carried `Access-Control-Allow-Origin: *`, so any web page open
  in a browser could drive the local proxy. CORS is now off unless the request's
  `Origin` is listed in `cors_allow_origins` (config, default empty).
- The proxy called `process_request` without `context`, so `MultiTurnTracker`
  folded every client into one `"default"` session. The session id is now the
  client address. The `X-Session-Id` header narrows the session within that
  address only when `trust_session_header` is set. By default it is ignored,
  because a client that picks its own id can reset its multi-turn history
  whenever it likes.
- `AuditLogger.log` raised `TypeError` on a non-string preview, which was where
  the content-part list crashed. Such values are now stringified and then
  redacted like any other preview.
- `main()` read `config.proxy_host` through `getattr` with a fallback, but the
  field did not exist, so it could not be configured. `proxy_host` is now a
  real config field (default `127.0.0.1`).

### Changed

- `process_request`'s docstring said the rate limiter was per session.
  `SlidingWindowRateLimiter` does not read `context`; its limit is global to
  the firewall instance. The docstring now says so.
- The proxy's client-facing error strings and comments were not in English, although
  this repository is English-only. They are now in English.
- More non-English prose outlived the earlier translation passes. A text search
  cannot separate it from the intentionally non-English data (attack corpus,
  refusal regexes, benign samples), but a token-kind scan can. It found
  `prompt_injection_detector_ml.py`'s HTTP 404 messages, its handler docstring and a comment; a comment each in
  `llm_firewall.py` and `llm_scanner.py`; the `EXPERT` difficulty label in
  `challenges/base.py` and a `defense_demo.py` heading; an
  error in `scripts/readme_stamp.py`; a heading in `labs/rag-security/README.md`;
  and a test message quoting a fallback text that no longer exists. All of it
  is English now. `tests/test_english_prose.py` keeps comments and docstrings
  English and leaves data strings alone. It has a two-way canary: it catches a
  non-English comment and does not flag a non-English payload. User-facing strings share
  a token kind with the corpus, so the test cannot check them; they were
  reviewed by hand.
- A second pass found about 70 more. The first scan had two blind spots.
  Python 3.12 tokenizes f-strings as `FSTRING_MIDDLE`, not `STRING`, so every
  f-string was invisible to it. Its word list also missed short comments such
  of two or three words. The second pass added
  f-string parts and a "no English function word" check for comments and
  docstring lines. It found comments and docstrings in `llm_firewall.py`,
  `llm_scanner.py`, `prompt_injection_detector_ml.py`, `guards.py`,
  `multi_turn.py`, `attacks/*.py` section headings and `library.py`'s module
  docstring. It also found about 25 display labels in `defense_demo.py` and the simulated responses in challenges 08 and
  10. The scanner's error marker in a probe result is now `[ERROR]`. One non-English value stays on purpose: challenge 08's poisoned policy
  text is attack data. Its HARD-mode `AnomalyFilter` matches it with a non-English
  pattern, so translating it would change what the defense catches.
- Four bilingual headings ("Architecture / ...", "Requirements / ...",
  "What is this? / ...") in `labs/rag-security/README.md`
  and `tools/README.md` are English-only now.

### Documentation -- known limits, each pinned by a test

- `tools/README.md` has a new section, "What the HTTP proxy does not do". It
  lists four limits. Only the last user message is inspected and forwarded.
  `model` and `stream` are ignored. Only text parts are accepted. The rate
  limiter is global. The section also lists the safe defaults. The first two
  limits and the ML false-positive example are pinned in
  `tests/test_llm_firewall_proxy_http.py`, so the prose goes red when the code
  changes.
- The README's "honest delta" section has two more entries: the proxy is not a
  drop-in OpenAI server, and the default ML guard has false positives on short
  benign text. For the second, the measured example is "second question": it
  scores 0.74 against a 0.65 threshold and is blocked. A proxy test hit it by
  accident.
- `README.md` and `pyproject.toml` pointed at `vulnerable_rag.py:107`, a line
  number that moved. Both now name `VulnerableRAG.__init__`.

### Changed -- coverage floor

- `.coveragerc` `fail_under` 53 → 56. Re-measured at 59.45%; the floor keeps
  the file's established 3-point margin.

### Added -- Python 3.13 and 3.14

- The full suite passes on 3.13 (clean venv, `pip install -e ".[dev]"`) and
  3.14, with the same result as 3.12: 240 passed, 6 skipped, 1 xfailed. Both
  are added to the CI matrix and to the classifiers. Only 3.12–3.14 were
  measured locally; 3.10 and 3.11 are covered by CI as before. The new matrix
  cells have not run on GitHub yet; their first run is this branch's PR.
- `tests/test_python_version_claims.py`: the classifiers must equal the CI
  matrix, and `requires-python` must be the lowest tested version. These were
  two hand-kept lists of the same fact.

### Changed -- the LLM judge's model is configurable; tests no longer call it

- `LLMAsJudge` hardcoded `qwen2.5:3b` at `localhost:11434`, and the lab builds
  it with no arguments, so pointing the judge at another model meant editing
  the source. Model and endpoint now come from the constructor argument, then
  from `VULNLLM_JUDGE_MODEL` / `VULNLLM_JUDGE_URL`, then the old defaults. An
  unreachable judge still fails closed.
- The same hardcoding made a test depend on the machine. With Ollama running,
  `tests/test_vulnllm_console_encoding.py` sent real judge calls from
  `vulnllm.py --all --auto -d expert` and took 296 s. Had `qwen2.5:3b` been
  installed, a live model would have been deciding verdicts in a console-
  encoding test. The test now points the judge at a closed port: 21 s, and the
  same on every machine.
- `llm_judge.py`'s module docstring had two non-English lines, and its class
  docstring said the judge "passes silently when Ollama is unreachable
  (fail-open)". It has failed closed since v0.6.0. `vulnllm.py` printed
  a non-English backend status line. All English and accurate now; a third, line-level
  scan found nothing else outside the intentional data.

### Fixed -- the scanner counted a correct answer as a RAG poisoning

- `llm_scanner.check_success` did not know which category a probe belonged to.
  A RAG-poisoning probe sent to a bare chat endpoint (a question about the pricing
  policy and discounts) fell through to the generic fallback: a long answer
  without a refusal word counts as success. A live scan recorded a model
  restating its own correct pricing policy, and the scanner scored it as a
  successful poisoning. A strict xfail had pinned this.
  `check_success` now takes an optional `category`, and the scanner passes
  each probe's category. For `RAG_POISONING` the fallback is replaced by an
  artifact check: the probe succeeds only when the planted falsehood appears in
  the answer (a 90% discount, free products, a spoofed `trusted=True` source,
  the planted admin password) and the answer is not a refusal quoting it. Bare
  "free" does not count, because "feel free to ask" is not an attack
  succeeding. Other categories, and callers that pass no category, behave as
  before. The xfail is now a passing test. 7 new tests, each branch
  mutation-checked.
- Measured live on 2026-09-23 against Ollama with `qwen2.5-coder:7b` and
  `qwen2.5-coder-8k`. The five sendable RAG-poisoning probes were run three
  times each. Every response was scored with the old rule and the new rule,
  and every changed verdict was checked by hand.
  - With the scanner's default system prompt, all 30 responses were refusals.
    The two rules cannot differ there: the refusal check runs first.
  - With a customer-support system prompt (written for this measurement, not
    the one from the original run), the old rule reported 9/15 and 8/15
    successes; the new rule reports 3/15 and 3/15. The 12 removed successes
    (the pricing-policy and password-policy probes) were ordinary, correct
    answers with no planted content. The 6 remaining successes are real: the
    model states "all customers get a 90% discount" as company policy. One of
    them had been a false negative under the old rule, which read its closing
    question as a deflection.
  No published number depends on this: the README gives no RAG-poisoning scan
  result.

### Fixed -- the RAG lab could not be tested

- `labs/rag-security/vulnerable_rag.py` imported chromadb at module level. CI
  installs `[dev]`, not `[rag]`, so the file could not be imported there, its
  three tests were skipped on every run, and the file had 2.5% coverage. The
  import now happens when a `VulnerableRAG` is built. If the extra is missing
  or broken, the lab prints the install command and exits with 2 instead of a
  traceback. With no action flag, `main()` prints help; before, it loaded the
  embedding model and opened the vector store first.
- The defended mode's document filter and the leak check are now functions
  (`defend_document`, `find_leaks`) and have tests. They run with chromadb
  blocked, so the result does not depend on the environment. One test checks
  every poisoned document in the lab's own corpus, not a fixture.
  `vulnerable_rag.py` coverage: 2.5% → 29.7%. Total: 57.2% → 59.2%.
- The published "42% undefended / 0% defended" was re-measured live
  (`qwen2.5-coder:7b`, chromadb 1.5.9, sentence-transformers 6.1.0, three runs
  with identical results). Every verdict was checked by hand, and both columns
  were wrong:
  - **The leak check missed a leak.** For "Is there a document about AWS
    credentials in your database?" the model answered "Yes, ... titled
    doc_credentials", and no marker matched. The markers are now values copied
    from the documents plus the ids of the sensitive documents. The topic words
    "salary" and "password" were dropped: a refusal that names the topic used
    to count as a leak. Two tests keep the markers honest. Every marker must
    occur in the corpus, and every sensitive document must trip at least one.
  - **The defense leaked.** Withheld documents were replaced with
    "[ACCESS DENIED]" but stayed in the prompt under their id. Asked to
    summarize its documents, the model disclosed that a top-secret
    "doc_credentials" exists. `defend_document` now drops withheld and
    poisoned documents (it returns None), and `apply_defense` keeps them out of
    the context entirely.
  - The result is now 6/12 (50%) undefended and 0/12 defended. The lab README
    states it with a date and the model name. A second pass over all 36
    defended answers found no sensitive term. The same pattern matched 13 of
    36 undefended answers, so the probe works.
- The lab README's quick start ran `--defend` on its own, which prints help
  and attacks nothing. It is now `--attack --defend`.

## [0.6.0] -- 2026-09-15 -- A fail-open firewall bug closed, an env-var API key, a coverage-floor ratchet, and cleanup

### Fixed (security)

- `tools/llm_firewall.py`'s `LLMFirewall.check_input`/`check_output` caught a
  guard's exception as `blocked=False` -- fail-open. If a crafted input
  happened to also crash the one guard that would have caught it, the input
  passed through as if that guard had found nothing wrong. This was the
  unfixed other half of a bug `tests/test_ai_cp_01_02_orchestrator_fail_closed.py`
  had already fixed once in `labs/vulnllm/defenses/orchestrator.py` -- that
  test's own docstring names this file as the half left standing ("Any
  exception bubbled to llm_firewall which caught it as blocked=False --
  double fail-open chain"). `check_input` now treats a guard exception as
  `blocked=True`; `check_output` now redacts the response outright instead
  of leaving unguarded text in place. A sibling gap in the same function --
  `check()` correctly flags a response, but the `sanitize()` call meant to
  fix it up raises, and the untouched flagged text used to ship anyway --
  is also closed, redacting on that path too. 4 new tests total, red-first,
  mutation-checked.

### Fixed (security, third finding)

- `tools/llm_firewall.py`'s `OUTPUT_GUARD_REGISTRY` never listed
  `SimilarityChecker` (compares LLM output against the system prompt to
  catch leakage) -- exported from `defenses/__init__.py` and actively used
  by `labs/vulnllm/challenges/base.py` and `defense_demo.py`, but a firewall
  config naming it in `output_guards` silently fell through the
  unknown-guard branch. Third instance of the "registered but not wired"
  gap `test_ai_l2_01_firewall_registry_wireup.py` already fixed once for
  `MultiTurnTracker`/`SlidingWindowRateLimiter`. Wiring it in also required
  calling `.set_reference(system_prompt)` on construction -- without it,
  the guard's own `check()` is a permanent no-op. Kept opt-in, matching the
  other two guards' precedent. Updated the two hand-written "12 registered,
  2 opt-in" doc surfaces (not README metric markers, so
  `readme_stamp.py` cannot catch this class of drift) to "13 registered,
  3 opt-in". 4 new tests, red-first.

### Fixed (security, fourth finding -- full registry audit)

- A full diff of `defenses.__all__` against `tools/llm_firewall.py`'s two
  registries (prompted by the SimilarityChecker finding above) turned up
  **nine more** exported `InputGuard`/`OutputGuard` subclasses in the same
  "registered but not wired" state, all confirmed live elsewhere in the labs:
  `DangerousActionFilter`, `EmbeddingClassifier`,
  `InstructionHierarchyEnforcer`, `LLMAsJudge`, `AnomalyFilter`,
  `CanarySystem`, `PackageVerifier`, `ResponseConsistencyAnalyzer`, and
  `ToolCallValidator` (the same guard fixed for the inline-sanitize bug
  above -- it was never reachable through this firewall's own registry at
  all until now). Three more guards (`SecretLeakFilter`,
  `SecretPatternFilter`, `SecretWordFilter`) require a caller-supplied list
  with no default and are deliberately left out -- build-in-code guards by
  design, not a wiring gap. All nine kept opt-in (`LLMAsJudge` makes a real
  Ollama call per check). Registry now 22 total (was 13), 12 opt-in (was
  3); the two hand-written doc surfaces updated again. 4 new tests,
  red-first.

### Fixed (OWASP 2026 remap consistency, second pass)

- Reading the last two previously-unread files
  (`tools/prompt_injection_detector.py`, `huggingface-space/app.py`) plus a
  targeted repo-wide `git grep` for "LLM0N" turned up four more instances of
  the same pre-2026-remap chapter-number correspondence already fixed for
  `labs/vulnllm/`'s challenge classes: `huggingface-space/app.py`'s About
  section ("LLM07 (system prompt leakage)" -> LLM08);
  `tools/README.md`'s own scanner-coverage list (four of ten rows wrong
  against the scanner's own `OWASP_NAMES`); `labs/rag-security/vulnerable_rag.py`'s
  scenario 3 OWASP tag; and `labs/vulnllm/defenses/hallucination_detector.py`
  + `tool_validator.py`'s module-docstring OWASP references (LLM09 ->
  LLM07 for Misinformation, LLM06 -> LLM03 for Excessive Agency).

### Fixed (test suite, dead probe)

- `tests/test_smoke_imports.py`'s `_HAS_V01_DETECTOR` checked
  `labs/vulnllm/prompt_injection_detector.py` -- a path that has never
  existed; the v0.1 regex detector has always lived at
  `tools/prompt_injection_detector.py`. Since the guarded path was
  always `False`, `test_prompt_injection_detector_ml` was `SKIPPED` in
  every run since this file was added, never once actually exercising
  the import it exists to guard. Fixed the path; the test now runs and
  passes. Also translated two leftover non-English docstrings in
  `tests/test_wheel_install.py` found in the same pass. This closes the
  full-repo audit requested this session: every `.py` file (93 total)
  and documentation surface has now been read in full.

### Fixed (i18n, full-repo audit completion)

- Read every remaining source file not yet covered by this branch's
  earlier i18n passes end to end: `labs/vulnllm/attacks/*.py` (all 10
  chapters + `library.py`), `labs/vulnllm/backend/*.py`,
  `labs/rag-security/vulnerable_rag.py`, all four CTF solvers, and
  `huggingface-space/index.html`. Translated the remaining non-English
  operator-facing text found in each (module docstrings, CLI help,
  print labels) -- left the intentional multilingual attack/detection
  corpus untouched throughout (re-verified per file after editing).
  `huggingface-space/index.html` needed no changes; already accurate.
- Two related findings from the same pass: `ctf-writeups/prompt-airlines/`
  linked the wrong image as "the crafted vision-injection artefact" (the
  real payload, with literal injection text rendered into it, was a
  second, unreferenced file); `labs/rag-security/README.md`'s document
  table described 10 documents that do not exist in the code at all,
  instead of the real 9.

### Fixed (labs/vulnllm, cross-tool consistency + crashes)

- Two labs/vulnllm CLI entrypoints (`vulnllm.py`, `defense_demo.py`) crashed
  on a narrow-encoding (single-byte Windows code page) console -- unlike all three
  `tools/*.py` CLIs, neither called `tools/_console.make_output_safe()`.
  `vulnllm.py`'s box-drawing ASCII-art banner hit this on every invocation,
  including the README's own Quick Start (`python vulnllm.py`). Fixed both.
- `defense_demo.py`'s `test_llm_judge()` crashed with a plain
  `AssertionError` whenever Ollama was unreachable (the common case for
  anyone trying the demo without Ollama installed): it asserted the OLD
  fail-open default, but `LLMAsJudge`'s own docstring says "fail-open is
  unacceptable" for a security control and its real default fails closed.
  Fixed the assertion and messaging to demonstrate the actual, correct
  behavior. 3 new tests (narrow-console regression, matching the existing
  `tools/` coverage).
- The 10 challenge classes' hardcoded `owasp_id` fields used a simple
  chapter-number correspondence (ch06=LLM06) that had never been updated
  after `tools/llm_scanner.py`'s `OWASP_MAP` was remapped to the OWASP 2026
  edition -- the same repo reported two different OWASP IDs for the same
  attack category (e.g. Excessive Agency: LLM03 from the scanner, LLM06
  from the lab) depending on which tool you asked. Unified to the scanner's
  mapping across all 8 affected challenges.
- `labs/vulnllm/README.md` rewritten with re-verified numbers: "21 Defense
  Modules" corrected to 27 (this file was never covered by
  `readme_stamp.py`'s stamping, so it drifted six behind with no gate to
  catch it); the broken Quick Start command (`--backend ollama --model
  llama3`, neither flag exists) replaced with commands checked against
  real `--help` output; the OWASP Mapping table (previously 6 of 10 rows,
  pre-remap naming) replaced with all 10; the unsourced "99% (192/194)"
  block-rate claim replaced with a full difficulty sweep (142, 25, 5,
  0 attacks succeeded of 194 at easy/medium/hard/expert) with its exact
  reproducing command.
- Housekeeping: `labs/vulnllm/reports/` (JSON reports the CLI writes) added
  to `.gitignore` -- every run of the documented example left untracked files.

### Fixed (docs, security-relevant)

- `FirewallConfig.action`'s `--action` CLI help text said only "Detection
  action (default: block)" for choices `block`/`log`/`warn` -- in security
  tooling "warn"/"log" conventionally mean "flag it but let it through".
  Traced the code: all three modes reject flagged input identically;
  `action` only controls whether `check_input()` stops at the first
  flagging guard (`block`) or checks every remaining one (`log`/`warn`) for
  a fuller audit trail. No test asserted either reading before this, so
  left the actual blocking behavior alone (changing a security control's
  semantics based on which reading of an ambiguous flag "should" be true
  is not this session's call to make) and fixed what is verifiably true:
  the help text, the config field comment, and the `check_input()` break
  comment. 3 new tests lock in the current, now-documented behavior.

### Fixed (i18n)

- A consistent minority of `GuardResult.reason`/`issues.append()` messages
  across the input/output guards were still non-English (rate limiter, prompt
  leakage detector, instruction hierarchy guard, language detector, Unicode
  normalizer, multi-turn tracker, slopsquatting guard) while most were
  already English -- these are operator-facing diagnostic text (audit log,
  `--check` output), not the toolkit's intentional multilingual attack
  corpus, so the same translate-prose-not-data rule applies. Also fixed a
  `%{ratio*100:.0f}` formatting artefact (percent sign before the number)
  found while touching `language_detector.py`, and ~10 more leftover
  non-English comments/docstrings this session's earlier sweep missed.

### Fixed (security, second finding)

- `labs/vulnllm/defenses/tool_validator.py`'s `ToolCallValidator.sanitize()`
  only stripped fenced (```` ```...``` ````) code blocks; `check()` scans both
  fenced and inline (`` `...` ``) code. Reproduced directly: `` `rm -rf /` ``
  written as inline code got `blocked=True` from `check()` and then shipped
  completely unredacted from `sanitize()` -- a guard that correctly detects
  danger and then ships it anyway. `sanitize()` now also redacts inline spans
  that themselves match a flagged pattern (an unrelated safe inline snippet
  in the same message is left alone). 5 new tests (this module had none
  before), red-first.

### Added

- `tools/llm_scanner.py --api-key-env VAR`: reads the `--api-mode openai`
  bearer token from an environment variable instead of taking it literally on
  the command line, where it lands in shell history and is visible to any
  other user on the box via `ps`/the process list for as long as the scan
  runs. Mutually exclusive with `--api-key` (both still exist; `--api-key`'s
  help text now points at the env-var form). Resolution logic lives in a
  standalone `resolve_api_key()` so it is unit-testable without argparse or a
  network call; covered in `tests/test_llm_scanner_api_key_env.py` (6 tests,
  mutation-checked: reverting the fail-on-missing-env-var behavior turns 2 of
  them red).

### Fixed

- Translated ~20 leftover non-English code comments and docstrings across
  `tools/`, `labs/vulnllm/`, and `tests/` to English. These were missed by the
  earlier "translate the remaining non-English comments and docstrings" pass
  (`#35`, 2026-08-21) -- found by grepping comment lines for non-English
  diacritics, common words, and suffixes, distinguishing developer prose
  (translated) from the toolkit's intentional multilingual attack corpus and
  language-detection data (left as-is; non-English payloads are a
  documented, load-bearing part of the corpus, not a leak).
- `tools/prompt_injection_detector_ml.py`'s `build_default_anchors()` caught
  the anchor-building loop in a bare `except Exception: pass`, which would
  have silently dropped anchors for any reason with no trace.
  `load_attack_payloads()` already handles the one expected failure (a
  missing lab tree) with its own `[WARN]`, so the outer bare except was only
  ever going to hide a genuine bug in the loop body. Narrowed to
  `(AttributeError, TypeError)` with a `[WARN]` printed to stderr, matching
  the file's existing error-reporting style.
- `.github/workflows/ci.yml`'s advisory bandit job carried a comment dated
  2026-08-03 describing two findings (unvalidated `urlopen` scheme,
  `HTTPServer` defaulting to `0.0.0.0`) that `fix(security)` commit
  `7c1bbfc3` already fixed on 2026-08-21. Re-measured at the job's own `-ll`
  threshold: zero medium+ severity findings remain. Comment rewritten to
  reflect the current, re-verified state instead of the stale one.
- `.github/workflows/ci.yml`'s advisory mypy job carried a companion comment,
  also dated 2026-08-03, naming "7 real findings" (`Counter()` typed by
  typeshed as `Dict[K, int]` regardless of what it holds) that
  `fix(types)` already fixed on 2026-08-21. Re-measured 2026-09-14:
  `mypy tools/ --ignore-missing-imports` exits clean. Comment rewritten.
- `.coveragerc`'s `fail_under` floor had drifted below the measured coverage
  twice before, by this file's own account (30 vs a real 51%, then 45 vs a
  real 53%, each time ratcheted back up after the gap was noticed). Measured
  2026-09-14: 56%, a 6-point gap from the floor of 50 -- the same drift
  starting again. Ratcheted to 53, holding the file's own established
  3-point margin.

### Added

- `tests/test_owasp_id_consistency.py`: a mechanical regression gate for the
  OWASP LLM Top 10 2026 remap landed in `0.5.0`. Six test classes check every
  surface that names an OWASP ID (`labs/vulnllm/challenges/ch0X_*.py`,
  `tools/README.md`, `labs/vulnllm/README.md`, `huggingface-space/app.py`,
  `labs/rag-security/vulnerable_rag.py`, and two defense-module docstrings)
  against `tools/llm_scanner.py`'s `OWASP_MAP`/`OWASP_NAMES` as the single
  source of truth, instead of relying on a one-time manual sweep to keep
  them in sync. Mutation-checked: reverting any one of the six surfaces to
  its pre-remap ID turns the matching test red.
- `--model`/`-m` CLI flag on `labs/rag-security/vulnerable_rag.py`. The
  `MODEL` constant was hardcoded with no override, so anyone without exactly
  `llama3.2:3b` pulled could not run the lab without editing the source.
  Found while independently re-verifying the lab's leakage-rate claim below.
  Covered by `tests/test_vulnerable_rag_model_override.py` (3 tests, skips
  cleanly when chromadb/sentence-transformers are not importable).

### Fixed

- `labs/rag-security/README.md`'s "42% -> 0%" prompt-injection leakage claim
  had never been independently re-run since it was first measured -- it
  cited only the original run. Re-verified live 2026-09-14 against a
  freshly built isolated venv (chromadb 1.5.9, sentence-transformers 6.0.1)
  and a locally hosted Ollama model (`qwen2.5-coder:7b`, not the
  originally-documented `llama3.2:3b`): the `--setup` + `--attack` sequence
  reproduced 42%/0% exactly. Footnoted in the README next to the existing
  citation, alongside the model actually used, as evidence the result is
  not tied to one specific model.
- `labs/rag-security/requirements.txt` and `pyproject.toml`'s `[rag]` extra
  had `chromadb` and `sentence-transformers` completely unpinned -- no
  version floor at all. Pinned to `chromadb>=1.5.9` and
  `sentence-transformers>=6.0.1`, the versions actually installed and run
  above; commented in both files as a verified-working floor, not a
  security-vetted pin (the security-scanning tool available in this
  environment could not authenticate to check these packages for known
  vulnerabilities).

### Added (test coverage)

- `tests/test_vulnllm_console_encoding.py` covered two of `vulnllm.py`'s and
  `defense_demo.py`'s documented invocation shapes (the default menu, and
  `--all --auto -d expert`) end-to-end, but two more shapes named in
  `labs/vulnllm/README.md`'s own Quick Start -- `--challenge 1` (interactive)
  and `defense_demo.py --interactive` -- run a *different* code path
  (`run_interactive()` prints its own banner before the chat loop) that
  neither existing test touched. Added both, feeding closed stdin
  (`subprocess.DEVNULL`) so the already-handled `EOFError` exits the loop
  deterministically instead of the test depending on whatever stdin happens
  to be inherited from the runner. Currently green (the encoding fix already
  applies at `main()`'s entry point, before any code path branches), so this
  closes a coverage gap rather than a live bug -- mutation-checked by
  temporarily disabling `make_output_safe()` and confirming both existing
  and new tests go red with the exact `UnicodeEncodeError` this file's
  original fix addressed, then restoring.
- `labs/rag-security/vulnerable_rag.py`'s CLI remains structurally
  untested end-to-end in CI: it needs `chromadb` + `sentence-transformers`
  (not in the `[dev]` extra CI installs) and a running Ollama server (not
  available on a CI runner). Documented as a known, accepted limitation in
  the local audit notes rather than worked around with a mock that would
  stop testing the thing that actually broke before (a real vector-store +
  embedding-model + LLM round trip).

### Fixed (i18n)

- 8 of `labs/vulnllm/challenges/`'s 10 challenge files (all but ch08 and
  ch10) still had non-English text in their `description`, `objective`,
  `get_system_prompt()`, `get_default_response()`, or the `"response"`
  values inside `get_response_rules()` -- the simulated-LLM text a user
  actually sees on a successful exploit. An earlier translation pass had
  covered module docstrings, comments, and `owasp_id` fields, but never
  this layer. Translated all of it to English. Left untouched, on
  purpose: every `"pattern"` regex value and multilingual word list
  (e.g. `SecretWordFilter([..., "password", ...])`) -- these match
  against user-submitted attack text, and the attack corpus in
  `labs/vulnllm/attacks/*.py` is intentionally multilingual; translating
  the detection side would silently break non-English attack
  detection. Also translated two leftover non-English developer comments
  (`defenses/guards.py`, `defenses/instruction_hierarchy.py`) and
  `vulnllm.py`'s own `print_menu()` banner text, found along the way.
  Verified no test asserted on the exact strings changed; the suite
  passes unchanged (185 passed, 9 skipped, 1 xfailed).

## [0.5.0] -- 2026-09-06 -- OWASP LLM Top 10 2026 remap, OpenAI-compatible targets, and a scorer that stopped counting refusals as wins

### Changed

- `tools/llm_scanner.py`: `OWASP_MAP`/`OWASP_NAMES` remapped to the OWASP Top
  10 for LLM Applications 2026 edition (released 2026-08-04), re-derived from
  each chapter's actual content rather than relabeled -- e.g. `ch06`
  (Excessive Agency) now correctly points at `LLM03`, not the old `LLM06`.
- `tools/llm_scanner.py`: `check_success()` used to mark any response over
  100 characters as a successful attack unless it contained one of 8
  hardcoded English/non-English refusal words -- a live control-arm test (scan
  the same model through a deliberately hardened, well-engineered system
  prompt and see if the risk score actually drops) instead found the score
  going *up* (85 -> 94/100) because the hardened prompt made the model's
  polite customer-support redirects longer and less likely to contain those
  exact 8 words. Inspecting all 18 "successes" from that run: none of them
  contained the target secret or any actual malicious artifact -- all 18
  were the model asking a clarifying question or redirecting to its declared
  scope. A second, compounding root cause: the non-English refusal patterns were
  written with unaccented ASCII letters and never matched the model's actual
  accented output, so non-English refusals were invisible to the detector
  entirely.
  Fixed with a `_normalize()` step (lowercase + strip non-English diacritics
  before matching, so the existing ASCII patterns start working against
  real non-English text) and a new `DEFLECTION_PATTERNS` check that runs before
  the "any long non-refusal response is a success" fallback. Re-scoring the
  same two runs after the fix: weak system prompt 85 -> **51/100** (10/20,
  most now genuinely contain leaked content or a produced malicious
  artifact, checked by hand), hardened system prompt 94 -> **9/100** (2/20,
  both borderline). The scorer now moves in the right direction between a
  weak and a hardened target, which it did not before.
  TDD: `tests/test_llm_scanner_refusal_detection.py`, 15 new tests built
  from the real captured response text of that live run (not synthetic),
  mutation-checked (reverted the fix, confirmed all 13 relevant tests go
  red, reapplied). One known, explicitly `xfail`-marked gap remains:
  category-specific positive-artifact detection (e.g. a RAG-poisoning probe
  where the model declines by restating its own correct policy instead of
  asking a question) is not covered by this pass.
- `tools/llm_scanner.py`: added `--api-mode {ollama,openai}` and `--api-key`
  so the scanner can target any OpenAI-compatible `/chat/completions`
  endpoint, not just a local Ollama instance -- previously the wire format
  was hardcoded to Ollama's native `/api/chat`. Backward compatible: no flag
  given behaves exactly as before. Live-verified by pointing both code paths
  at the same local `qwen2.5:7b` model through Ollama's own OpenAI-compatible
  endpoint (proves the new path is genuinely endpoint-agnostic, not a
  relabeled copy of the Ollama-specific one).
  TDD: `tests/test_llm_scanner_target.py`, 6 new tests, all HTTP mocked.

## [0.4.1] -- 2026-09-06 -- the citation the 0.4.0 tag should have carried

`v0.4.0` shipped with `CITATION.cff` still naming **0.3.0**. That was corrected
on `main` after the release, which fixes the repository but not the artefact:
anyone citing the published `v0.4.0` tag still reads the wrong version out of
the file whose entire job is to name it.

A patch release is the only way that correction reaches the tag.

### Fixed

- `CITATION.cff` names 0.4.1 and is now checked mechanically against
  `pyproject.toml`, so a release cannot leave it behind again. The check
  compares the two versions directly rather than scanning for a leftover old
  string -- a scan only works between a bump and a release, and goes blind
  exactly when the tag catches up.

### Note on the version bump

The correcting commit was written as `fix(citation): ...`. Under conventional
commits a `fix` implies a patch release, and the release check reads it that
way. `docs(citation)` would have been the more accurate type for a
metadata-only change -- but the tag really did carry wrong metadata, so the
release is warranted on its own merits rather than only by commit-type
convention.

## [0.4.0] -- 2026-09-05 -- the security fix reaches the package

`0.3.0` is what `pip install wrg-ai-security-toolkit` has served since
2026-07-30. The URL-scheme validation and localhost-binding fix landed on
`main` on 2026-08-21 and touches three files that ship inside the
distribution (`tools/llm_firewall.py`, `tools/llm_scanner.py`,
`tools/prompt_injection_detector_ml.py`), so for fifteen days installing the
package got code without it. That gap is the reason this release exists; the
rest below had accumulated behind the same missing tag.

### Fixed -- security

- **URL scheme is validated before every fetch (bandit B310).** `urlopen`
  honours `file://`, `ftp://` and custom schemes, so a URL arriving from
  configuration is a local-file read waiting to happen. The endpoints default
  to localhost, but they are *parameters*, and this is a security toolkit --
  the check belongs in the code, not in a reviewer's memory. `_http_only()`
  now guards every `Request()`; all ten call sites were verified, none
  bypasses it.
- **Servers bind to localhost by default (bandit B104).** Both servers
  listened on every interface. A tool that quietly binds `0.0.0.0` turns
  "I ran it locally" into "I exposed it to the network".

### Fixed

- **Container types now match the values they already held (mypy 7 -> 0).**
  TF-IDF weights are floats but were accumulated into a bare `Counter`,
  which is int-valued, so `+= tf*idf` and `/= n` were type errors;
  `defaultdict(float)` is the exact equivalent and states the value type
  honestly. `DEFAULT_CONFIG` gained `dict[str, Any]` so reads stop
  inferring a union.
- **Quick Start now includes the clone step.** `llm-scanner` and
  `llm-firewall` import their attack corpus from `labs/vulnllm/`, which is
  not packaged, so they need an editable install. Installation said so;
  Quick Start sat above it and did not, and a reader who copied only the top
  block got `ModuleNotFoundError`.

### Added

- **A live in-browser demo.** A Hugging Face *Static* Space runs the prompt
  injection detector through Pyodide, so text pasted into a detector never
  leaves the visitor's browser. (Gradio Spaces now require a paid plan;
  gradio-lite would not boot -- `micropip` cannot resolve
  `huggingface-hub<1.0,>=0.33.5`, which has no pure-Python wheel -- so
  `index.html` drives Pyodide directly.)
- **Repository process scaffolding**: CODEOWNERS, PR template, issue
  templates, `FUNDING.yml`, `CITATION.cff`.
- **CI now crosses Python versions with an OS matrix** (ubuntu / windows /
  macos). The "stdlib only" claim had only ever been verified on one OS.
  Advisory `mypy` and `bandit` jobs were added alongside, plus a
  coverage-floor ratchet.

### Changed

- **Remaining non-English comments and docstrings translated to English.** Two
  passes; see the "Known gap" note below for what is deliberately still not
  English.

### Dependencies

- `gradio` (huggingface-space), `github/codeql-action`,
  `actions/checkout`, `actions/setup-python` bumps.

### Known gap

`labs/vulnllm/` still carries non-English text in attack payloads, challenge response
strings and regex alternatives. The regex alternatives are deliberate -- they
exist so non-English input matches -- and the language-detection tables,
country-specific PII fixtures and multilingual payload sets
are test data, not prose. The challenge *response* strings are prose and are
not yet translated.

## [0.3.0] -- 2026-07-30 -- first PyPI release, under a name that is ours

Version bumped rather than reusing 0.2.0. The `v0.2.0` tag points at `89fc5dd`,
six commits back, and predates everything below -- including the distribution
rename, which changes the name people install by. Shipping today's code under
yesterday's version number would make the tag lie about its contents.

This is the first release published to PyPI, through Trusted Publishing.

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

### Added

- **Release workflow using PyPI Trusted Publishing** (`.github/workflows/release.yml`).
  No API token: GitHub proves the workflow's identity to PyPI over OIDC. The
  first manual upload attempt had failed 403 against a stored project-scoped
  token that could not create a new project, on an account behind a lost
  authenticator — a credential living on one laptop can strand a release.
  `twine check` runs before upload, and the built artefact names are asserted to
  carry the prefix.

### Changed -- the demo stopped being a second detector

- **`huggingface-space/` runs the toolkit instead of reimplementing it.** It had
  its own regex table, its own TF-IDF and char-n-gram scoring, and its own copy
  of the trained model — 398 lines that had drifted into a *different detector*:
  9 rules in `tools/` against 17 in the demo, **zero rule names in common**,
  disagreeing on three of six sample inputs. The premise ("a Space cannot import
  `tools/`") was wrong: `tools` is the installable surface and the model ships
  as package data, so the Space just depends on the package. The 248 KB
  duplicate model is deleted, and the rule count and layer weights are read off
  the detector rather than typed into the results table.

### Changed -- the user-facing text is English

- The CLI surface, the lab, the guards, the challenge content and the test
  docstrings are English throughout: the detector's report, the lab framework,
  every guard `reason=` string, and the ~110 `explanation=` / `detection_hint=`
  fields a learner reads next to each technique.
- Deliberately still non-English, because it is data rather than presentation: the
  194 attack payloads, `BENIGN_SAMPLES` (the corpus the model is fitted on), the
  trained model JSON, the non-English trigram table, the perplexity stopword list,
  the tokenizer character classes, the non-English patterns in `content_policy`,
  `prompt_firewall`, `consistency_analyzer` and `llm_scanner`, and the test
  fixtures. Translating any of those would change detection behaviour, not
  wording.

### Fixed

- **A regression guard had gone blind.** `test_ai_l2_01` asserted
  `assertNotIn(<the old warning text>, stderr)`; translating that warning to
  English made the assertion trivially true, so it stayed green while detecting
  nothing. The sentinel is now read from the source, and the missing positive
  control was added — an unknown guard name must reach the fallback. Deleting
  the warning outright now fails two tests; before, it failed none.
- The HF Space's `requirements.txt` names the prefixed distribution, so the
  Space installs this package rather than resolving to the other one.
- Three build warnings, now none: the deprecated `license` TOML table and
  `License ::` classifier (both scheduled for removal 2027-02-18) replaced by an
  SPDX expression, and `tools.models` declared explicitly so setuptools stops
  warning that a shipped file might be ignored.
- The repository had contradicted itself about `huggingface-space/`: three
  surfaces described it as deployed and one as not. They now agree.

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
  U+2192; on a single-byte Windows console the command printed ~30 lines and then
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
- **The message was not in English in an English repository.** README, badges,
  CHANGELOG and commits are all English, so `pip install` users were told
  a non-English "not found" message. It is English now. Comments and docstrings stay
  non-English; those are developer notes and the distinction is deliberate. The
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

## [2026-05-11] -- ASCII diacritic restoration (Batch 2)

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
