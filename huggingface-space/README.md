---
title: Prompt Injection Detector
emoji: 🛡️
colorFrom: red
colorTo: yellow
sdk: gradio
sdk_version: 5.31.0
app_file: app.py
pinned: false
license: mit
short_description: Hybrid ML detector for AI/LLM prompt injection attacks
---

# Prompt Injection Detector

Hybrid ML detector combining Regex (17 rules) + TF-IDF + Char N-gram for detecting prompt injection attacks.

**Features:**
- Zero external ML dependencies (Python stdlib only)
- Pre-trained on 194 real attack payloads
- Three-layer detection: pattern matching + statistical analysis + character similarity
- OWASP LLM Top 10 mapped

Part of [AI Security Toolkit](https://github.com/WRG-11/ai-security-toolkit)


## Relationship to the main toolkit

This Space is deployed separately and cannot import `tools/`, so two things
are copies rather than references: the trained model JSON and the regex rule
table.

Be aware that the rule tables are **not the same detector**. Measured
2026-07-29: `tools/prompt_injection_detector.py` carries 9 rules, this app
carries 17, and they share no rule names. On six sample inputs the two
disagreed on three — a prompt this demo flags may not be flagged by the
downloaded tool, and vice versa.

`tests/test_hf_space_parity.py` in the main repo pins the model copies as
byte-identical and measures the rule divergence so it cannot grow unnoticed.
Merging the two tables is a separate job: the regex layer feeds the hybrid
detector's weighted score, so changing it requires re-running the threshold
calibration.
