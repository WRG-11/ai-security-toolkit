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
