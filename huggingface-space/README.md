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

Hybrid ML detector combining Regex (<!-- METRIC:hf_rule_count -->9<!-- /METRIC:hf_rule_count --> rules) + TF-IDF + Char N-gram for detecting prompt injection attacks.

**Features:**
- Zero external ML dependencies (Python stdlib only)
- Pre-trained on 194 real attack payloads
- Three-layer detection: pattern matching + statistical analysis + character similarity
- OWASP LLM Top 10 mapped

Part of [AI Security Toolkit](https://github.com/WRG-11/ai-security-toolkit)


## Relationship to the main toolkit

This Space **runs the toolkit**, it does not reimplement it. `requirements.txt`
installs the package from the repository and `app.py` imports the same
`HybridDetector` you get from `pip install`; the trained model arrives with the
package as package data. So what you see here is what the downloaded tool does.

That was not always true, and it is worth recording why the arrangement changed.
The Space used to carry its own regex table and its own copy of the model,
because "a Space cannot import `tools/`". Measured 2026-07-29 and again
2026-07-30, the two had become **different detectors**: 9 rules in the toolkit,
17 here, **no rule names in common**, disagreeing on three of six sample inputs.
A prompt this demo flagged might not be flagged by the tool you installed.

The premise was wrong. `tools` is the installable surface and the model ships
with it, so the Space can just depend on the package —
`tests/test_wheel_install.py` drives exactly that path from a real wheel.
`tests/test_hf_space_parity.py` no longer measures drift between two
implementations; it pins that the second implementation stays gone.

## Honest limits

The score is a hybrid heuristic, not a verdict. On a 5-fold holdout it reaches
F1 0.90 at the default threshold, with recall 0.83 and precision 0.98 — about
one attack in six still gets through. The measurements and the method are in the
[README](https://github.com/WRG-11/ai-security-toolkit#how-the-detector-is-measured).
