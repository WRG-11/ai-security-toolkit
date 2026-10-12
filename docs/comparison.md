# How it compares

Where this toolkit falls short is listed in the [README](../README.md#limits). This page
puts it next to the frameworks most people reach for first.

| Framework | Surface | Language | Setup | Best for |
|---|---|---|---|---|
| **ai-security-toolkit** | Tools + labs + CTF + research | Python stdlib only | `git clone` | Self-contained practitioner kit, education, zero-dep CI |
| [PyRIT](https://github.com/Azure/PyRIT) (Microsoft) | Risk identification framework | Python + Azure SDKs | `pip install + cloud auth` | Microsoft-stack red teaming at scale |
| [Garak](https://github.com/NVIDIA/garak) (NVIDIA) | LLM vulnerability scanner | Python + provider SDKs | `pip install + API keys` | Academic + automated probing |
| [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) (NVIDIA) | Conversational AI guardrails | Python + Colang DSL | `pip install + LLM provider` | Production conversational guardrails |
| [Lakera Gandalf](https://gandalf.lakera.ai/) | CTF + Lakera-hosted detection | Web platform | Browser | Public CTF (no tools to install) |

## When to reach for ai-security-toolkit

- You want a zero-dep Python kit that runs in any sandbox (CI minutes, a locked-down corporate environment)
- You are learning AI security with hands-on labs (mock mode needs no API key)
- You want documented techniques beyond stock framework probes
- You need a comparison baseline before adopting PyRIT, Garak or NeMo

If you need enterprise-scale fleet probing, reach for PyRIT. If you need an extensive
academic-style scanner, reach for Garak. If you need conversational guardrails as a
service, reach for NeMo. Reach for ai-security-toolkit when you want a small, hackable,
MIT-licensed kit you can read end-to-end in an afternoon.

## Framework techniques referenced

10 attack payloads are tagged to a NVIDIA Garak probe module, 6 to a Microsoft PyRIT
converter or strategy. To recount:

```bash
git grep -oE '"garak:[^"]*"' labs/vulnllm/attacks/*.py | wc -l
git grep -oE '"pyrit:[^"]*"' labs/vulnllm/attacks/*.py | wc -l
```

This is provenance for the attack corpus, not a runtime integration or a test suite run
against either framework. NeMo Guardrails is not referenced in the corpus; all three
appear only in the comparison table above.
