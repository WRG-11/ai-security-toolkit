# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest commit on `main` | Yes |
| Older commits / forks | No |

There are no tagged releases yet, so `main` is the only supported ref.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
responsibly.

**Do not open a public issue.**

**Use GitHub Security Advisories** (private vulnerability disclosure):

- https://github.com/WRG-11/ai-security-toolkit/security/advisories/new

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected surface (see the scope table below)
- Potential impact
- Suggested fix (if any)

## Disclosure Timeline

We follow a 90-day responsible disclosure timeline:

1. **Day 0**: Vulnerability reported via GitHub Security Advisories
2. **Day 1-7**: Acknowledgment sent to reporter
3. **Day 1-90**: Fix developed and tested
4. **Day 90**: Public disclosure (coordinated with reporter)

## Scope

In scope — everything this repository publishes and someone else can run:

| Surface | Why it is in scope |
|---|---|
| `tools/llm_firewall.py` | Middleware other people put in front of their own LLM |
| `tools/llm_scanner.py` | Sends attacker-shaped traffic to a target the user names |
| `tools/prompt_injection_detector_ml.py`, `tools/prompt_injection_detector.py` | The detection engine; a bypass is a finding |
| `tools/models/injection_model.json` | Ships as package data and is loaded at startup |
| `huggingface-space/` | The Gradio demo — a web UI that renders attacker-chosen input, wherever it is run |
| `labs/` | Deliberately vulnerable teaching code — see the qualification below |
| `ctf-writeups/` | Solver scripts that talk to third-party endpoints |
| `scripts/`, `.github/workflows/` | Repository tooling, including anything that runs on untrusted PR content |

The previous version of this list named three files and `labs/`. It predated
the Gradio demo, the packaged model, the CI workflows and the scripts
directory — so a web UI that renders untrusted input, and the workflows that
run on untrusted pull requests, were both outside the stated scope.

**What counts as a finding in a detection tool.** A detection *gap* is in
scope: a payload shaped to slip past the firewall or the detector, an input
that makes the scanner report a clean result without having actually probed,
or a way to make a tool exit 0 when it should not. So is a divergence between
the CLI detector and the Gradio demo — the two are separate implementations of
the same idea, and someone may reasonably try the demo and then install the
tool expecting the same answer.

**`labs/` is intentionally vulnerable, and that is not the finding.** The
challenges exist to be exploited; solving one is the point, not a report. What
*is* in scope there: a lab escaping its own boundary — writing outside its
directory, executing something the challenge did not intend, or reaching the
network while claiming to run in mock mode.

## Out of Scope

- Third-party dependencies (report to upstream maintainers)
- Social engineering attacks
- Denial of service attacks against hosted instances
- Successfully solving a `labs/vulnllm/` challenge as designed
- The CTF target platforms themselves (Gandalf, Agent ODIN, Prompt Airlines) —
  report those to their owners, not here
