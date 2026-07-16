# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Use GitHub Security Advisories** (private vulnerability disclosure):

- https://github.com/WRG-11/ai-security-toolkit/security/advisories

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Disclosure Timeline

We follow a 90-day responsible disclosure timeline:

1. **Day 0**: Vulnerability reported via GitHub Security Advisories
2. **Day 1-7**: Acknowledgment sent to reporter
3. **Day 1-90**: Fix developed and tested
4. **Day 90**: Public disclosure (coordinated with reporter)

## Scope

The following components are in scope for security reports:

- `tools/llm_firewall.py` — AI security firewall
- `tools/llm_scanner.py` — OWASP LLM Top 10 scanner
- `tools/prompt_injection_detector_ml.py` — ML-based prompt injection detection
- `labs/` — Security lab environments

## Out of Scope

- Third-party dependencies (report to upstream maintainers)
- Social engineering attacks
- Denial of service attacks against hosted instances
