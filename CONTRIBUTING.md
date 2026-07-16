# Contributing

`ai-security-toolkit` is a single-author portfolio of offensive + defensive
AI/LLM security tools, labs, CTF writeups, and research. Contributions are
welcome for tools, labs, and writeups, but review time is limited and scope
control matters.

## Before You Start

- Search existing issues and pull requests first.
- Open an issue before starting larger work or new tool additions.
- Small docs fixes, typo corrections, and CTF writeup additions can go
  straight to PR.

## Triage Expectations

There is no guaranteed SLA. For small PRs, expect a best-effort review when
the maintainer is active. For larger proposals (new tool, new lab), an
issue may sit until there is a clear use case or maintainer need.

## Local Dev Setup

```bash
git clone https://github.com/WRG-11/ai-security-toolkit.git
cd ai-security-toolkit
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
# tools/ and labs/vulnllm/ are stdlib-only (nothing to install).
# labs/rag-security/ needs extras:
pip install -r labs/rag-security/requirements.txt
```

## Bar for Accepting a PR

- New tools must include a usage example + README entry.
- New labs must include a README + intended attack/defense scope.
- New CTF writeups must redact any leaked secrets and respect platform ToS.
- Update README sections (Tools / Labs / CTF Writeups) when adding new
  content.
- Keep the diff at or below 500 LOC unless prearranged in an issue (this
  repo accepts larger PRs than typical because tools / labs are inherently
  larger than library helpers).
- Stdlib-only discipline for core tools (`tools/`); labs may have additional
  requirements declared in their own `requirements.txt`.

## Commit Messages

Use clear, concise commit messages. Conventional commit style is preferred:

- `feat(tools): add new prompt-injection probe class`
- `feat(labs): add new defense module`
- `feat(ctf): add Gandalf level 8 writeup`
- `docs: update tool comparison table`

## Disclosure Discipline

This is an offensive security toolkit. Contributors must:

- Only test against systems they own or have explicit written authorization.
- Never include real victim data (PII, real credentials, real session IDs).
- Use mock targets, test fixtures, and synthetic data in examples.
- Respect platform Terms of Service for CTF challenges.
- Redact secrets / tokens / endpoints in CTF writeups even if they have
  expired (preserves OPSEC habit + protects against future revival).

## Security Issues

Do not open public issues for security vulnerabilities in this toolkit
itself. Use GitHub Security Advisories:

- https://github.com/WRG-11/ai-security-toolkit/security/advisories

For vulnerabilities discovered in OTHER systems using these tools, follow
the upstream maintainer's responsible disclosure policy.
