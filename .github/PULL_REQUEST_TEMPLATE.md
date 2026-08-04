<!--
Read CONTRIBUTING.md first, especially "Bar for Accepting a PR" and
"Disclosure Discipline". The checklist below mirrors both so a reviewer
doesn't have to cross-reference a second document.
-->

## What this changes

## Checklist

- [ ] Diff is at or below 500 LOC, or a prearranged exception is linked
- [ ] `tools/` changes stay stdlib-only; new deps are scoped to a lab's own
      `requirements.txt` / a pyproject extra, not core
- [ ] New tool: usage example + README entry included
- [ ] New lab: README + intended attack/defense scope included
- [ ] New CTF writeup: secrets/tokens/endpoints redacted (even if expired),
      platform ToS respected
- [ ] No real victim data (PII, real credentials, real session IDs) --
      mock targets / synthetic data only
- [ ] README sections (Tools / Labs / CTF Writeups) updated if scope changed
- [ ] `pytest -q` green
- [ ] `ruff check .` clean
