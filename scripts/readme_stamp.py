#!/usr/bin/env python3
"""Stamp README's countable claims from the code itself.

README said "21 defense modules" while the code had 27. Nobody had done
anything wrong -- defenses were added and a number in prose stayed where it
was. That is what hand-written counts do, and the repo has already been bitten
by it more than once.

Each metric below resolves from the source of truth and is written between
HTML-comment markers, so the surrounding sentence stays editable:

    - <!-- METRIC:defense_count -->27<!-- /METRIC:defense_count --> defense modules

Usage:
    python scripts/readme_stamp.py            # rewrite markers in place
    python scripts/readme_stamp.py --check    # CI gate: exit 1 on drift

stdlib only, matching the rest of the toolkit -- this runs in CI where nothing
is installed.
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

# What counts as a "defense module" is a judgement, so it is spelled out here
# rather than left to a regex. Three kinds of class live in defenses/ and only
# one of them is a defense:
#
#   - data carriers: GuardResult, PolicyRule, SessionState -- hold state
#   - abstract bases: InputGuard, OutputGuard -- the interface, not an
#     implementation of it (both are ABCs in base.py)
#   - private helpers: _TFIDFModel, _CharNgramVectorizer -- internals of one
#     guard, not guards themselves
#
# A first pass counted 31 by excluding only the data carriers, which would
# have swapped one wrong number in the README for another.
_DATA_CARRIER_SUFFIXES = ("Result", "Rule", "State")


def _is_defense_class(node: ast.ClassDef) -> bool:
    if node.name.startswith("_"):
        return False
    if node.name.endswith(_DATA_CARRIER_SUFFIXES):
        return False
    # Abstract bases inherit ABC directly; concrete guards inherit those bases.
    if any(getattr(b, "id", None) == "ABC" for b in node.bases):
        return False
    return True


def count_defense_modules(root: Path) -> int:
    """Concrete guard/filter/detector classes under labs/vulnllm/defenses/."""
    total = 0
    for path in sorted((root / "labs" / "vulnllm" / "defenses").glob("*.py")):
        if path.name == "__init__.py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        total += sum(
            1
            for node in tree.body
            if isinstance(node, ast.ClassDef) and _is_defense_class(node)
        )
    return total


def count_attack_payloads(root: Path) -> int:
    """Payloads the detector is actually trained on.

    Imported rather than pattern-matched: the loader assembles them from
    several modules, so counting occurrences of a literal would drift from
    what the model really sees.
    """
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "labs" / "vulnllm"))
    from tools.prompt_injection_detector_ml import load_attack_payloads

    return len(load_attack_payloads())


def count_challenges(root: Path) -> int:
    return len(list((root / "labs" / "vulnllm" / "challenges").glob("ch*.py")))


def count_test_modules(root: Path) -> int:
    return len(list((root / "tests").glob("test_*.py")))


METRICS = {
    "defense_count": count_defense_modules,
    "attack_payload_count": count_attack_payloads,
    "challenge_count": count_challenges,
    "test_module_count": count_test_modules,
}


def _read(path: Path) -> str:
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def _write(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def _marker_re(name: str) -> re.Pattern[str]:
    esc = re.escape(name)
    return re.compile(
        r"<!-- METRIC:" + esc + r" -->(.*?)<!-- /METRIC:" + esc + r" -->",
        re.DOTALL,
    )


def stamp_text(text: str, root: Path) -> tuple[str, list[tuple[str, str, str]]]:
    """Return (rewritten, drift) with drift as (metric, old, new) per stale block."""
    drift: list[tuple[str, str, str]] = []
    out = text
    for name, resolver in METRICS.items():
        value = str(resolver(root))
        regex = _marker_re(name)

        def _repl(m: re.Match[str], _n: str = name, _v: str = value) -> str:
            if m.group(1) != _v:
                drift.append((_n, m.group(1), _v))
            return f"<!-- METRIC:{_n} -->{_v}<!-- /METRIC:{_n} -->"

        out = regex.sub(_repl, out)
        if not regex.search(text):
            print(f"warning: marker {name!r} not found in README", file=sys.stderr)
    return out, drift


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit 1 on drift, do not write")
    args = parser.parse_args(argv)

    if not README.exists():
        print(f"error: {README} not found", file=sys.stderr)
        return 2

    original = _read(README)
    rewritten, drift = stamp_text(original, REPO_ROOT)
    summary = ", ".join(f"{n}={r(REPO_ROOT)}" for n, r in METRICS.items())

    if args.check:
        if drift:
            for name, old, new in drift:
                print(f"DRIFT {name}: README says {old!r}, code says {new!r}")
            print(f"{len(drift)} marker(s) stale -- run `python scripts/readme_stamp.py`.")
            return 1
        print(f"README metrics in sync ({summary}).")
        return 0

    if rewritten != original:
        _write(README, rewritten)
        print(f"stamped README: {summary} ({len(drift)} block(s) updated)")
    else:
        print(f"README already in sync ({summary}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
