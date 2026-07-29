#!/usr/bin/env python3
"""Stamp countable claims in the docs from the code itself.

README said "21 defense modules" while the code had 27. Nobody had done
anything wrong -- defenses were added and a number in prose stayed where it
was. That is what hand-written counts do, and the repo has already been bitten
by it more than once.

Each metric below resolves from the source of truth and is written between
HTML-comment markers, so the surrounding sentence stays editable:

    - <!-- METRIC:defense_count -->27<!-- /METRIC:defense_count --> defense modules

Two files are stamped, not one. The first version covered README.md only, and
`tools/README.md` -- describing the same three tools -- drifted underneath it:
on 2026-07-29 it still advertised the retracted "100% F1 score on test set",
"17 rules" for a 9-rule engine, "88 benign samples" for 80, and line counts
~140 lines short. The fix had been applied one table away from the defect.

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
TOOLS_README = REPO_ROOT / "tools" / "README.md"
HF_README = REPO_ROOT / "huggingface-space" / "README.md"

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


def count_benign_samples(root: Path) -> int:
    """BENIGN_SAMPLES length. tools/README claimed 88; it is 80."""
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "labs" / "vulnllm"))
    from tools.prompt_injection_detector_ml import BENIGN_SAMPLES

    return len(BENIGN_SAMPLES)


def _count_list_literal(path: Path, name: str) -> int:
    """Length of a module-level list literal, read without importing.

    AST rather than import because the HF demo pulls in gradio, which is not
    installed in the docs job -- and because a doc stamper should not need to
    execute the thing it documents.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == name:
            return len(node.value.elts)
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == name:
            return len(node.value.elts)
    raise AssertionError(f"{path.name} icinde {name} bulunamadi")


def count_regex_rules(root: Path) -> int:
    """v0.1 regex rules in tools/. tools/README said 17 -- that is the HF
    demo's count, for a different rule table, in a different file."""
    return _count_list_literal(root / "tools" / "prompt_injection_detector.py", "_RULES")


def count_hf_rules(root: Path) -> int:
    """The Gradio demo's separate rule table."""
    return _count_list_literal(root / "huggingface-space" / "app.py", "RULES")


def _line_count(path: Path) -> int:
    with open(path, encoding="utf-8", newline="") as fh:
        return sum(1 for _ in fh)


def count_lines_ml(root: Path) -> int:
    return _line_count(root / "tools" / "prompt_injection_detector_ml.py")


def count_lines_scanner(root: Path) -> int:
    return _line_count(root / "tools" / "llm_scanner.py")


def count_lines_firewall(root: Path) -> int:
    return _line_count(root / "tools" / "llm_firewall.py")


def count_challenges(root: Path) -> int:
    return len(list((root / "labs" / "vulnllm" / "challenges").glob("ch*.py")))


def count_test_modules(root: Path) -> int:
    return len(list((root / "tests").glob("test_*.py")))


def coverage_floor(root: Path) -> int:
    """The enforced floor from .coveragerc.

    README used to quote a measured percentage ("36%") and .coveragerc's own
    comment quoted another ("35%"); the real figure on 2026-07-29 was 51%.
    A measured percentage moves with every commit and cannot be resolved
    without running the suite, so what gets stamped is the number that is
    actually enforced -- `coverage report` fails below it.
    """
    text = (root / ".coveragerc").read_text(encoding="utf-8")
    match = re.search(r"^fail_under\s*=\s*(\d+)", text, re.MULTILINE)
    if not match:
        raise AssertionError(".coveragerc icinde fail_under bulunamadi")
    return int(match.group(1))


METRICS = {
    "defense_count": count_defense_modules,
    "attack_payload_count": count_attack_payloads,
    "benign_sample_count": count_benign_samples,
    "regex_rule_count": count_regex_rules,
    "hf_rule_count": count_hf_rules,
    "lines_ml": count_lines_ml,
    "lines_scanner": count_lines_scanner,
    "lines_firewall": count_lines_firewall,
    "challenge_count": count_challenges,
    "test_module_count": count_test_modules,
    "coverage_floor": coverage_floor,
}

# Which metrics each file is expected to carry. Explicit, because "missing
# marker" has to be distinguishable from "this metric does not belong here" --
# otherwise the check either nags about irrelevant metrics or goes quiet when
# a real one is deleted.
TARGETS: dict[Path, tuple[str, ...]] = {
    README: (
        "defense_count",
        "attack_payload_count",
        "challenge_count",
        "test_module_count",
        "lines_ml",
        "lines_scanner",
        "lines_firewall",
        "coverage_floor",
    ),
    TOOLS_README: (
        "attack_payload_count",
        "benign_sample_count",
        "regex_rule_count",
        "lines_ml",
        "lines_scanner",
        "lines_firewall",
    ),
    # The Space card. It is a third copy of the same claims, rendered on a
    # page most readers reach before the repo -- and it carried the fourth
    # hand-typed "17 rules" in a repo that had already fixed the other three.
    HF_README: ("hf_rule_count",),
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


def stamp_text(
    text: str, root: Path, names: tuple[str, ...]
) -> tuple[str, list[tuple[str, str, str]]]:
    """Return (rewritten, drift) with drift as (metric, old, new) per stale block.

    A metric with no marker counts as drift. It used to print a warning to
    stderr and leave the drift list empty, so `--check` exited 0: deleting a
    marker silently switched that metric off, and the job stayed green while
    the number it guards drifted freely. The whole point of this script is
    that a countable claim cannot rot unnoticed -- an unstamped one is exactly
    that, so it has to fail rather than warn.
    """
    drift: list[tuple[str, str, str]] = []
    out = text
    for name in names:
        value = str(METRICS[name](root))
        regex = _marker_re(name)

        if not regex.search(text):
            drift.append((name, "<no marker>", value))
            continue

        def _repl(m: re.Match[str], _n: str = name, _v: str = value) -> str:
            if m.group(1) != _v:
                drift.append((_n, m.group(1), _v))
            return f"<!-- METRIC:{_n} -->{_v}<!-- /METRIC:{_n} -->"

        out = regex.sub(_repl, out)
    return out, drift


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit 1 on drift, do not write")
    args = parser.parse_args(argv)

    for path in TARGETS:
        if not path.exists():
            print(f"error: {path} not found", file=sys.stderr)
            return 2

    total_drift = 0
    written = 0
    for path, names in TARGETS.items():
        original = _read(path)
        rewritten, drift = stamp_text(original, REPO_ROOT, names)
        rel = path.relative_to(REPO_ROOT)

        if args.check:
            for name, old, new in drift:
                print(f"DRIFT {rel}:{name}: says {old!r}, code says {new!r}")
            total_drift += len(drift)
            continue

        if drift and any(old == "<no marker>" for _, old, _ in drift):
            for name, old, new in drift:
                if old == "<no marker>":
                    print(f"error: {rel} has no {name!r} marker "
                          f"(value {new!r}) -- add it by hand", file=sys.stderr)
            total_drift += 1
            continue

        if rewritten != original:
            _write(path, rewritten)
            written += 1
            print(f"stamped {rel}: {len(drift)} block(s) updated")
        else:
            print(f"{rel} already in sync")

    summary = ", ".join(f"{n}={METRICS[n](REPO_ROOT)}" for n in sorted(METRICS))

    if args.check:
        if total_drift:
            print(f"{total_drift} marker(s) stale -- run `python scripts/readme_stamp.py`.")
            return 1
        print(f"docs metrics in sync ({summary}).")
        return 0

    return 1 if total_drift else 0


if __name__ == "__main__":
    raise SystemExit(main())
