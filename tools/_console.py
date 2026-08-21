"""Make console output resilient to non-ASCII text.

Measured 2026-07-29 on a Windows (cp1254) console:

    python tools/llm_scanner.py --list-probes
    ...
    UnicodeEncodeError: 'charmap' codec can't encode character '\\u2192'

The command died after printing ~30 probes and returned exit 1 -- a successful
informational command turning into a red CI step. The cause was data: one probe
name contains U+2192 instead of "->". Trimming the data would have been the
wrong fix; what broke was the console encoding.

A milder form of the same class, the same day in the same repo: the two [WARN]
lines in prompt_injection_detector_ml.py were written with Turkish accents and
mojibaked on that console (`Sald\\u00fdr\\u00fd k\\u00fdt\\u00fdphanesi`), while
every other user-facing message in the file was already folded to ASCII.

`reconfigure` is used rather than wrapping in a `TextIOWrapper`: the wrapper
closes the buffer underneath it when collected, corrupting a shared stdout.
"""
from __future__ import annotations

import sys


def make_output_safe() -> None:
    """Switch stdout/stderr to UTF-8 with ``errors='replace'``.

    Idempotent and quiet: it does nothing when the encoding is already fine,
    and returns silently when a stream does not support ``reconfigure``
    (redirected or custom streams) -- an output-hygiene helper must never take
    down the program it is protecting.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            # Closed or exotic stream. We do not take the caller down over cosmetics.
            pass


__all__ = ["make_output_safe"]
