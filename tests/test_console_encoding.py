"""Dar kodlamali bir konsolda ciktinin hayatta kalmasi.

2026-07-29 olcumu, Windows cp1254 konsolunda:

    python tools/llm_scanner.py --list-probes
    ... ~30 satir ...
    UnicodeEncodeError: 'charmap' codec can't encode character '\\u2192'
    exit 1

Basarili bir bilgilendirme komutu, verinin icindeki tek bir "->" oku yuzunden
yarida oluyor ve BASARISIZ raporluyordu.

Kodlama ortamdan gelir, bu yuzden test de ortami zorlar: PYTHONIOENCODING ile
cp1254 dayatilir, boylece kosul Linux CI'da da uretilir -- yoksa bu regresyon
yalnizca bir gelistiricinin Windows makinesinde gorunurdu.
"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SCANNER = _ROOT / "tools" / "llm_scanner.py"


def _run_with_encoding(args: list[str], encoding: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONIOENCODING=encoding)
    return subprocess.run(
        [sys.executable, str(_SCANNER), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=str(_ROOT),
    )


class NarrowConsoleTest(unittest.TestCase):
    def test_list_probes_survives_a_cp1254_console(self):
        proc = _run_with_encoding(["--list-probes"], "cp1254")
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr[-400:]}")
        self.assertNotIn("UnicodeEncodeError", proc.stderr)

    def test_list_probes_prints_every_probe_not_just_the_ascii_prefix(self):
        """Varlik kontrolu yetmez: eski hal de ilk ~30 satiri basiyordu.

        Olculen sey, ciktinin BASLIKTA vaat edilen sayiya ulasmasi -- yani
        kirilma noktasindan sonrasinin da geldigi.
        """
        proc = _run_with_encoding(["--list-probes"], "cp1254")
        lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("  [")]
        header = proc.stdout.splitlines()[0]
        promised = int("".join(ch for ch in header if ch.isdigit()))
        self.assertEqual(
            len(lines),
            promised,
            f"baslik {promised} probe vaat etti, {len(lines)} satir basildi",
        )

    def test_utf8_console_is_unaffected(self):
        """Duzeltme dar kodlamayi kurtarirken genis olani bozmamali."""
        proc = _run_with_encoding(["--list-probes"], "utf-8")
        self.assertEqual(proc.returncode, 0, f"stderr: {proc.stderr[-400:]}")


if __name__ == "__main__":
    unittest.main()
