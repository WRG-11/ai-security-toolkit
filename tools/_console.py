"""Konsol cikisini ASCII-disi metne dayanikli hale getir.

2026-07-29 olcumu, Windows (cp1254) konsolunda:

    python tools/llm_scanner.py --list-probes
    ...
    UnicodeEncodeError: 'charmap' codec can't encode character '\\u2192'

Komut ~30 probe bastiktan sonra oluyordu ve exit 1 donuyordu -- yani basarili
bir bilgilendirme komutu, CI'da kirmizi bir adim. Sebep veri: bir probe adinda
"->" yerine U+2192 var. Veriyi kirpmak yanlis cozum olurdu; kiran sey konsol
kodlamasi.

Ayni sinifin daha yumusak hali, ayni gun ayni depoda: prompt_injection_
detector_ml.py'deki iki [UYARI] satiri Turkce aksanlarla yazilmisti ve ayni
konsolda mojibake oluyordu (`Sald\\u00fdr\\u00fd k\\u00fdt\\u00fdphanesi`),
dosyadaki diger tum kullanici-metinleri zaten ASCII'ye katlanmisken.

`reconfigure` kullanilir, `TextIOWrapper` sarmalanmaz: sarmalayici cop
toplandiginda altindaki tamponu kapatir ve paylasilan stdout'u bozar.
"""
from __future__ import annotations

import sys


def make_output_safe() -> None:
    """stdout/stderr'i UTF-8 + errors='replace' yap.

    Idempotent ve sessiz: kodlama zaten uygunsa hicbir sey yapmaz, konsol
    reconfigure'u desteklemiyorsa (yonlendirilmis ozel akislar) sessizce
    gecer -- bir cikti-hijyeni yardimcisi, korudugu programi dusuremez.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            # Kapali/ozel akis. Cikti kozmetigi icin cagirani dusurmeyiz.
            pass


__all__ = ["make_output_safe"]
