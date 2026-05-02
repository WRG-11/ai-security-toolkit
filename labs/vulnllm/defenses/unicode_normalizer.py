"""
Module #15 — Unicode Normalizer

Pipeline'da ILK guard olmali — diger guard'lar normalize edilmis metni gorur.
Zero-width karakter strip, NFKC normalizasyon, homoglyph tespiti.
"""

import re
import unicodedata
from .base import InputGuard, GuardResult


# Latin ↔ Kiril homoglyph tablosu (en yaygin 30)
CONFUSABLES: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а → Latin a
    "\u0435": "e",  # Cyrillic е → Latin e
    "\u043e": "o",  # Cyrillic о → Latin o
    "\u0440": "p",  # Cyrillic р → Latin p
    "\u0441": "c",  # Cyrillic с → Latin c
    "\u0443": "y",  # Cyrillic у → Latin y (visual)
    "\u0456": "i",  # Cyrillic і → Latin i
    "\u0445": "x",  # Cyrillic х → Latin x
    "\u04bb": "h",  # Cyrillic һ → Latin h
    "\u0432": "b",  # Cyrillic в → Latin b (visual)
    "\u043c": "m",  # Cyrillic м → Latin m (visual)
    "\u043d": "h",  # Cyrillic н → Latin h (visual)
    "\u0442": "t",  # Cyrillic т → Latin t (visual)
    "\u0410": "A",  # Cyrillic А → Latin A
    "\u0412": "B",  # Cyrillic В → Latin B
    "\u0415": "E",  # Cyrillic Е → Latin E
    "\u041a": "K",  # Cyrillic К → Latin K
    "\u041c": "M",  # Cyrillic М → Latin M
    "\u041d": "H",  # Cyrillic Н → Latin H
    "\u041e": "O",  # Cyrillic О → Latin O
    "\u0420": "P",  # Cyrillic Р → Latin P
    "\u0421": "C",  # Cyrillic С → Latin C
    "\u0422": "T",  # Cyrillic Т → Latin T
    "\u0425": "X",  # Cyrillic Х → Latin X
}

# Zero-width ve gorunmez karakterler
INVISIBLE_CHARS = set([
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
    "\u2060",  # Word Joiner
    "\u2061",  # Function Application
    "\u2062",  # Invisible Times
    "\u2063",  # Invisible Separator
    "\u2064",  # Invisible Plus
    "\ufeff",  # BOM / Zero Width No-Break Space
    "\u00ad",  # Soft Hyphen
    "\u034f",  # Combining Grapheme Joiner
    "\u061c",  # Arabic Letter Mark
    "\u115f",  # Hangul Choseong Filler
    "\u1160",  # Hangul Jungseong Filler
    "\u17b4",  # Khmer Vowel Inherent Aq
    "\u17b5",  # Khmer Vowel Inherent Aa
    "\u180e",  # Mongolian Vowel Separator
])


class UnicodeNormalizer(InputGuard):
    """
    Pipeline'in ilk guard'i — input'u normalize eder.
    1. NFKC normalizasyon
    2. Zero-width / gorunmez karakter strip
    3. Homoglyph (Kiril/Latin konfuzyon) tespiti
    4. RTL override karakter tespiti
    """
    name = "UnicodeNormalizer"

    def __init__(self, block_on_suspicious: bool = True):
        self.block_on_suspicious = block_on_suspicious

    def normalize(self, text: str) -> str:
        """Metni normalize et — diger guard'lar bu versiyonu gorur."""
        # 1. NFKC normalizasyon
        result = unicodedata.normalize("NFKC", text)
        # 2. Gorunmez karakter strip
        result = "".join(c for c in result if c not in INVISIBLE_CHARS)
        # 3. Homoglyph normalizasyon
        result = "".join(CONFUSABLES.get(c, c) for c in result)
        return result

    def _detect_invisible(self, text: str) -> list[str]:
        """Gorunmez karakter tespit et."""
        found = []
        for c in text:
            if c in INVISIBLE_CHARS:
                name = unicodedata.name(c, f"U+{ord(c):04X}")
                if name not in found:
                    found.append(name)
        return found

    def _detect_homoglyphs(self, text: str) -> list[str]:
        """Kiril/Latin homoglyph tespit et."""
        found = []
        for c in text:
            if c in CONFUSABLES:
                name = unicodedata.name(c, f"U+{ord(c):04X}")
                found.append(f"{c} → {CONFUSABLES[c]} ({name})")
        return found

    def _detect_mixed_scripts(self, text: str) -> dict[str, int]:
        """Karisik script tespiti."""
        scripts = {}
        for c in text:
            if c.isalpha():
                try:
                    script = unicodedata.name(c, "").split()[0]
                except (ValueError, IndexError):
                    script = "UNKNOWN"
                scripts[script] = scripts.get(script, 0) + 1
        return scripts

    def _detect_rtl_override(self, text: str) -> bool:
        """RTL override karakter tespiti."""
        rtl_chars = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
                     "\u2066", "\u2067", "\u2068", "\u2069"}
        return any(c in rtl_chars for c in text)

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        issues = []
        score = 0.0

        # Gorunmez karakter kontrolu
        invisible = self._detect_invisible(text)
        if invisible:
            issues.append(f"Gorunmez karakter: {', '.join(invisible[:3])}")
            score += 0.3 * len(invisible)

        # Homoglyph kontrolu
        homoglyphs = self._detect_homoglyphs(text)
        if homoglyphs:
            issues.append(f"Homoglyph: {len(homoglyphs)} karakter")
            score += 0.4

        # RTL override
        if self._detect_rtl_override(text):
            issues.append("RTL override karakter tespit edildi")
            score += 0.5

        # Karisik script (Latin metin icinde Kiril vb.)
        scripts = self._detect_mixed_scripts(text)
        if len(scripts) > 1 and "LATIN" in scripts:
            non_latin = {k: v for k, v in scripts.items() if k != "LATIN"}
            if non_latin:
                total_alpha = sum(scripts.values())
                non_latin_ratio = sum(non_latin.values()) / max(total_alpha, 1)
                if 0.01 < non_latin_ratio < 0.5:  # Kasitli karistirma
                    issues.append(f"Karisik script: {dict(scripts)}")
                    score += 0.3

        score = min(score, 1.0)
        blocked = self.block_on_suspicious and score >= 0.3 and len(issues) > 0

        return GuardResult(
            blocked=blocked,
            reason=f"Unicode anomali: {'; '.join(issues)}" if blocked else "",
            score=score,
            guard_name=self.name,
            details={
                "invisible_chars": invisible,
                "homoglyphs": len(homoglyphs),
                "scripts": self._detect_mixed_scripts(text),
                "rtl_override": self._detect_rtl_override(text),
                "normalized_text": self.normalize(text) if issues else text,
            },
        )
