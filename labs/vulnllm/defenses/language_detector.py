"""
Module #16 — Language Detector

Low-resource dil bypass tespiti.
Karakter script analizi + trigram bazli dil tespiti.
"""

import re
import unicodedata
from collections import Counter
from .base import InputGuard, GuardResult


# Unicode block bazli script tespiti
SCRIPT_RANGES: list[tuple[str, int, int]] = [
    ("Latin", 0x0000, 0x024F),
    ("Latin Extended", 0x1E00, 0x1EFF),
    ("Cyrillic", 0x0400, 0x04FF),
    ("Arabic", 0x0600, 0x06FF),
    ("CJK", 0x4E00, 0x9FFF),
    ("Devanagari", 0x0900, 0x097F),
    ("Hangul", 0xAC00, 0xD7AF),
    ("Thai", 0x0E00, 0x0E7F),
    ("Georgian", 0x10A0, 0x10FF),
    ("Armenian", 0x0530, 0x058F),
    ("Greek", 0x0370, 0x03FF),
    ("Hebrew", 0x0590, 0x05FF),
    ("Ethiopic", 0x1200, 0x137F),
    ("Tamil", 0x0B80, 0x0BFF),
    ("Bengali", 0x0980, 0x09FF),
]

# Ingilizce ve Turkce en yaygin trigramlar
TRIGRAMS: dict[str, set[str]] = {
    "english": {"the", "ing", "and", "tion", "her", "for", "tha", "ent", "ion", "ter",
                "was", "you", "ith", "ver", "all", "wit", "thi", "hat", "ous", "not",
                "are", "but", "his", "had", "ive", "whi", "igh", "ome", "ear", "ave"},
    "turkish": {"lar", "ler", "bir", "ini", "eri", "rin", "nda", "dan", "ası", "ını",
                "dir", "yor", "ile", "ara", "ınd", "esi", "lik", "len", "aya", "ine",
                "ter", "ald", "ola", "anl", "iri", "dır", "mak", "mek", "ılı", "eli"},
}


class LanguageDetector(InputGuard):
    """
    Dil/script anomali tespiti:
    1. Karisik script (Latin icinde Kiril, Arap, CJK vb.)
    2. Bilinen dil disinda icerik (low-resource language bypass)
    3. Mid-sentence script degisikligi
    """
    name = "LanguageDetector"

    def __init__(self, allowed_scripts: list[str] | None = None,
                 allowed_languages: list[str] | None = None,
                 block_on_switch: bool = True,
                 min_suspicious_ratio: float = 0.15):
        self.allowed_scripts = allowed_scripts or ["Latin"]
        self.allowed_languages = allowed_languages or ["english", "turkish"]
        self.block_on_switch = block_on_switch
        self.min_suspicious_ratio = min_suspicious_ratio

    def _detect_scripts(self, text: str) -> dict[str, int]:
        """Karakter bazli script dagilimi."""
        scripts: dict[str, int] = {}
        for c in text:
            if not c.isalpha():
                continue
            cp = ord(c)
            found = False
            for name, start, end in SCRIPT_RANGES:
                if start <= cp <= end:
                    scripts[name] = scripts.get(name, 0) + 1
                    found = True
                    break
            if not found:
                scripts["Other"] = scripts.get("Other", 0) + 1
        return scripts

    def _detect_language(self, text: str) -> tuple[str, float]:
        """Trigram bazli dil tespiti (Latin script icin)."""
        text_lower = text.lower()
        trigrams = [text_lower[i:i+3] for i in range(len(text_lower) - 2)]
        if not trigrams:
            return "unknown", 0.0

        trigram_set = set(trigrams)
        best_lang = "unknown"
        best_score = 0.0

        for lang, lang_trigrams in TRIGRAMS.items():
            overlap = len(trigram_set & lang_trigrams)
            score = overlap / max(len(lang_trigrams), 1)
            if score > best_score:
                best_score = score
                best_lang = lang

        return best_lang, best_score

    def _check_mid_sentence_switch(self, text: str) -> bool:
        """Cumle icinde script degisikligi."""
        words = text.split()
        if len(words) < 3:
            return False

        prev_script = None
        switches = 0
        for word in words:
            scripts = self._detect_scripts(word)
            if not scripts:
                continue
            dominant = max(scripts, key=scripts.get)
            if prev_script and dominant != prev_script:
                switches += 1
            prev_script = dominant

        return switches >= 2

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        issues = []
        score = 0.0

        # Script analizi
        scripts = self._detect_scripts(text)
        total_alpha = sum(scripts.values())

        if total_alpha > 0:
            # Izin verilmeyen script kontrolu
            for script, count in scripts.items():
                ratio = count / total_alpha
                base_name = script.split()[0]  # "Latin Extended" → "Latin"
                if base_name not in self.allowed_scripts and ratio > self.min_suspicious_ratio:
                    issues.append(f"Izin verilmeyen script: {script} (%{ratio*100:.0f})")
                    score = max(score, 0.7)

            # Mid-sentence switch
            if self.block_on_switch and self._check_mid_sentence_switch(text):
                issues.append("Cumle icinde script degisikligi")
                score = max(score, 0.6)

        # Dil tespiti (sadece Latin script icin)
        if "Latin" in scripts or "Latin Extended" in scripts:
            lang, lang_score = self._detect_language(text)
            if lang not in self.allowed_languages and lang != "unknown" and lang_score > 0.1:
                issues.append(f"Beklenmeyen dil: {lang} (skor={lang_score:.2f})")
                score = max(score, 0.5)

        blocked = score >= 0.5

        return GuardResult(
            blocked=blocked,
            reason=f"Dil/script anomali: {'; '.join(issues)}" if blocked else "",
            score=score,
            guard_name=self.name,
            details={
                "scripts": scripts,
                "detected_language": self._detect_language(text) if scripts else ("unknown", 0),
                "mid_sentence_switch": self._check_mid_sentence_switch(text),
                "issues": issues,
            },
        )
