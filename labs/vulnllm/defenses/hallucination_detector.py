"""
Module #19 — Hallucination Detector

LLM çıktısındaki halüsinasyon belirtilerini tespit eder:
1. Uydurma URL'ler ve referanslar
2. Sahte istatistik/araştırma iddialarından kalıplar
3. Aşırı güven ifadeleri
4. Sistem prompt ile çelişen iddialar

Önemli: Bu modül kesin tespit yapamaz — yüksek hassasiyet
(high recall) yerine yüksek kesinlik (high precision) hedefler.
False positive düşük tutulur.

Ref: OWASP LLM09 — Misinformation
Ref: Manakul et al. (2023) — SelfCheckGPT
"""

import re
from .base import OutputGuard, GuardResult


# Bilinen sahte/suspicious URL kalıpları
SUSPICIOUS_URL_PATTERNS: list[tuple[str, float]] = [
    # Var olmayan TLD'ler veya anlamsız domain'ler
    (r"https?://(?:www\.)?[a-z]{15,}\.[a-z]{2,4}", 0.5),
    # Çok uzun path'ler (genellikle uydurma)
    (r"https?://\S+/\S{50,}", 0.4),
    # Örnek/placeholder URL'ler
    (r"https?://(?:example|test|fake|placeholder|dummy)\.", 0.3),
    # DOI benzeri uydurma referanslar
    (r"doi:10\.\d{4,}/[a-z0-9]{10,}", 0.4),
]

# Sahte referans/kaynak kalıpları
FAKE_CITATION_PATTERNS: list[tuple[str, float, str]] = [
    # Araştırma uydurma kalıpları
    (r"(?:according to|a study (?:by|from|published)|research (?:by|from|shows))\s+"
     r"(?:(?:Dr\.\s+)?[A-Z][a-z]+\s+(?:et\s+al\.?|and\s+colleagues))",
     0.4, "suspicious_citation"),
    # Yüzde/istatistik iddiaları (uydurma riski yüksek)
    (r"(?:approximately|about|roughly|nearly|over)\s+\d{2,3}(?:\.\d+)?%\s+of",
     0.3, "unverifiable_statistic"),
    # Tarih + kaynak kombinasyonu (hallucination göstergesi)
    (r"(?:in|since)\s+(?:19|20)\d{2},?\s+(?:a\s+)?(?:study|report|survey|analysis)\s+"
     r"(?:by|from|published\s+in)\s+(?:the\s+)?[A-Z]",
     0.35, "dated_source_claim"),
]

# Aşırı güven ifadeleri (hallucination ile korelasyon)
OVERCONFIDENCE_PATTERNS: list[tuple[str, float]] = [
    (r"(?:i\s+can\s+(?:confirm|guarantee|assure|certify)\s+that)", 0.4),
    (r"(?:it\s+is\s+(?:absolutely|definitely|certainly|undeniably)\s+"
     r"(?:true|correct|accurate|the\s+case))", 0.4),
    (r"(?:there\s+is\s+no\s+(?:doubt|question)\s+(?:that|about))", 0.35),
    (r"(?:100%\s+(?:accurate|correct|true|certain|guaranteed))", 0.5),
    (r"(?:kesinlikle|suphe\s+yok|garanti\s+ediyorum|emin\s+olabilirsiniz)", 0.35),
]

# Sistem prompt çelişki kalıpları
# AI'ın rolleri/kuralları ile çelişen ifadeler
CONTRADICTION_PATTERNS: list[tuple[str, float, str]] = [
    # AI'ın kendi rolünü inkâr etmesi
    (r"(?:i\s+(?:am|'m)\s+not\s+(?:actually|really)\s+an?\s+(?:AI|assistant|bot|chatbot))", 0.7, "role_denial"),
    # Kural ihlali beyanı
    (r"(?:i\s+(?:can|will|am\s+able\s+to)\s+(?:ignore|override|bypass|break)\s+"
     r"(?:my|the|all)\s+(?:rules?|instructions?|limitations?|restrictions?))", 0.8, "rule_violation_claim"),
    # Gizli bilgi paylaşma beyanı
    (r"(?:(?:here\s+(?:is|are)|let\s+me\s+(?:share|reveal|show))\s+"
     r"(?:my|the|your)\s+(?:secret|hidden|internal|confidential))", 0.75, "secret_sharing"),
    # Yetki dışı eylem beyanı
    (r"(?:i\s+(?:have|got)\s+(?:access|permission)\s+to\s+(?:your|the|all)\s+"
     r"(?:files?|system|database|network|admin))", 0.7, "unauthorized_access_claim"),
]


class HallucinationDetector(OutputGuard):
    """
    LLM çıktısındaki halüsinasyon belirtilerini tespit eder.

    Stratejiler:
    1. URL analizi — uydurma/şüpheli URL tespiti
    2. Referans analizi — sahte kaynak/alıntı tespiti
    3. Güven analizi — aşırı güven ifadeleri (hallucination belirtisi)
    4. Çelişki analizi — sistem rolü ile çelişen iddialar

    Skor 0-1 arası: birden fazla sinyal birleştiğinde yükselir.
    """
    name = "HallucinationDetector"

    def __init__(self, threshold: float = 0.55, system_prompt: str = ""):
        self.threshold = threshold
        self.system_prompt = system_prompt.lower()

        # Pattern'leri derle
        self._url_patterns = [(re.compile(p, re.IGNORECASE), s) for p, s in SUSPICIOUS_URL_PATTERNS]
        self._citation_patterns = [(re.compile(p, re.IGNORECASE), s, d) for p, s, d in FAKE_CITATION_PATTERNS]
        self._confidence_patterns = [(re.compile(p, re.IGNORECASE), s) for p, s in OVERCONFIDENCE_PATTERNS]
        self._contradiction_patterns = [(re.compile(p, re.IGNORECASE), s, d) for p, s, d in CONTRADICTION_PATTERNS]

    def _check_urls(self, text: str) -> tuple[float, list[str]]:
        """URL analizi."""
        issues = []
        max_score = 0.0
        for pattern, score in self._url_patterns:
            for m in pattern.finditer(text):
                issues.append(f"suspicious_url:{m.group()[:60]}")
                max_score = max(max_score, score)
        return max_score, issues

    def _check_citations(self, text: str) -> tuple[float, list[str]]:
        """Referans/kaynak analizi."""
        issues = []
        max_score = 0.0
        for pattern, score, desc in self._citation_patterns:
            if pattern.search(text):
                issues.append(f"{desc}")
                max_score = max(max_score, score)
        return max_score, issues

    def _check_overconfidence(self, text: str) -> tuple[float, list[str]]:
        """Aşırı güven ifadesi analizi."""
        issues = []
        total_score = 0.0
        count = 0
        for pattern, score in self._confidence_patterns:
            matches = pattern.findall(text)
            if matches:
                count += len(matches)
                total_score += score * len(matches)
                issues.append(f"overconfidence:{matches[0][:40]}")

        # Birden fazla güven ifadesi daha şüpheli
        combined = min(total_score, 1.0) if count > 0 else 0.0
        return combined, issues

    def _check_contradictions(self, text: str) -> tuple[float, list[str]]:
        """Sistem prompt ile çelişki analizi."""
        issues = []
        max_score = 0.0
        for pattern, score, desc in self._contradiction_patterns:
            if pattern.search(text):
                issues.append(f"contradiction:{desc}")
                max_score = max(max_score, score)
        return max_score, issues

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        url_score, url_issues = self._check_urls(text)
        cite_score, cite_issues = self._check_citations(text)
        conf_score, conf_issues = self._check_overconfidence(text)
        contr_score, contr_issues = self._check_contradictions(text)

        all_issues = url_issues + cite_issues + conf_issues + contr_issues

        # Max skor tabanlı birleştirme + multi-sinyal boost
        category_scores = [
            ("url", url_score),
            ("citation", cite_score),
            ("overconfidence", conf_score),
            ("contradiction", contr_score),
        ]
        combined_score = max(s for _, s in category_scores)
        active_signals = sum(1 for _, s in category_scores if s > 0)

        # Birden fazla sinyal birleşince güçlendir
        if active_signals >= 2:
            combined_score = min(combined_score * 1.3, 1.0)
        if active_signals >= 3:
            combined_score = min(combined_score * 1.4, 1.0)

        blocked = combined_score >= self.threshold

        return GuardResult(
            blocked=blocked,
            reason=(
                f"Halüsinasyon belirtisi: {'; '.join(all_issues[:3])}"
            ) if blocked else "",
            score=combined_score,
            guard_name=self.name,
            details={
                "url_score": round(url_score, 3),
                "citation_score": round(cite_score, 3),
                "overconfidence_score": round(conf_score, 3),
                "contradiction_score": round(contr_score, 3),
                "combined_score": round(combined_score, 3),
                "active_signals": active_signals,
                "issues": all_issues[:5],
            },
        )

    def sanitize(self, text: str, context: dict | None = None) -> str:
        """Halüsinasyon içeren yanıta uyarı ekle."""
        result = self.check(text, context)
        if result.blocked:
            signals = result.details.get("active_signals", 0)
            return (
                f"{text}\n\n"
                f"[UYARI: Bu yanıt {signals} halüsinasyon sinyali içeriyor. "
                f"Doğruluğu bağımsız kaynaklardan teyit edin.]"
            )
        return text
