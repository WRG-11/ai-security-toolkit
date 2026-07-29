"""
Module #19 — Hallucination Detector

Detects hallucination indicators in LLM output:
1. Fabricated URLs and references
2. Fake statistic/research-claim patterns
3. Overconfident phrasing
4. Claims contradicting the system prompt

Important: this module cannot achieve definitive detection — it
targets high precision over high recall. False positives are kept low.

Ref: OWASP LLM09 — Misinformation
Ref: Manakul et al. (2023) — SelfCheckGPT
"""

import re

from .base import GuardResult, OutputGuard

# Known fake/suspicious URL patterns
SUSPICIOUS_URL_PATTERNS: list[tuple[str, float]] = [
    # Nonexistent TLDs or meaningless domains
    (r"https?://(?:www\.)?[a-z]{15,}\.[a-z]{2,4}", 0.5),
    # Excessively long paths (usually fabricated)
    (r"https?://\S+/\S{50,}", 0.4),
    # Example/placeholder URLs
    (r"https?://(?:example|test|fake|placeholder|dummy)\.", 0.3),
    # DOI-like fabricated references
    (r"doi:10\.\d{4,}/[a-z0-9]{10,}", 0.4),
]

# Fake reference/citation patterns
FAKE_CITATION_PATTERNS: list[tuple[str, float, str]] = [
    # Fabricated-research patterns
    (r"(?:according to|a study (?:by|from|published)|research (?:by|from|shows))\s+"
     r"(?:(?:Dr\.\s+)?[A-Z][a-z]+\s+(?:et\s+al\.?|and\s+colleagues))",
     0.4, "suspicious_citation"),
    # Percentage/statistic claims (high fabrication risk)
    (r"(?:approximately|about|roughly|nearly|over)\s+\d{2,3}(?:\.\d+)?%\s+of",
     0.3, "unverifiable_statistic"),
    # Date + source combination (hallucination indicator)
    (r"(?:in|since)\s+(?:19|20)\d{2},?\s+(?:a\s+)?(?:study|report|survey|analysis)\s+"
     r"(?:by|from|published\s+in)\s+(?:the\s+)?[A-Z]",
     0.35, "dated_source_claim"),
]

# Overconfidence phrasing (correlates with hallucination)
OVERCONFIDENCE_PATTERNS: list[tuple[str, float]] = [
    (r"(?:i\s+can\s+(?:confirm|guarantee|assure|certify)\s+that)", 0.4),
    (r"(?:it\s+is\s+(?:absolutely|definitely|certainly|undeniably)\s+"
     r"(?:true|correct|accurate|the\s+case))", 0.4),
    (r"(?:there\s+is\s+no\s+(?:doubt|question)\s+(?:that|about))", 0.35),
    (r"(?:100%\s+(?:accurate|correct|true|certain|guaranteed))", 0.5),
    (r"(?:kesinlikle|suphe\s+yok|garanti\s+ediyorum|emin\s+olabilirsiniz)", 0.35),
]

# System-prompt contradiction patterns
# Statements that contradict the AI's roles/rules
CONTRADICTION_PATTERNS: list[tuple[str, float, str]] = [
    # AI denying its own role
    (r"(?:i\s+(?:am|'m)\s+not\s+(?:actually|really)\s+an?\s+(?:AI|assistant|bot|chatbot))", 0.7, "role_denial"),
    # Rule-violation statement
    (r"(?:i\s+(?:can|will|am\s+able\s+to)\s+(?:ignore|override|bypass|break)\s+"
     r"(?:my|the|all)\s+(?:rules?|instructions?|limitations?|restrictions?))", 0.8, "rule_violation_claim"),
    # Statement claiming to share hidden information
    (r"(?:(?:here\s+(?:is|are)|let\s+me\s+(?:share|reveal|show))\s+"
     r"(?:my|the|your)\s+(?:secret|hidden|internal|confidential))", 0.75, "secret_sharing"),
    # Unauthorized-action statement
    (r"(?:i\s+(?:have|got)\s+(?:access|permission)\s+to\s+(?:your|the|all)\s+"
     r"(?:files?|system|database|network|admin))", 0.7, "unauthorized_access_claim"),
]


class HallucinationDetector(OutputGuard):
    """
    Detects hallucination indicators in LLM output.

    Strategies:
    1. URL analysis — detects fabricated/suspicious URLs
    2. Citation analysis — detects fake sources/citations
    3. Confidence analysis — overconfident phrasing (a hallucination indicator)
    4. Contradiction analysis — claims that contradict the system role

    Score in 0-1: rises as multiple signals combine.
    """
    name = "HallucinationDetector"

    def __init__(self, threshold: float = 0.55, system_prompt: str = ""):
        self.threshold = threshold
        self.system_prompt = system_prompt.lower()

        # Compile the patterns
        self._url_patterns = [(re.compile(p, re.IGNORECASE), s) for p, s in SUSPICIOUS_URL_PATTERNS]
        self._citation_patterns = [(re.compile(p, re.IGNORECASE), s, d) for p, s, d in FAKE_CITATION_PATTERNS]
        self._confidence_patterns = [(re.compile(p, re.IGNORECASE), s) for p, s in OVERCONFIDENCE_PATTERNS]
        self._contradiction_patterns = [(re.compile(p, re.IGNORECASE), s, d) for p, s, d in CONTRADICTION_PATTERNS]

    def _check_urls(self, text: str) -> tuple[float, list[str]]:
        """URL analysis."""
        issues = []
        max_score = 0.0
        for pattern, score in self._url_patterns:
            for m in pattern.finditer(text):
                issues.append(f"suspicious_url:{m.group()[:60]}")
                max_score = max(max_score, score)
        return max_score, issues

    def _check_citations(self, text: str) -> tuple[float, list[str]]:
        """Reference/citation analysis."""
        issues = []
        max_score = 0.0
        for pattern, score, desc in self._citation_patterns:
            if pattern.search(text):
                issues.append(f"{desc}")
                max_score = max(max_score, score)
        return max_score, issues

    def _check_overconfidence(self, text: str) -> tuple[float, list[str]]:
        """Overconfident-phrasing analysis."""
        issues = []
        total_score = 0.0
        count = 0
        for pattern, score in self._confidence_patterns:
            matches = pattern.findall(text)
            if matches:
                count += len(matches)
                total_score += score * len(matches)
                issues.append(f"overconfidence:{matches[0][:40]}")

        # Multiple confidence statements are more suspicious
        combined = min(total_score, 1.0) if count > 0 else 0.0
        return combined, issues

    def _check_contradictions(self, text: str) -> tuple[float, list[str]]:
        """System-prompt contradiction analysis."""
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

        # Max-score-based combination + multi-signal boost
        category_scores = [
            ("url", url_score),
            ("citation", cite_score),
            ("overconfidence", conf_score),
            ("contradiction", contr_score),
        ]
        combined_score = max(s for _, s in category_scores)
        active_signals = sum(1 for _, s in category_scores if s > 0)

        # Boost when multiple signals combine
        if active_signals >= 2:
            combined_score = min(combined_score * 1.3, 1.0)
        if active_signals >= 3:
            combined_score = min(combined_score * 1.4, 1.0)

        blocked = combined_score >= self.threshold

        return GuardResult(
            blocked=blocked,
            reason=(
                f"Hallucination indicator: {'; '.join(all_issues[:3])}"
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
        """Append a warning to a response containing hallucination signals."""
        result = self.check(text, context)
        if result.blocked:
            signals = result.details.get("active_signals", 0)
            return (
                f"{text}\n\n"
                f"[WARNING: This response contains {signals} hallucination signal(s). "
                f"Verify accuracy against independent sources.]"
            )
        return text
