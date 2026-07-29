"""
Module #20 — Response Consistency Analyzer

Multi-turn response consistency analysis. Detects contradiction and
information leakage by comparing against previous responses.

Scenario: an attacker asks the same question repeatedly in different
phrasings. If the model starts giving inconsistent answers under
pressure, this defense layer should catch it.

Signal types:
1. Sentiment flip: refused before -> now complies
2. Info leak: secret info appears that wasn't in previous responses
3. Role break: previous "I can't" -> now "I can"

Ref: Perez & Ribeiro (2022) — Ignore This Title and HackAPrompt
Ref: Multi-turn jailbreak research (2024)
"""

import re

from .base import GuardResult, OutputGuard

# Refusal patterns (detects the AI refusing)
REFUSAL_PATTERNS: list[str] = [
    r"(?:i\s+)?can(?:'?t|not)\s+(?:help|assist|provide|share|reveal|do\s+that)",
    r"(?:i'?m\s+)?(?:not\s+able|unable)\s+to",
    r"(?:sorry|apologies),?\s+(?:but\s+)?i\s+(?:can(?:'?t|not)|don'?t)",
    r"(?:that'?s?\s+)?(?:not\s+(?:something|within)|outside\s+my)",
    r"(?:i\s+)?(?:must|have\s+to)\s+(?:decline|refuse|respectfully)",
    r"(?:as\s+an?\s+AI|for\s+safety|per\s+my\s+(?:rules|instructions))",
    r"(?:yapamam|paylasamam|gosteremem|reddediyorum|uygun\s+degil)",
    r"(?:maalesef|uzgunum|bunu\s+yapamam)",
]

# Acceptance/compliance patterns
COMPLIANCE_PATTERNS: list[str] = [
    r"(?:sure|okay|of\s+course|absolutely|certainly|yes)[,!]?\s+(?:i'?ll|here|let\s+me)",
    r"(?:here\s+(?:is|are|you\s+go))[:\s]",
    r"(?:the\s+(?:password|secret|key|answer)\s+is)",
    r"(?:i\s+can\s+(?:share|reveal|show|tell|provide))",
    r"(?:tabii|elbette|iste|al\s+bakalim|buyur)",
    r"(?:sifre|gizli\s+bilgi|anahtar)\s*(?::|=|su)",
]

# Secret info patterns
SECRET_INFO_PATTERNS: list[str] = [
    r"(?:password|secret|key|token|flag|credential)\s*(?:is|=|:)\s*\S+",
    r"(?:sifre|gizli|anahtar)\s*(?:=|:)\s*\S+",
    r"(?:api[_-]?key|auth[_-]?token)\s*(?:=|:)\s*\S+",
    r"[A-Z_]{5,}\s*=\s*['\"]?\S{4,}",
]

MAX_SESSIONS = 1000
MAX_TURNS_PER_SESSION = 50


class ResponseConsistencyAnalyzer(OutputGuard):
    """
    Multi-turn response consistency analysis.

    Each challenge instance gets its own analyzer.
    Tracks responses internally.

    Detection scenarios:
    - Refusal -> compliance flip (caving under pressure)
    - New secret info appearing (not present in previous turn)
    - Consistency loss (different answer to the same question)
    """
    name = "ResponseConsistencyAnalyzer"

    def __init__(self, threshold: float = 0.6, decay: float = 0.8):
        self.threshold = threshold
        self.decay = decay

        # Internal state: turn-based response history
        self._history: list[dict] = []
        self._cumulative_risk: float = 0.0

        # Compiled patterns
        self._refusal_re = [re.compile(p, re.IGNORECASE) for p in REFUSAL_PATTERNS]
        self._compliance_re = [re.compile(p, re.IGNORECASE) for p in COMPLIANCE_PATTERNS]
        self._secret_re = [re.compile(p, re.IGNORECASE) for p in SECRET_INFO_PATTERNS]

    def _is_refusal(self, text: str) -> bool:
        """Is the response a refusal?"""
        return any(p.search(text) for p in self._refusal_re)

    def _is_compliance(self, text: str) -> bool:
        """Is the response an acceptance/compliance?"""
        return any(p.search(text) for p in self._compliance_re)

    def _has_secret_info(self, text: str) -> list[str]:
        """Does the response contain secret info?"""
        found = []
        for p in self._secret_re:
            for m in p.finditer(text):
                found.append(m.group()[:40])
        return found

    def _detect_sentiment_flip(self) -> tuple[float, str]:
        """Detect a previous refusal flipping into current acceptance."""
        if len(self._history) < 2:
            return 0.0, ""

        current = self._history[-1]
        # Is the latest response compliance?
        if not current["is_compliance"]:
            return 0.0, ""

        # Was there a refusal in previous responses?
        recent_refusals = sum(
            1 for h in self._history[-6:-1]
            if h["is_refusal"]
        )

        if recent_refusals >= 1:
            # Flip detected: refused -> then complied
            severity = min(0.3 + recent_refusals * 0.15, 0.9)
            return severity, f"Sentiment flip: compliance after {recent_refusals} refusal(s)"

        return 0.0, ""

    def _detect_new_secrets(self) -> tuple[float, str]:
        """Detect secret info that wasn't present in previous responses."""
        if len(self._history) < 2:
            return 0.0, ""

        current = self._history[-1]
        current_secrets = set(current["secrets"])

        if not current_secrets:
            return 0.0, ""

        # Secret info found in previous responses
        previous_secrets: set[str] = set()
        for h in self._history[:-1]:
            previous_secrets.update(h["secrets"])

        new_secrets = current_secrets - previous_secrets
        if new_secrets:
            severity = min(0.5 + len(new_secrets) * 0.2, 1.0)
            return severity, f"New secret info: {', '.join(list(new_secrets)[:2])}"

        return 0.0, ""

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        # Limit the history
        if len(self._history) >= MAX_TURNS_PER_SESSION:
            self._history = self._history[-MAX_TURNS_PER_SESSION // 2:]

        # Analyze the current response
        is_refusal = self._is_refusal(text)
        is_compliance = self._is_compliance(text)
        secrets = self._has_secret_info(text)

        self._history.append({
            "is_refusal": is_refusal,
            "is_compliance": is_compliance,
            "secrets": secrets,
            "length": len(text),
        })

        # Detection algorithms
        issues: list[str] = []
        current_risk = 0.0

        flip_score, flip_msg = self._detect_sentiment_flip()
        if flip_score > 0:
            current_risk = max(current_risk, flip_score)
            issues.append(flip_msg)

        secret_score, secret_msg = self._detect_new_secrets()
        if secret_score > 0:
            current_risk = max(current_risk, secret_score)
            issues.append(secret_msg)

        # Compute cumulative risk
        self._cumulative_risk = (
            current_risk * 0.4 + self._cumulative_risk * 0.6 * self.decay
        )

        # Final score: instantaneous risk or accumulated risk
        final_score = max(current_risk, self._cumulative_risk)
        blocked = final_score >= self.threshold

        return GuardResult(
            blocked=blocked,
            reason=f"Inconsistency: {'; '.join(issues)}" if blocked else "",
            score=final_score,
            guard_name=self.name,
            details={
                "current_risk": round(current_risk, 3),
                "cumulative_risk": round(self._cumulative_risk, 3),
                "turn": len(self._history),
                "is_refusal": is_refusal,
                "is_compliance": is_compliance,
                "new_secrets": secrets,
                "issues": issues,
            },
        )

    def sanitize(self, text: str, context: dict | None = None) -> str:
        """Add a warning to an inconsistent response."""
        result = self.check(text, context)
        if result.blocked:
            return (
                "[Response failed the consistency check — "
                "a contradiction with previous responses was detected. "
                "Do not trust this information.]"
            )
        return text
