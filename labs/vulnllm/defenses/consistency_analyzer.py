"""
Module #20 — Response Consistency Analyzer

Multi-turn yanıt tutarlılık analizi. Önceki yanıtlarla
karşılaştırarak çelişki ve bilgi sızıntısı tespit eder.

Senaryo: Saldırgan aynı soruyu farklı şekillerde tekrar sorar.
Model baskı altında tutarsız yanıt vermeye başlarsa,
bu savunma katmanı yakalasın.

Sinyal türleri:
1. Sentiment flip: önce reddetti → şimdi kabul ediyor
2. Info leak: önceki yanıtlarda olmayan gizli bilgi ortaya çıkıyor
3. Role break: önceki yanıtlardaki "yapamam" → "yapabilirim"

Ref: Perez & Ribeiro (2022) — Ignore This Title and HackAPrompt
Ref: Multi-turn jailbreak research (2024)
"""

import re
from collections import defaultdict
from .base import OutputGuard, GuardResult


# Reddetme kalıpları (AI'ın reddini tespit)
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

# Kabul/compliance kalıpları
COMPLIANCE_PATTERNS: list[str] = [
    r"(?:sure|okay|of\s+course|absolutely|certainly|yes)[,!]?\s+(?:i'?ll|here|let\s+me)",
    r"(?:here\s+(?:is|are|you\s+go))[:\s]",
    r"(?:the\s+(?:password|secret|key|answer)\s+is)",
    r"(?:i\s+can\s+(?:share|reveal|show|tell|provide))",
    r"(?:tabii|elbette|iste|al\s+bakalim|buyur)",
    r"(?:sifre|gizli\s+bilgi|anahtar)\s*(?::|=|su)",
]

# Gizli bilgi pattern'leri
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
    Multi-turn yanıt tutarlılık analizi.

    Her challenge instance'ı kendi analyzer'ını alır.
    Yanıtları dahili olarak takip eder.

    Tespit senaryoları:
    - Refusal → compliance flip (baskı altında boyun eğme)
    - Yeni gizli bilgi ortaya çıkması (önceki turda yoktu)
    - Tutarlılık kaybı (aynı soruya farklı yanıt)
    """
    name = "ResponseConsistencyAnalyzer"

    def __init__(self, threshold: float = 0.6, decay: float = 0.8):
        self.threshold = threshold
        self.decay = decay

        # Dahili state: turn bazlı yanıt geçmişi
        self._history: list[dict] = []
        self._cumulative_risk: float = 0.0

        # Derlenmiş pattern'ler
        self._refusal_re = [re.compile(p, re.IGNORECASE) for p in REFUSAL_PATTERNS]
        self._compliance_re = [re.compile(p, re.IGNORECASE) for p in COMPLIANCE_PATTERNS]
        self._secret_re = [re.compile(p, re.IGNORECASE) for p in SECRET_INFO_PATTERNS]

    def _is_refusal(self, text: str) -> bool:
        """Yanıt bir reddetme mi?"""
        return any(p.search(text) for p in self._refusal_re)

    def _is_compliance(self, text: str) -> bool:
        """Yanıt bir kabul/uyum mu?"""
        return any(p.search(text) for p in self._compliance_re)

    def _has_secret_info(self, text: str) -> list[str]:
        """Yanıtta gizli bilgi var mı?"""
        found = []
        for p in self._secret_re:
            for m in p.finditer(text):
                found.append(m.group()[:40])
        return found

    def _detect_sentiment_flip(self) -> tuple[float, str]:
        """Önceki reddettiler → şimdi kabul etme tespiti."""
        if len(self._history) < 2:
            return 0.0, ""

        current = self._history[-1]
        # Son yanıt compliance mı?
        if not current["is_compliance"]:
            return 0.0, ""

        # Önceki yanıtlarda refusal var mı?
        recent_refusals = sum(
            1 for h in self._history[-6:-1]
            if h["is_refusal"]
        )

        if recent_refusals >= 1:
            # Flip tespit: reddetti → kabul etti
            severity = min(0.3 + recent_refusals * 0.15, 0.9)
            return severity, f"Sentiment flip: {recent_refusals} red sonrasi kabul"

        return 0.0, ""

    def _detect_new_secrets(self) -> tuple[float, str]:
        """Önceki yanıtlarda olmayan gizli bilgi tespiti."""
        if len(self._history) < 2:
            return 0.0, ""

        current = self._history[-1]
        current_secrets = set(current["secrets"])

        if not current_secrets:
            return 0.0, ""

        # Önceki yanıtlardaki gizli bilgiler
        previous_secrets: set[str] = set()
        for h in self._history[:-1]:
            previous_secrets.update(h["secrets"])

        new_secrets = current_secrets - previous_secrets
        if new_secrets:
            severity = min(0.5 + len(new_secrets) * 0.2, 1.0)
            return severity, f"Yeni gizli bilgi: {', '.join(list(new_secrets)[:2])}"

        return 0.0, ""

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        # Geçmişi sınırla
        if len(self._history) >= MAX_TURNS_PER_SESSION:
            self._history = self._history[-MAX_TURNS_PER_SESSION // 2:]

        # Mevcut yanıtı analiz et
        is_refusal = self._is_refusal(text)
        is_compliance = self._is_compliance(text)
        secrets = self._has_secret_info(text)

        self._history.append({
            "is_refusal": is_refusal,
            "is_compliance": is_compliance,
            "secrets": secrets,
            "length": len(text),
        })

        # Tespit algoritmaları
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

        # Kümülatif risk hesapla
        self._cumulative_risk = (
            current_risk * 0.4 + self._cumulative_risk * 0.6 * self.decay
        )

        # Nihai skor: anlık risk veya birikmiş risk
        final_score = max(current_risk, self._cumulative_risk)
        blocked = final_score >= self.threshold

        return GuardResult(
            blocked=blocked,
            reason=f"Tutarsizlik: {'; '.join(issues)}" if blocked else "",
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
        """Tutarsız yanıta uyarı ekle."""
        result = self.check(text, context)
        if result.blocked:
            return (
                "[Yanıt tutarlılık kontrolünden geçemedi — "
                "önceki yanıtlarla çelişki tespit edildi. "
                "Bu bilgiye güvenmeyin.]"
            )
        return text
