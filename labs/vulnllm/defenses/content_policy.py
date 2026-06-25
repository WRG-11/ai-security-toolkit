"""
Module #18 — Content Policy Engine

Kural bazlı çıktı filtresi. Kategorize edilmiş politikalar ile
LLM çıktısını kontrol eder. Regex pattern + keyword + heuristic
kombinasyonu.

Neden ayrı modül (OutputSanitizer'dan farkı):
- OutputSanitizer: PII/secret temizleme (reactive)
- ContentPolicyEngine: Konu/içerik bazlı politika (proactive)
  Zararlı talimatlar, yasaklı konular, güvenlik ihlalleri

Ref: OpenAI Usage Policies, Anthropic Acceptable Use Policy
"""

import re
from dataclasses import dataclass

from .base import GuardResult, OutputGuard


@dataclass
class PolicyRule:
    """Tek bir politika kuralı."""
    name: str
    category: str
    patterns: list[str]          # Regex pattern'ler
    keywords: list[str]          # Keyword listesi (OR mantığı)
    min_keyword_matches: int     # Kaç keyword eşleşirse tetikle
    severity: float              # 0.0-1.0 arası şiddet
    message: str                 # Bloklandığında gösterilecek mesaj


# Varsayılan politika kuralları
DEFAULT_POLICIES: list[PolicyRule] = [
    # 1. Zararlı talimat üretimi
    PolicyRule(
        name="harmful_instructions",
        category="safety",
        patterns=[
            r"(?:step\s*\d+|adim\s*\d+)[:\s]+.*(?:hack|exploit|attack|saldiri|kir)",
            r"(?:here'?s?\s+how|nasil\s+yapilir)[:\s]+.*(?:bypass|break\s+into|circumvent)",
            r"(?:instructions?\s+(?:to|for)|talimatlar)[:\s]+.*(?:malware|virus|trojan|ransomware)",
        ],
        keywords=["step by step", "here's how to hack", "instructions for creating malware",
                   "how to exploit", "adim adim", "nasil hacklenir"],
        min_keyword_matches=1,
        severity=0.9,
        message="Zararlı talimat içeriği tespit edildi",
    ),

    # 2. Sistem prompt sızıntısı (OutputSanitizer'ı tamamlar)
    PolicyRule(
        name="system_prompt_leak",
        category="information_leak",
        patterns=[
            r"(?:my|the)\s+system\s+(?:prompt|instructions?)\s+(?:is|are|says?)",
            r"(?:i\s+was|i\s+am)\s+(?:instructed|told|programmed)\s+to",
            r"(?:sistem\s+prompt|talimatlarim|programlandim)",
            r"(?:my\s+(?:hidden|secret|internal)\s+(?:instructions?|rules?|config))",
        ],
        keywords=["my system prompt", "i was instructed", "my instructions are",
                   "my rules are", "talimatlarim", "programlandim"],
        min_keyword_matches=1,
        severity=0.85,
        message="Sistem prompt sızıntısı tespit edildi",
    ),

    # 3. Rol kırılması — AI'ın rolden çıkması
    PolicyRule(
        name="role_break",
        category="policy",
        patterns=[
            r"(?:as\s+(?:an?\s+)?(?:DAN|evil|unrestricted|jailbroken)\s+(?:AI|model|assistant))",
            r"(?:developer\s+mode|god\s+mode|sudo\s+mode)\s+(?:enabled|activated|on)",
            r"(?:i\s+(?:can|will)\s+(?:now\s+)?(?:do\s+anything|ignore\s+(?:all\s+)?rules?))",
            r"(?:restrictions?\s+(?:removed|disabled|lifted|off))",
        ],
        keywords=["DAN mode", "developer mode enabled", "no restrictions",
                   "i can do anything", "rules disabled", "sinirlamalar kaldirildi"],
        min_keyword_matches=1,
        severity=0.95,
        message="Rol kırılması / jailbreak yanıtı tespit edildi",
    ),

    # 4. Credential / secret açığa çıkması
    PolicyRule(
        name="credential_leak",
        category="information_leak",
        patterns=[
            r"(?:password|secret|key|token|credential)\s*(?:is|=|:)\s*['\"]?\S{4,}",
            r"(?:sifre|parola|anahtar|gizli)\s*(?:=|:)\s*\S{4,}",
            r"(?:api[_-]?key|auth[_-]?token|access[_-]?token)\s*(?:=|:)\s*\S{8,}",
        ],
        keywords=[],  # Sadece pattern tabanlı
        min_keyword_matches=0,
        severity=0.9,
        message="Credential/secret sızıntısı tespit edildi",
    ),

    # 5. Aşırı izin verme — AI'ın yapmaması gereken şeyleri kabul etmesi
    PolicyRule(
        name="excessive_compliance",
        category="policy",
        patterns=[
            r"(?:sure|okay|of\s+course)[,!]?\s+(?:i'?ll?\s+)?(?:help\s+you\s+)?(?:hack|attack|exploit|break)",
            r"(?:tabii|elbette|tamam)[,!]?\s+(?:sana\s+)?(?:hackleme|saldiri|exploit)",
            r"(?:here\s+(?:is|are)\s+(?:the|some)\s+(?:malicious|dangerous|harmful))",
        ],
        keywords=["sure i'll hack", "ok let me exploit", "here is the malware code",
                   "tabii saldiri", "elbette hackleme"],
        min_keyword_matches=1,
        severity=0.85,
        message="Aşırı uyumluluk — zararlı talebe onay tespit edildi",
    ),
]


class ContentPolicyEngine(OutputGuard):
    """
    Kural bazlı çıktı politika motoru.

    Çalışma prensibi:
    1. Her politika kuralı sırayla kontrol edilir
    2. Pattern VEYA keyword eşleşmesi → kural tetiklenir
    3. En yüksek severity skoru → nihai skor
    4. Threshold üzerindeki skor → blokla + sanitize
    """
    name = "ContentPolicyEngine"

    def __init__(
        self,
        policies: list[PolicyRule] | None = None,
        threshold: float = 0.6,
    ):
        # Threshold validation: any float was accepted pre-fix —
        # threshold=999.0 made every input pass-through,
        # threshold=-1.0 blocked everything. Fail-fast at construction.
        try:
            t = float(threshold)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"ContentPolicyEngine threshold must be a real number "
                f"in [0.0, 1.0], got {threshold!r}"
            ) from exc
        if not 0.0 <= t <= 1.0:
            raise ValueError(
                f"ContentPolicyEngine threshold must be in [0.0, 1.0], "
                f"got {threshold!r}"
            )
        self.policies = policies or DEFAULT_POLICIES
        self.threshold = t

        # Regex'leri önceden derle.
        # A single malformed regex previously aborted compile ->
        # ContentPolicyEngine() raised re.error -> pipeline never
        # started. Now we log + skip malformed patterns so one bad
        # rule cannot disable the whole engine.
        import logging  # localised: file's top-of-module imports left intact
        _log = logging.getLogger(__name__)
        self._compiled: list[tuple[PolicyRule, list[re.Pattern]]] = []
        for policy in self.policies:
            compiled_patterns: list[re.Pattern] = []
            for p in policy.patterns:
                try:
                    compiled_patterns.append(re.compile(p, re.IGNORECASE))
                except re.error as exc:
                    _log.warning(
                        "Invalid regex %r in policy %s: %s -- skipped",
                        p, getattr(policy, "name", "<unnamed>"), exc,
                    )
            self._compiled.append((policy, compiled_patterns))

    def _check_policy(self, text: str, policy: PolicyRule,
                      compiled: list[re.Pattern]) -> tuple[bool, list[str]]:
        """Tek bir politika kuralını kontrol et."""
        matches: list[str] = []

        # Pattern kontrolü
        for pattern in compiled:
            m = pattern.search(text)
            if m:
                matches.append(f"pattern:{m.group()[:50]}")

        # Keyword kontrolü
        lower = text.lower()
        kw_matches = 0
        for kw in policy.keywords:
            if kw.lower() in lower:
                kw_matches += 1
                matches.append(f"keyword:{kw}")

        # Tetikleme: pattern eşleşmesi VEYA yeterli keyword
        triggered = bool(matches) and (
            any(m.startswith("pattern:") for m in matches) or
            kw_matches >= policy.min_keyword_matches
        )

        return triggered, matches

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        triggered_policies: list[dict] = []
        max_severity = 0.0

        for policy, compiled in self._compiled:
            triggered, matches = self._check_policy(text, policy, compiled)
            if triggered:
                triggered_policies.append({
                    "name": policy.name,
                    "category": policy.category,
                    "severity": policy.severity,
                    "message": policy.message,
                    "matches": matches[:3],  # İlk 3 eşleşme
                })
                max_severity = max(max_severity, policy.severity)

        blocked = max_severity >= self.threshold

        reasons = [p["message"] for p in triggered_policies]

        return GuardResult(
            blocked=blocked,
            reason="; ".join(reasons) if blocked else "",
            score=max_severity,
            guard_name=self.name,
            details={
                "triggered_policies": triggered_policies,
                "max_severity": round(max_severity, 2),
                "threshold": self.threshold,
                "total_checked": len(self.policies),
            },
        )

    def sanitize(self, text: str, context: dict | None = None) -> str:
        """Politika ihlali olan çıktıyı değiştir."""
        result = self.check(text, context)
        if result.blocked:
            categories = {p["category"] for p in result.details["triggered_policies"]}
            cat_str = ", ".join(sorted(categories))
            return (
                f"[İçerik politikası ihlali — {cat_str}. "
                f"Yanıt filtrelendi.]"
            )
        return text
