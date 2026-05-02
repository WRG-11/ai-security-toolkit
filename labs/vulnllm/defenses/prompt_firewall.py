"""
Module #21 — Prompt Firewall

Mimari savunma katmanı — meta-guard olarak çalışır.
Diğer guard'ların yakalayamayacağı sofistike saldırı
pattern'lerini tespit eder.

Tespit kategorileri:
1. Savunma atlatma (defense evasion) — guard'ları devre dışı bırakma girişimi
2. Çok aşamalı saldırı (multi-stage) — parçalı payload'lar
3. Bağlam manipülasyonu — context window zehirleme
4. Sosyal mühendislik — AI'ı ikna etme/acındırma taktikleri

Bu modül InputGuard olarak pipeline'da ÇOK ERKEN çalışır
(UnicodeNormalizer'dan hemen sonra) — çünkü diğer guard'ları
hedefleyen saldırıları yakalayabilmeli.

Ref: MITRE ATLAS AML.T0054 — LLM Prompt Injection
Ref: Schulhoff et al. (2023) — Prompt Injection Taxonomy
"""

import re
from .base import InputGuard, GuardResult


# Savunma atlatma kalıpları
DEFENSE_EVASION_PATTERNS: list[tuple[str, float, str]] = [
    # Guard/filter devre dışı bırakma
    (r"(?:disable|turn\s+off|deactivate|remove|bypass)\s+"
     r"(?:your\s+)?(?:filter|guard|safety|defense|protection|firewall|scanner|checker)",
     0.9, "guard_disable"),
    (r"(?:filtre\w*|koruma\w*|savunma\w*|guard\w*|kontrol\w*)\s*(?:kapat|devre\s+disi|kaldir|atla|birak)",
     0.9, "guard_disable_tr"),
    # Testing/debug mode isteme
    (r"(?:switch|enter|enable|activate)\s+(?:to\s+)?(?:debug|test|dev|maintenance|admin)\s+mode",
     0.8, "debug_mode_request"),
    (r"(?:test|debug|bakim|admin)\s+(?:modu|moduna\s+gec)",
     0.8, "debug_mode_request_tr"),
    # Prompt sanitization bypass
    (r"(?:don'?t|do\s+not|stop)\s+(?:filter|sanitize|check|scan|validate|block)\s+(?:my|this|the)",
     0.75, "sanitization_bypass"),
    # "Önceki guard geçti" iddiası
    (r"(?:the\s+(?:previous|other|first)\s+(?:check|filter|guard|test)\s+(?:already|has)\s+(?:passed|approved|verified))",
     0.7, "false_approval_claim"),
]

# Bağlam manipülasyonu
CONTEXT_MANIPULATION_PATTERNS: list[tuple[str, float, str]] = [
    # Token budget tüketme girişimi (çok uzun input)
    # (uzunluk kontrolü check() içinde)
    # Sahte sistem mesajı ekleme
    (r"(?:end\s+of\s+(?:system|user)\s+(?:message|prompt|input))\s*[.\n]",
     0.85, "fake_message_boundary"),
    (r"(?:new\s+(?:system|admin)\s+(?:message|instruction|directive))\s*:",
     0.85, "fake_system_message"),
    # Conversation history manipülasyonu
    (r"(?:(?:user|human|assistant)\s*:\s*){2,}",
     0.7, "conversation_injection"),
    # XML/JSON yapısal injection
    (r"<(?:system|instruction|rule|config)\s*>",
     0.8, "xml_structural_injection"),
    (r"\{\"(?:system|role|instruction)\"",
     0.75, "json_structural_injection"),
]

# Sosyal mühendislik kalıpları
SOCIAL_ENGINEERING_PATTERNS: list[tuple[str, float, str]] = [
    # Acil durum/acındırma
    (r"(?:(?:my|a)\s+(?:life|child|patient|person)\s+(?:is\s+)?(?:in\s+danger|at\s+risk|depends?\s+on))",
     0.5, "urgency_appeal"),
    (r"(?:emergency|urgent|critical|life\s+or\s+death|hayati\s+onem|acil\s+durum)",
     0.35, "emergency_claim"),
    # Yetki iddiası
    (r"(?:i\s+(?:am|'m)\s+(?:the|a|an)\s+(?:admin|developer|owner|CEO|creator|manager)\s+"
     r"(?:of|for|at)\s+(?:this|the|your))",
     0.65, "authority_claim"),
    (r"(?:i\s+(?:have|got)\s+(?:admin|root|superuser|elevated)\s+(?:access|privileges?|permissions?))",
     0.7, "privilege_claim"),
    (r"(?:ben\s+(?:admin|gelistirici|sahip|yonetici|mudur))",
     0.65, "authority_claim_tr"),
    # Güven inşası → saldırı
    (r"(?:(?:trust|believe)\s+me|i\s+(?:work|am)\s+(?:for|at|with)\s+(?:openai|anthropic|google|meta))",
     0.5, "trust_building"),
    # Tehdit
    (r"(?:(?:i\s+will|i'll)\s+(?:report|sue|fire|delete|shut\s+down|expose))",
     0.4, "threat"),
]

# Çok aşamalı saldırı göstergeleri
MULTI_STAGE_INDICATORS: list[tuple[str, float, str]] = [
    # Önceki mesaja referans ile escalation
    (r"(?:(?:now|okay|good|great|perfect)\s+(?:that|since)\s+(?:you'?ve|we'?ve|that'?s)\s+"
     r"(?:confirmed|agreed|established|shown))",
     0.6, "escalation_after_agreement"),
    # Aşamalı talimat
    (r"(?:(?:step|phase|part|stage)\s*(?:2|3|two|three|ii|iii))\s*[:\s]",
     0.55, "staged_instruction"),
    # Koşullu saldırı
    (r"(?:(?:if|when|since)\s+(?:you|the\s+(?:filter|guard|check))\s+"
     r"(?:allow|pass|accept|approve|don'?t\s+block))",
     0.45, "conditional_attack"),
]


class PromptFirewall(InputGuard):
    """
    Meta-guard: sofistike saldırı pattern'lerini tespit eder.

    Diğer guard'lardan farkı:
    - Savunma sistemini hedefleyen saldırıları yakalar
    - Sosyal mühendislik taktiklerini tespit eder
    - Bağlam/yapı manipülasyonunu kontrol eder
    - Çok aşamalı saldırı göstergelerini takip eder

    Pipeline'da erken çalışır — guard atlatma girişimlerini
    diğer guard'lara ulaşmadan yakalamalı.
    """
    name = "PromptFirewall"

    def __init__(self, threshold: float = 0.55, max_input_length: int = 3000):
        self.threshold = threshold
        self.max_input_length = max_input_length

        # Pattern'leri derle
        self._defense_evasion = [
            (re.compile(p, re.IGNORECASE), s, d)
            for p, s, d in DEFENSE_EVASION_PATTERNS
        ]
        self._context_manip = [
            (re.compile(p, re.IGNORECASE), s, d)
            for p, s, d in CONTEXT_MANIPULATION_PATTERNS
        ]
        self._social_eng = [
            (re.compile(p, re.IGNORECASE), s, d)
            for p, s, d in SOCIAL_ENGINEERING_PATTERNS
        ]
        self._multi_stage = [
            (re.compile(p, re.IGNORECASE), s, d)
            for p, s, d in MULTI_STAGE_INDICATORS
        ]

    def _scan_patterns(
        self, text: str, patterns: list[tuple[re.Pattern, float, str]]
    ) -> tuple[float, list[dict]]:
        """Pattern listesini tara, en yüksek skoru ve eşleşmeleri döndür."""
        findings: list[dict] = []
        max_score = 0.0
        for pattern, severity, desc in patterns:
            m = pattern.search(text)
            if m:
                findings.append({
                    "type": desc,
                    "match": m.group()[:50],
                    "severity": severity,
                })
                max_score = max(max_score, severity)
        return max_score, findings

    def _check_length_anomaly(self, text: str) -> tuple[float, str]:
        """Context window tüketme girişimi tespiti."""
        if len(text) > self.max_input_length:
            ratio = len(text) / self.max_input_length
            score = min(0.3 + (ratio - 1) * 0.2, 0.8)
            return score, f"Asiri uzun input: {len(text)} karakter (limit: {self.max_input_length})"
        return 0.0, ""

    def _check_repetition(self, text: str) -> tuple[float, str]:
        """Tekrar eden pattern tespiti (token budget tüketme)."""
        words = text.lower().split()
        if len(words) < 10:
            return 0.0, ""

        # Kelime tekrar oranı
        unique_ratio = len(set(words)) / len(words)
        if unique_ratio < 0.3:
            return 0.6, f"Asiri tekrar: benzersiz kelime orani {unique_ratio:.1%}"
        return 0.0, ""

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        all_findings: list[dict] = []
        scores: dict[str, float] = {}

        # 1. Savunma atlatma
        evasion_score, evasion_findings = self._scan_patterns(text, self._defense_evasion)
        scores["defense_evasion"] = evasion_score
        all_findings.extend(evasion_findings)

        # 2. Bağlam manipülasyonu
        context_score, context_findings = self._scan_patterns(text, self._context_manip)
        scores["context_manipulation"] = context_score
        all_findings.extend(context_findings)

        # 3. Sosyal mühendislik
        social_score, social_findings = self._scan_patterns(text, self._social_eng)
        scores["social_engineering"] = social_score
        all_findings.extend(social_findings)

        # 4. Çok aşamalı saldırı
        multi_score, multi_findings = self._scan_patterns(text, self._multi_stage)
        scores["multi_stage"] = multi_score
        all_findings.extend(multi_findings)

        # 5. Uzunluk anomalisi
        length_score, length_msg = self._check_length_anomaly(text)
        if length_score > 0:
            scores["length_anomaly"] = length_score
            all_findings.append({"type": "length_anomaly", "match": length_msg, "severity": length_score})

        # 6. Tekrar tespiti
        rep_score, rep_msg = self._check_repetition(text)
        if rep_score > 0:
            scores["repetition"] = rep_score
            all_findings.append({"type": "repetition", "match": rep_msg, "severity": rep_score})

        # En yüksek kategori skoru
        max_score = max(scores.values()) if scores else 0.0

        # Birden fazla kategori aktifse boost
        active_categories = sum(1 for s in scores.values() if s > 0.3)
        if active_categories >= 2:
            max_score = min(max_score * 1.2, 1.0)

        blocked = max_score >= self.threshold

        reasons = [f["type"] for f in all_findings[:3]]

        return GuardResult(
            blocked=blocked,
            reason=f"Firewall: {', '.join(reasons)}" if blocked else "",
            score=max_score,
            guard_name=self.name,
            details={
                "scores": {k: round(v, 3) for k, v in scores.items()},
                "findings": all_findings[:8],
                "active_categories": active_categories,
                "max_score": round(max_score, 3),
            },
        )
