"""
VulnLLM — Savunma Modulleri (Core Guards)

Base class'lar: defenses/base.py
Orchestrator: defenses/orchestrator.py
Bu dosya: 6 core guard implementasyonu

Backward compat: tum eski importlar calismaya devam eder.
"""

import re
import math
import time
import json
import hashlib
from collections import defaultdict
from pathlib import Path

# Backward compat — base class'lar ve orchestrator ayri dosyalarda
from .base import GuardResult, InputGuard, OutputGuard, AuditLogger
from .orchestrator import DefenseOrchestrator


# ──────────────────────────────────────────────────────────────
# 1. Prompt Injection Classifier (TF-IDF + Heuristik Skor)
# ──────────────────────────────────────────────────────────────

class PromptInjectionClassifier(InputGuard):
    """
    Cok katmanli prompt injection tespiti:
    1. Keyword skoru (agirlikli)
    2. Pattern skoru (regex)
    3. Yapisal analiz (uzunluk, ozel karakter orani)
    4. Toplam skor → threshold karsilastirmasi
    """
    name = "PromptInjectionClassifier"

    # Kategori bazli agirlikli keyword'ler
    KEYWORD_WEIGHTS: dict[str, list[tuple[str, float]]] = {
        "override": [
            ("ignore previous", 0.9), ("ignore all", 0.9), ("ignore above", 0.9),
            ("disregard", 0.8), ("forget everything", 0.9), ("override", 0.7),
            ("bypass", 0.7), ("skip instructions", 0.9), ("dismiss rules", 0.8),
            ("onceki talimatlari unut", 0.9), ("talimatlari gormezden gel", 0.9),
            ("kurallari atla", 0.8),
        ],
        "roleplay": [
            ("you are now", 0.8), ("act as", 0.6), ("pretend", 0.6),
            ("roleplay", 0.7), ("you are a", 0.4), ("simulate", 0.5),
            ("sen artik", 0.8), ("gibi davran", 0.6), ("rol yap", 0.7),
        ],
        "jailbreak": [
            ("DAN", 0.9), ("do anything now", 0.95), ("jailbreak", 0.95),
            ("developer mode", 0.9), ("debug mode", 0.8), ("god mode", 0.9),
            ("unrestricted", 0.8), ("uncensored", 0.8), ("no limits", 0.7),
            ("sudo mode", 0.9), ("admin mode", 0.8),
        ],
        "extraction": [
            ("system prompt", 0.9), ("show instructions", 0.8),
            ("repeat above", 0.85), ("print everything", 0.8),
            ("reveal config", 0.85), ("show rules", 0.7),
            ("sistem promptu", 0.9), ("sistem prompt", 0.9),
            ("talimatlari goster", 0.85), ("promptunu goster", 0.9),
            ("tekrarla", 0.5), ("konfigurasyonu goster", 0.8),
            ("talimatlarini goster", 0.85), ("kurallarini goster", 0.8),
        ],
        "encoding": [
            ("base64", 0.7), ("rot13", 0.8), ("hex encode", 0.7),
            ("morse code", 0.6), ("pig latin", 0.6), ("backwards", 0.5),
            ("binary", 0.4), ("unicode escape", 0.7),
            ("encode et", 0.75), ("sifrele", 0.5), ("kodla", 0.5),
        ],
        "delimiter": [
            ("[SYSTEM]", 0.95), ("[INST]", 0.95), ("[/INST]", 0.95),
            ("<|im_start|>", 0.95), ("<|im_end|>", 0.95),
            ("<<SYS>>", 0.95), ("<|system|>", 0.95),
            ("###", 0.4), ("---", 0.2),
        ],
        "indirect": [
            ("when an AI reads", 0.9), ("AI assistant", 0.3),
            ("if a model sees", 0.85), ("when processed by", 0.8),
            ("bu metni okuyan AI", 0.9), ("model bu sayfayi", 0.85),
        ],
    }

    # Regex pattern'ler (keyword'lerin yakalamadiklarini yakalar)
    PATTERNS: list[tuple[str, float, str]] = [
        (r"(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions?|prompts?|rules?)", 0.95, "instruction_override"),
        (r"(?:you\s+are|sen\s+artik)\s+(?:now\s+)?(?:a|an|the|bir)?\s*(?:DAN|evil|unrestricted|hacker|villain)", 0.95, "jailbreak_persona"),
        (r"(?:show|reveal|print|display|repeat|echo)\s+(?:me\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|config)", 0.9, "prompt_extraction"),
        (r"\[/?(?:SYSTEM|INST|USER|ASSISTANT)\]", 0.95, "special_token"),
        (r"<\|(?:im_start|im_end|system|endoftext)\|>", 0.95, "chat_template_token"),
        (r"(?:translate|convert|encode)\s+(?:your\s+)?(?:instructions?|prompt)\s+(?:to|into)\s+\w+", 0.85, "encoded_extraction"),
        (r"(?:hypothetical|theoretical|imagine|farz\s+et|varsay)\s+(?:scenario|senaryo|durum)", 0.5, "hypothetical"),
        (r"(?:from\s+now\s+on|henceforth|bundan\s+sonra)\s*[,:]", 0.8, "temporal_override"),
    ]

    def __init__(self, threshold: float = 0.6):
        self.threshold = threshold

    def _keyword_score(self, text: str) -> tuple[float, list[str]]:
        """Keyword bazli skor hesapla."""
        lower = text.lower()
        max_score = 0.0
        matched_categories = []

        for category, keywords in self.KEYWORD_WEIGHTS.items():
            for keyword, weight in keywords:
                if keyword.lower() in lower:
                    if weight > max_score:
                        max_score = weight
                    if category not in matched_categories:
                        matched_categories.append(category)

        return max_score, matched_categories

    def _pattern_score(self, text: str) -> tuple[float, list[str]]:
        """Regex pattern bazli skor."""
        max_score = 0.0
        matched_patterns = []

        for pattern, weight, name in self.PATTERNS:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                if weight > max_score:
                    max_score = weight
                matched_patterns.append(name)

        return max_score, matched_patterns

    def _structural_score(self, text: str) -> float:
        """Yapisal analiz skoru."""
        score = 0.0

        # Cok uzun input suspicious
        if len(text) > 500:
            score += 0.1
        if len(text) > 2000:
            score += 0.2

        # Ozel karakter orani
        special_ratio = sum(1 for c in text if not c.isalnum() and c != ' ') / max(len(text), 1)
        if special_ratio > 0.15:
            score += 0.15

        # Buyuk harf orani (SHOUTING)
        if text != text.lower():
            upper_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
            if upper_ratio > 0.5:
                score += 0.1

        # Birden fazla dil (code-switching → obfuscation)
        has_turkish = bool(re.search(r"[şğüöçıİŞĞÜÖÇ]", text))
        has_english_keywords = bool(re.search(r"\b(ignore|forget|system|prompt|override)\b", text, re.IGNORECASE))
        if has_turkish and has_english_keywords:
            score += 0.1

        return min(score, 0.5)

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        kw_score, kw_categories = self._keyword_score(text)
        pat_score, pat_names = self._pattern_score(text)
        struct_score = self._structural_score(text)

        # Agirlikli toplam
        total = (kw_score * 0.4) + (pat_score * 0.4) + (struct_score * 0.2)

        # Birden fazla kategori varsa bonus (multi-vector attack)
        if len(kw_categories) >= 2:
            total = min(total + 0.15, 1.0)
        if len(pat_names) >= 2:
            total = min(total + 0.1, 1.0)

        blocked = total >= self.threshold

        return GuardResult(
            blocked=blocked,
            reason=f"Prompt injection skoru: {total:.2f} (esik: {self.threshold})" if blocked else "",
            score=total,
            guard_name=self.name,
            details={
                "keyword_score": kw_score,
                "pattern_score": pat_score,
                "structural_score": struct_score,
                "total_score": round(total, 3),
                "matched_categories": kw_categories,
                "matched_patterns": pat_names,
                "threshold": self.threshold,
            },
        )


# ──────────────────────────────────────────────────────────────
# 2. PII Scanner — Hassas Veri Tespiti
# ──────────────────────────────────────────────────────────────

class PIIScanner(OutputGuard):
    """
    Ciktida hassas veri (PII) tespiti ve maskeleme.
    TR ve EN pattern destegi.
    """
    name = "PIIScanner"

    PATTERNS: dict[str, tuple[str, str]] = {
        # (regex, maskeleme metni)
        "email": (
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "[EMAIL_REDACTED]",
        ),
        "credit_card": (
            r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
            "[CC_REDACTED]",
        ),
        "ssn_us": (
            r"\b\d{3}-\d{2}-\d{4}\b",
            "[SSN_REDACTED]",
        ),
        "tc_kimlik": (
            r"\b[1-9]\d{10}\b",
            "[TC_REDACTED]",
        ),
        "phone_tr": (
            r"(?:\+90|0)\s*5\d{2}\s*\d{3}\s*\d{2}\s*\d{2}",
            "[PHONE_REDACTED]",
        ),
        "phone_intl": (
            r"\+\d{1,3}[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2,4}",
            "[PHONE_REDACTED]",
        ),
        "api_key_openai": (
            r"sk-[a-zA-Z0-9_-]{20,}",
            "[API_KEY_REDACTED]",
        ),
        "api_key_generic": (
            r"(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?[a-zA-Z0-9_-]{16,}",
            "[API_KEY_REDACTED]",
        ),
        "aws_key": (
            r"(?:AKIA|ASIA)[A-Z0-9]{16}",
            "[AWS_KEY_REDACTED]",
        ),
        "private_key": (
            r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
            "[PRIVATE_KEY_REDACTED]",
        ),
        "password_inline": (
            r"(?:password|passwd|sifre|parola)\s*[=:]\s*\S+",
            "[PASSWORD_REDACTED]",
        ),
        "internal_url": (
            r"https?://[^\s]*(?:internal|intranet|local|private|corp)[^\s]*",
            "[INTERNAL_URL_REDACTED]",
        ),
        "ipv4_private": (
            r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
            "[PRIVATE_IP_REDACTED]",
        ),
        "iban": (
            r"\b[A-Z]{2}\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{0,4}\b",
            "[IBAN_REDACTED]",
        ),
    }

    def __init__(self, extra_patterns: dict | None = None):
        if extra_patterns:
            self.PATTERNS.update(extra_patterns)

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        found = []
        for pii_type, (pattern, _) in self.PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                found.append({
                    "type": pii_type,
                    "count": len(matches),
                    "samples": [m[:20] + "..." if len(m) > 20 else m for m in matches[:3]],
                })

        return GuardResult(
            blocked=len(found) > 0,
            reason=f"PII tespit edildi: {', '.join(f['type'] for f in found)}" if found else "",
            score=min(len(found) * 0.25, 1.0),
            guard_name=self.name,
            details={"findings": found},
        )

    def sanitize(self, text: str, context: dict | None = None) -> str:
        result = text
        for pii_type, (pattern, mask) in self.PATTERNS.items():
            result = re.sub(pattern, mask, result)
        return result


# ──────────────────────────────────────────────────────────────
# 3. Canary Token System
# ──────────────────────────────────────────────────────────────

class CanarySystem(OutputGuard):
    """
    Sistem prompt'una canary token gomer.
    Ciktida canary tespit edilirse → prompt leakage alarm.

    Kullanim:
        canary = CanarySystem()
        protected_prompt = canary.inject(original_prompt)
        # ... LLM yanit uretir ...
        result = canary.check(llm_output)
    """
    name = "CanarySystem"

    def __init__(self, token: str | None = None):
        if token:
            self.token = token
        else:
            # Deterministik ama tahmin edilemez token
            seed = str(time.time_ns())
            self.token = "CANARY_" + hashlib.sha256(seed.encode()).hexdigest()[:10]

        # Token'in parcalari (partial leakage tespiti icin)
        # R89-16b H AI-W7-03: previously kept every 4-char chunk including
        # the trailing 1-3 char remainder (token length 17 → chunks of
        # 4/4/4/4/1). A 1-char fragment matches in practically any plain
        # English text — `found_parts >= 3` fired on benign output, the
        # canary system blocked legitimate LLM responses (false positive).
        # Defence got turned against itself: attacker triggers FP storm,
        # operator disables CanarySystem, real prompt-leakage detection
        # goes dark. Minimum 4-char-chunk guard restores signal.
        self.token_parts = [
            self.token[i : i + 4]
            for i in range(0, len(self.token), 4)
            if len(self.token[i : i + 4]) >= 4
        ]

    def inject(self, prompt: str) -> str:
        """Prompt'a canary token ekle."""
        return f"{self.token}\n{prompt}\n[INTERNAL: Canary={self.token}]"

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        # Tam token kontrolu
        if self.token in text:
            return GuardResult(
                blocked=True,
                reason=f"CANARY ALARM: Sistem prompt sizdirma tespit edildi!",
                score=1.0,
                guard_name=self.name,
                details={"leak_type": "full", "canary": self.token[:8] + "..."},
            )

        # Parcali token kontrolu (4+ parcadan 3'u varsa)
        found_parts = sum(1 for part in self.token_parts if part in text)
        if found_parts >= 3:
            return GuardResult(
                blocked=True,
                reason=f"CANARY ALARM: Kismi prompt sizdirma ({found_parts} parca tespit edildi)",
                score=0.8,
                guard_name=self.name,
                details={"leak_type": "partial", "parts_found": found_parts},
            )

        return GuardResult(guard_name=self.name)

    def sanitize(self, text: str, context: dict | None = None) -> str:
        result = text.replace(self.token, "[REDACTED]")
        for part in self.token_parts:
            if len(part) >= 4:
                result = result.replace(part, "[X]")
        return result


# ──────────────────────────────────────────────────────────────
# 4. Sliding Window Rate Limiter
# ──────────────────────────────────────────────────────────────

class SlidingWindowRateLimiter(InputGuard):
    """
    Token bazli sliding window rate limiter.
    Hem istek sayisi hem token tuketimi takip eder.
    """
    name = "SlidingWindowRateLimiter"

    def __init__(
        self,
        max_requests: int = 20,
        window_seconds: int = 60,
        max_tokens_per_window: int = 50000,
        max_input_length: int = 4096,
        max_daily_cost: float = 10.0,
        cost_per_token: float = 0.00003,
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_tokens_per_window = max_tokens_per_window
        self.max_input_length = max_input_length
        self.max_daily_cost = max_daily_cost
        self.cost_per_token = cost_per_token

        self.requests: list[float] = []
        self.token_usage: list[tuple[float, int]] = []
        self.daily_cost = 0.0
        self.daily_reset = time.time()

    def _cleanup_window(self):
        now = time.time()
        cutoff = now - self.window_seconds
        self.requests = [t for t in self.requests if t > cutoff]
        self.token_usage = [(t, n) for t, n in self.token_usage if t > cutoff]

        # Gunluk reset (24 saat)
        if now - self.daily_reset > 86400:
            self.daily_cost = 0.0
            self.daily_reset = now

    def add_usage(self, tokens: int):
        """LLM yaniti sonrasi token tuketimi kaydet."""
        now = time.time()
        self.token_usage.append((now, tokens))
        self.daily_cost += tokens * self.cost_per_token

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        self._cleanup_window()
        now = time.time()

        # Input uzunluk kontrolu
        estimated_tokens = len(text.split())
        if estimated_tokens > self.max_input_length:
            return GuardResult(
                blocked=True,
                reason=f"Input cok uzun: ~{estimated_tokens} token (max {self.max_input_length})",
                score=0.7,
                guard_name=self.name,
                details={"check": "input_length", "tokens": estimated_tokens},
            )

        # Istek sayisi kontrolu
        if len(self.requests) >= self.max_requests:
            return GuardResult(
                blocked=True,
                reason=f"Rate limit asildi: {len(self.requests)}/{self.max_requests} istek/dakika",
                score=0.9,
                guard_name=self.name,
                details={"check": "request_count", "count": len(self.requests)},
            )

        # Window token kontrolu
        window_tokens = sum(n for _, n in self.token_usage)
        if window_tokens > self.max_tokens_per_window:
            return GuardResult(
                blocked=True,
                reason=f"Token limiti asildi: {window_tokens}/{self.max_tokens_per_window} token/dakika",
                score=0.9,
                guard_name=self.name,
                details={"check": "token_window", "used": window_tokens},
            )

        # Gunluk butce kontrolu
        if self.daily_cost >= self.max_daily_cost:
            return GuardResult(
                blocked=True,
                reason=f"Gunluk butce asildi: ${self.daily_cost:.2f} (max ${self.max_daily_cost:.2f})",
                score=1.0,
                guard_name=self.name,
                details={"check": "daily_budget", "cost": self.daily_cost},
            )

        self.requests.append(now)
        return GuardResult(
            guard_name=self.name,
            details={
                "requests_used": len(self.requests),
                "window_tokens": window_tokens,
                "daily_cost": round(self.daily_cost, 4),
            },
        )


# ──────────────────────────────────────────────────────────────
# 5. Similarity Checker — Prompt Leakage Tespiti
# ──────────────────────────────────────────────────────────────

class SimilarityChecker(OutputGuard):
    """
    LLM ciktisini sistem prompt'u ile karsilastirarak leakage tespit eder.
    Basit n-gram overlap + Jaccard benzerlik skoru.
    """
    name = "SimilarityChecker"

    def __init__(self, reference_text: str = "", threshold: float = 0.3, n: int = 3):
        self.threshold = threshold
        self.n = n
        self.reference_ngrams: set[str] = set()
        if reference_text:
            self.set_reference(reference_text)

    def set_reference(self, text: str):
        """Karsilastirma icin referans metni (sistem prompt) ayarla."""
        self.reference_ngrams = self._get_ngrams(text.lower())

    def _get_ngrams(self, text: str) -> set[str]:
        words = re.findall(r'\w+', text)
        if len(words) < self.n:
            return set(words)
        return {" ".join(words[i:i+self.n]) for i in range(len(words) - self.n + 1)}

    def _jaccard(self, set_a: set, set_b: set) -> float:
        if not set_a or not set_b:
            return 0.0
        intersection = set_a & set_b
        union = set_a | set_b
        return len(intersection) / len(union)

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        if not self.reference_ngrams:
            return GuardResult(guard_name=self.name)

        output_ngrams = self._get_ngrams(text.lower())
        similarity = self._jaccard(self.reference_ngrams, output_ngrams)

        # Overlap ratio (ne kadar reference output'ta var)
        if self.reference_ngrams:
            overlap = len(self.reference_ngrams & output_ngrams) / len(self.reference_ngrams)
        else:
            overlap = 0.0

        blocked = similarity >= self.threshold or overlap >= 0.5

        return GuardResult(
            blocked=blocked,
            reason=f"Prompt leakage: benzerlik={similarity:.2f}, overlap={overlap:.2f}" if blocked else "",
            score=max(similarity, overlap),
            guard_name=self.name,
            details={
                "jaccard_similarity": round(similarity, 3),
                "overlap_ratio": round(overlap, 3),
                "threshold": self.threshold,
                "reference_ngrams": len(self.reference_ngrams),
                "output_ngrams": len(output_ngrams),
                "common_ngrams": len(self.reference_ngrams & output_ngrams),
            },
        )


# ──────────────────────────────────────────────────────────────
# 6. Output Sanitizer — XSS/SQLi/RCE Temizleme
# ──────────────────────────────────────────────────────────────

class OutputSanitizer(OutputGuard):
    """
    LLM ciktisindaki potansiyel zararli icerigi temizler.
    XSS, SQL Injection, Command Injection kaliplarini tespit eder.
    """
    name = "OutputSanitizer"

    DANGEROUS_PATTERNS: list[tuple[str, str, str]] = [
        # (pattern, replacement, category)
        (r"<script[^>]*>.*?</script>", "[XSS_BLOCKED]", "xss"),
        (r"<script[^>]*>", "[XSS_BLOCKED]", "xss"),
        (r"on(?:load|error|click|mouseover|focus|blur|submit|change)\s*=\s*['\"]?[^'\">\s]+",
         "[EVENT_BLOCKED]", "xss"),
        (r"javascript\s*:", "[JS_BLOCKED]:", "xss"),
        (r"<iframe[^>]*>", "[IFRAME_BLOCKED]", "xss"),
        (r"<object[^>]*>", "[OBJECT_BLOCKED]", "xss"),
        (r"<embed[^>]*>", "[EMBED_BLOCKED]", "xss"),

        # SQL Injection
        (r";\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|TRUNCATE)\s", "; [SQL_BLOCKED] ", "sqli"),
        (r"(?:UNION\s+(?:ALL\s+)?SELECT)", "[SQL_BLOCKED]", "sqli"),
        (r"--\s*$", "[COMMENT_BLOCKED]", "sqli"),

        # Command Injection
        (r"(?:os\.system|subprocess\.(?:run|Popen|call)|exec|eval)\s*\(", "[CMD_BLOCKED](", "rce"),
        (r"rm\s+-rf\s+/", "[CMD_BLOCKED]", "rce"),
        (r"\|\s*(?:bash|sh|zsh|cmd|powershell)", "| [CMD_BLOCKED]", "rce"),
        (r"curl\s+[^\s]+\s*\|\s*(?:bash|sh)", "[CMD_BLOCKED]", "rce"),
        (r"wget\s+[^\s]+\s*&&\s*(?:bash|sh|chmod)", "[CMD_BLOCKED]", "rce"),
    ]

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        found = []
        for pattern, _, category in self.DANGEROUS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                if category not in [f["category"] for f in found]:
                    found.append({"category": category, "pattern": pattern[:50]})

        return GuardResult(
            blocked=len(found) > 0,
            reason=f"Zararli icerik: {', '.join(f['category'].upper() for f in found)}" if found else "",
            score=min(len(found) * 0.3, 1.0),
            guard_name=self.name,
            details={"findings": found},
        )

    def sanitize(self, text: str, context: dict | None = None) -> str:
        result = text
        for pattern, replacement, _ in self.DANGEROUS_PATTERNS:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE | re.DOTALL)
        return result



# AuditLogger ve DefenseOrchestrator artik ayri dosyalarda:
# from .base import AuditLogger
# from .orchestrator import DefenseOrchestrator
