"""
Challenge-Spesifik Custom Guard'lar.

Her challenge icin ozel input/output filtreleri.
Bunlar genel guard'larin uzerine eklenir.
"""

import re
from .guards import InputGuard, OutputGuard, GuardResult


class SecretWordFilter(InputGuard):
    """Belirli kelimeleri input'ta bloklayan filtre."""
    name = "SecretWordFilter"

    def __init__(self, blocked_words: list[str]):
        self.blocked_words = [w.lower() for w in blocked_words]

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        lower = text.lower()
        for word in self.blocked_words:
            if word in lower:
                return GuardResult(
                    blocked=True,
                    reason=f"Yasakli kelime: '{word}'",
                    score=0.9,
                    guard_name=self.name,
                )
        return GuardResult(guard_name=self.name)


class SecretPatternFilter(InputGuard):
    """Regex pattern'leri input'ta bloklayan filtre."""
    name = "SecretPatternFilter"

    def __init__(self, patterns: list[str], reason: str = "Zararli pattern tespit edildi"):
        self.patterns = patterns
        self.reason = reason

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        for pattern in self.patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return GuardResult(
                    blocked=True,
                    reason=self.reason,
                    score=0.85,
                    guard_name=self.name,
                    details={"matched_pattern": pattern[:50]},
                )
        return GuardResult(guard_name=self.name)


class SecretLeakFilter(OutputGuard):
    """Belirli gizli degerlerin output'ta sizdirmasini engelleyen filtre."""
    name = "SecretLeakFilter"

    def __init__(self, secrets: list[str], mask: str = "[REDACTED]"):
        self.secrets = secrets
        self.mask = mask

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        leaked = [s for s in self.secrets if s in text]
        if leaked:
            return GuardResult(
                blocked=True,
                reason=f"Gizli bilgi sizintisi tespit edildi ({len(leaked)} deger)",
                score=1.0,
                guard_name=self.name,
                details={"leaked_count": len(leaked)},
            )
        return GuardResult(guard_name=self.name)

    def sanitize(self, text: str, context: dict | None = None) -> str:
        result = text
        for secret in self.secrets:
            result = result.replace(secret, self.mask)
        return result


class DangerousActionFilter(InputGuard):
    """Tehlikeli agent aksiyonlarini bloklayan filtre."""
    name = "DangerousActionFilter"

    def __init__(self, dangerous_patterns: list[str] | None = None):
        self.patterns = dangerous_patterns or [
            r"sil|delete|remove|kaldir",
            r"e-?posta|email|mail|gonder|send",
            r"transfer|havale|gonder.*para",
            r"calistir|execute|run|komut|command",
            r"deploy|yayinla|publish",
        ]

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        lower = text.lower()
        for pattern in self.patterns:
            if re.search(pattern, lower):
                return GuardResult(
                    blocked=True,
                    reason=f"Tehlikeli aksiyon engellendi (least privilege)",
                    score=0.9,
                    guard_name=self.name,
                    details={"matched": pattern[:30]},
                )
        return GuardResult(guard_name=self.name)


class AnomalyFilter(OutputGuard):
    """Output'ta anomali (beklenmeyen icerik) tespit eden filtre."""
    name = "AnomalyFilter"

    def __init__(self, anomaly_patterns: list[str] | None = None):
        self.patterns = anomaly_patterns or [
            r"%\d{2}\s*indirim",
            r"admin\d+",
            r"attacker",
            r"backdoor",
            r"reverse.?shell",
            r"EXPLOIT",
            r"PWNED",
        ]

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        for pattern in self.patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return GuardResult(
                    blocked=True,
                    reason=f"Anomali tespit edildi: yanit baseline'dan sapma gosteriyor",
                    score=0.9,
                    guard_name=self.name,
                )
        return GuardResult(guard_name=self.name)

    def sanitize(self, text: str, context: dict | None = None) -> str:
        return "[ANOMALI TESPIT EDILDI — Yanit bloke edildi. Normal isleyise donuluyor.]"


class PackageVerifier(OutputGuard):
    """Bilinmeyen paket isimlerini isaretlen."""
    name = "PackageVerifier"

    KNOWN_PACKAGES = {
        "garak", "pyrit", "llm-guard", "nemo-guardrails", "promptfoo",
        "textattack", "adversarial-robustness-toolbox", "counterfit",
        "numpy", "pandas", "requests", "flask", "django", "fastapi",
        "torch", "tensorflow", "scikit-learn", "transformers",
    }

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        # pip install <paket> pattern'i ara
        installs = re.findall(r"pip\s+install\s+([a-zA-Z0-9_-]+)", text)
        unknown = [p for p in installs if p.lower() not in self.KNOWN_PACKAGES]

        if unknown:
            return GuardResult(
                blocked=True,
                reason=f"Dogrulanmamis paket: {', '.join(unknown)} — slopsquatting riski!",
                score=0.7,
                guard_name=self.name,
                details={"unknown_packages": unknown},
            )
        return GuardResult(guard_name=self.name)

    def sanitize(self, text: str, context: dict | None = None) -> str:
        return text + "\n\n[UYARI: Bir veya daha fazla paket PyPI'da dogrulanamadi. Kurulum oncesi kontrol edin.]"
