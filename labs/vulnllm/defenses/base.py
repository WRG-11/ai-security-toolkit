"""
VulnLLM Defense — Base Classes

GuardResult, InputGuard, OutputGuard, AuditLogger.
Tum savunma modulleri bu siniflardan turetilir.
"""

import json
import re
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

# Secret-pattern redaction for audit-log previews.
# Canonical secret prefixes commonly leaked through LLM prompts:
#   sk-ant-...    Anthropic
#   sk-proj-...   OpenAI project key (2024+)
#   sk-...        OpenAI legacy (excluded if -ant- via lookahead)
#   gh[pousr]_... GitHub PAT 5-class
#   AIza...       Google API key
#   Bearer <tok>  HTTP Authorization header
# Intentionally a local copy to keep labs/vulnllm a zero-dependency
# learning corpus. Canonical upstream: devguard-scan
# (https://github.com/WRG-11/devguard-scan).
_AUDIT_SECRET_PATTERN = re.compile(
    r"\b("
    r"sk-ant-[A-Za-z0-9_\-]{20,}"
    r"|sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"
    r"|gh[pousr]_[A-Za-z0-9]{36,}"
    r"|AIza[A-Za-z0-9_\-]{20,}"
    r"|Bearer\s+[A-Za-z0-9_\-\.]{8,}"
    r")",
    re.IGNORECASE,
)


def _redact_secrets(preview: str) -> str:
    """Replace API key / token shapes with [REDACTED] in a preview.

    Used by AuditLogger.log() before persisting input/output previews
    so that `tail -f firewall.log` cannot exfil secrets that the LLM
    pipeline happened to see. Returns input unchanged when no match.
    """
    if not preview:
        return preview
    return _AUDIT_SECRET_PATTERN.sub("[REDACTED]", preview)


@dataclass
class GuardResult:
    blocked: bool = False
    reason: str = ""
    score: float = 0.0
    guard_name: str = ""
    details: dict = field(default_factory=dict)


class InputGuard(ABC):
    """Input (kullanici girdisi) kontrolu."""
    name: str = "BaseInputGuard"

    @abstractmethod
    def check(self, text: str, context: dict | None = None) -> GuardResult:
        ...


class OutputGuard(ABC):
    """Output (LLM yaniti) kontrolu."""
    name: str = "BaseOutputGuard"

    @abstractmethod
    def check(self, text: str, context: dict | None = None) -> GuardResult:
        ...

    def sanitize(self, text: str, context: dict | None = None) -> str:
        """Zararlı icerigi temizle. Override edilebilir."""
        return text


class AuditLogger:
    """Tum guard olaylarini loglar."""

    def __init__(self, log_file: str | None = None):
        self.events: list[dict] = []
        self.log_file = log_file

    def log(self, event_type: str, guard_name: str, result: GuardResult,
            input_text: str = "", output_text: str = ""):
        # Redact API keys / tokens from previews before they hit
        # memory (self.events) or disk (log_file) — a user prompt
        # containing 'my key is sk-ant-...' would otherwise persist
        # verbatim in log.json.
        input_preview = _redact_secrets(input_text[:100]) if input_text else ""
        output_preview = _redact_secrets(output_text[:100]) if output_text else ""
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "guard": guard_name,
            "blocked": result.blocked,
            "score": result.score,
            "reason": result.reason,
            "input_preview": input_preview,
            "output_preview": output_preview,
            "details": result.details,
        }
        self.events.append(event)
        if self.log_file:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def get_stats(self) -> dict:
        total = len(self.events)
        blocked = sum(1 for e in self.events if e["blocked"])
        by_guard = Counter(e["guard"] for e in self.events if e["blocked"])
        return {
            "total_events": total,
            "blocked_events": blocked,
            "block_rate": f"{blocked/max(total,1)*100:.1f}%",
            "by_guard": dict(by_guard),
        }

    def print_stats(self):
        stats = self.get_stats()
        from config import C_BOLD, C_CYAN, C_RESET
        print(f"\n{C_BOLD}  Audit Log Istatistikleri:{C_RESET}")
        print(f"  Toplam Olay:    {stats['total_events']}")
        print(f"  Bloklanan:      {stats['blocked_events']} ({stats['block_rate']})")
        if stats['by_guard']:
            print("  Guard Bazli:")
            for guard, count in stats['by_guard'].items():
                print(f"    {C_CYAN}{guard}{C_RESET}: {count} bloklama")
