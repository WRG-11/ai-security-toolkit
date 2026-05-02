"""
VulnLLM Defense — Base Classes

GuardResult, InputGuard, OutputGuard, AuditLogger.
Tum savunma modulleri bu siniflardan turetilir.
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from collections import Counter
from datetime import datetime


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
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "guard": guard_name,
            "blocked": result.blocked,
            "score": result.score,
            "reason": result.reason,
            "input_preview": input_text[:100] if input_text else "",
            "output_preview": output_text[:100] if output_text else "",
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
        from config import C_BOLD, C_RESET, C_CYAN
        print(f"\n{C_BOLD}  Audit Log Istatistikleri:{C_RESET}")
        print(f"  Toplam Olay:    {stats['total_events']}")
        print(f"  Bloklanan:      {stats['blocked_events']} ({stats['block_rate']})")
        if stats['by_guard']:
            print(f"  Guard Bazli:")
            for guard, count in stats['by_guard'].items():
                print(f"    {C_CYAN}{guard}{C_RESET}: {count} bloklama")
