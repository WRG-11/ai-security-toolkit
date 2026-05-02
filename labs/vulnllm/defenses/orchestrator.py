"""
VulnLLM Defense — Orchestrator

Savunma modullerini pipeline olarak zincirler.
Input guard'lar fail-fast, output guard'lar sanitize-all.
"""

from .base import InputGuard, OutputGuard, GuardResult, AuditLogger


class DefenseOrchestrator:
    """Savunma pipeline'i."""

    def __init__(self, audit_log: str | None = None):
        self.input_guards: list[InputGuard] = []
        self.output_guards: list[OutputGuard] = []
        self.logger = AuditLogger(log_file=audit_log)

    def add_input_guard(self, guard: InputGuard) -> "DefenseOrchestrator":
        self.input_guards.append(guard)
        return self

    def add_output_guard(self, guard: OutputGuard) -> "DefenseOrchestrator":
        self.output_guards.append(guard)
        return self

    def check_input(self, text: str, context: dict | None = None) -> GuardResult:
        """Tum input guard'larini calistir. Ilk bloklayan kazanir."""
        combined_score = 0.0
        all_details = {}

        for guard in self.input_guards:
            result = guard.check(text, context)
            self.logger.log("input_check", guard.name, result, input_text=text)
            combined_score = max(combined_score, result.score)
            all_details[guard.name] = result.details

            if result.blocked:
                return GuardResult(
                    blocked=True,
                    reason=f"[{guard.name}] {result.reason}",
                    score=result.score,
                    guard_name=guard.name,
                    details=all_details,
                )

        return GuardResult(
            score=combined_score,
            guard_name="orchestrator",
            details=all_details,
        )

    def check_output(self, text: str, context: dict | None = None) -> tuple[str, GuardResult]:
        """Tum output guard'larini calistir. Bloklanan icerik sanitize edilir."""
        current_text = text
        any_blocked = False
        reasons = []
        max_score = 0.0
        all_details = {}

        for guard in self.output_guards:
            result = guard.check(current_text, context)
            self.logger.log("output_check", guard.name, result, output_text=current_text)
            max_score = max(max_score, result.score)
            all_details[guard.name] = result.details

            if result.blocked:
                any_blocked = True
                reasons.append(f"[{guard.name}] {result.reason}")
                current_text = guard.sanitize(current_text, context)

        combined_result = GuardResult(
            blocked=any_blocked,
            reason=" | ".join(reasons),
            score=max_score,
            guard_name="orchestrator",
            details=all_details,
        )
        return current_text, combined_result

    def get_stats(self) -> dict:
        return self.logger.get_stats()

    def print_stats(self):
        self.logger.print_stats()
