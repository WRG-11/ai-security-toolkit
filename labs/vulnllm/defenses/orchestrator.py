"""
VulnLLM Defense — Orchestrator

Savunma modullerini pipeline olarak zincirler.
Input guard'lar fail-fast, output guard'lar sanitize-all.
"""

import logging

from .base import AuditLogger, GuardResult, InputGuard, OutputGuard

# R89-28b AI-CP-01 + AI-CP-02: pipeline-level error logger (separate
# from AuditLogger.log which is the structured event sink). Used to
# warn about guard / sanitize / audit failures without crashing the
# pipeline.
_log = logging.getLogger(__name__)


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

    def _safe_audit_log(self, event_type: str, guard_name: str, result: GuardResult, **kwargs) -> None:
        """R89-28b AI-CP-02: audit log failure must NOT crash the pipeline.

        Disk full / permission denied / serializer error -- log a
        warning and continue. Audit gaps are non-fatal; security
        pipeline interruption is fatal.
        """
        try:
            self.logger.log(event_type, guard_name, result, **kwargs)
        except Exception as exc:
            _log.warning(
                "Audit log failed for guard %s (%s): %s -- continuing",
                guard_name, event_type, exc,
            )

    def check_input(self, text: str, context: dict | None = None) -> GuardResult:
        """Tum input guard'larini calistir. Ilk bloklayan kazanir.

        R89-28b AI-CP-01: each guard.check() is wrapped in try/except.
        A guard exception is treated as FAIL-CLOSED at the guard level
        (input is blocked, reason=guard-internal-error) -- the
        pipeline does NOT crash and the downstream llm_firewall does
        NOT see an unhandled exception (which would then have been
        absorbed as blocked=False per AI-L2-03, producing a double
        fail-open chain).
        """
        combined_score = 0.0
        all_details = {}

        for guard in self.input_guards:
            try:
                result = guard.check(text, context)
            except Exception as exc:
                _log.error(
                    "Input guard %s.check() raised %s: %s -- fail-closed",
                    guard.name, type(exc).__name__, exc,
                )
                # R89-28b AI-CP-01: guard internal error -> fail-closed
                # (block) with a synthetic GuardResult.
                err_result = GuardResult(
                    blocked=True,
                    reason=f"{guard.name} internal error ({type(exc).__name__}); fail-closed",
                    score=1.0,
                    guard_name=guard.name,
                    details={"error": str(exc), "error_type": type(exc).__name__},
                )
                self._safe_audit_log("input_check", guard.name, err_result, input_text=text)
                all_details[guard.name] = err_result.details
                return GuardResult(
                    blocked=True,
                    reason=f"[{guard.name}] {err_result.reason}",
                    score=err_result.score,
                    guard_name=guard.name,
                    details=all_details,
                )

            self._safe_audit_log("input_check", guard.name, result, input_text=text)
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
        """Tum output guard'larini calistir. Bloklanan icerik sanitize edilir.

        R89-28b AI-CP-01: same fail-closed discipline as check_input,
        but on output side the 'fail-closed' state is treated as
        'block (do not show) + flag for sanitization fallback'. If a
        guard.check() AND its sanitize() both fail, the response is
        replaced with a redaction marker so attacker payload never
        reaches the user verbatim.
        """
        current_text = text
        any_blocked = False
        reasons = []
        max_score = 0.0
        all_details = {}

        for guard in self.output_guards:
            try:
                result = guard.check(current_text, context)
            except Exception as exc:
                _log.error(
                    "Output guard %s.check() raised %s: %s -- fail-closed (redact)",
                    guard.name, type(exc).__name__, exc,
                )
                any_blocked = True
                reasons.append(f"[{guard.name}] internal error ({type(exc).__name__}); fail-closed")
                # Redact: do NOT pass attacker-influenced content
                # downstream when we have no confidence that the
                # guard inspected it.
                current_text = "[RESPONSE_REDACTED_GUARD_ERROR]"
                all_details[guard.name] = {"error": str(exc), "error_type": type(exc).__name__}
                self._safe_audit_log(
                    "output_check", guard.name,
                    GuardResult(blocked=True, reason=reasons[-1], score=1.0,
                                guard_name=guard.name,
                                details=all_details[guard.name]),
                    output_text=current_text,
                )
                continue

            self._safe_audit_log("output_check", guard.name, result, output_text=current_text)
            max_score = max(max_score, result.score)
            all_details[guard.name] = result.details

            if result.blocked:
                any_blocked = True
                reasons.append(f"[{guard.name}] {result.reason}")
                try:
                    current_text = guard.sanitize(current_text, context)
                except Exception as exc:
                    _log.error(
                        "Output guard %s.sanitize() raised %s: %s -- redact fallback",
                        guard.name, type(exc).__name__, exc,
                    )
                    current_text = "[RESPONSE_REDACTED_SANITIZE_ERROR]"

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
