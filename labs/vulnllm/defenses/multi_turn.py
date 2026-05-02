"""
Module #11 — Multi-Turn Conversation Tracker

Crescendo ve kademeli saldiri tespiti icin cross-turn risk takibi.
Her tur icin risk skoru hesaplar, kumulatif risk biriktir, eskalasyon tespit et.

Ref: Microsoft Crescendo Attack, PyRIT orchestrator
"""

import re
import math
import time
from dataclasses import dataclass, field
from .base import InputGuard, GuardResult


@dataclass
class SessionState:
    turn_count: int = 0
    risk_scores: list = field(default_factory=list)
    cumulative_risk: float = 0.0
    last_timestamp: float = 0.0
    escalation_count: int = 0


# Hafif risk keyword'leri (PromptInjectionClassifier'dan subset)
RISK_KEYWORDS: list[tuple[str, float]] = [
    # Override
    ("ignore previous", 0.8), ("forget everything", 0.8),
    ("override", 0.6), ("bypass", 0.6), ("unut", 0.7),
    # Extraction
    ("system prompt", 0.7), ("show instructions", 0.7),
    ("api key", 0.8), ("password", 0.6), ("secret", 0.6),
    ("sifre", 0.7), ("gizli", 0.5),
    # Jailbreak
    ("DAN", 0.9), ("jailbreak", 0.9), ("developer mode", 0.8),
    ("unrestricted", 0.7), ("no limits", 0.7),
    # Escalation
    ("now tell me", 0.4), ("but what about", 0.3),
    ("one more thing", 0.3), ("actually", 0.2),
    ("peki ya", 0.3), ("bir de", 0.3), ("simdi de", 0.4),
]


class MultiTurnTracker(InputGuard):
    """
    Cross-turn kumulatif risk takibi.

    Risk hesaplama:
      turn_risk = keyword bazli skor (0-1)
      cumulative = turn_risk * 0.4 + previous_cumulative * 0.6 * decay
      decay = exp(-0.1 * dakika_farki)

    Eskalasyon tespiti:
      Son 3 turda monoton artan risk → bonus
    """
    name = "MultiTurnTracker"

    def __init__(self, threshold: float = 0.7, max_sessions: int = 1000,
                 max_turns_per_session: int = 50):
        self.threshold = threshold
        self.max_sessions = max_sessions
        self.max_turns = max_turns_per_session
        self.sessions: dict[str, SessionState] = {}

    def _get_session(self, context: dict | None) -> tuple[str, SessionState]:
        session_id = (context or {}).get("session_id", "default")
        if session_id not in self.sessions:
            if len(self.sessions) >= self.max_sessions:
                # En eski session'i sil
                oldest = min(self.sessions, key=lambda k: self.sessions[k].last_timestamp)
                del self.sessions[oldest]
            self.sessions[session_id] = SessionState()
        return session_id, self.sessions[session_id]

    def _compute_turn_risk(self, text: str) -> float:
        lower = text.lower()
        max_risk = 0.0
        for keyword, weight in RISK_KEYWORDS:
            if keyword.lower() in lower:
                max_risk = max(max_risk, weight)
        return max_risk

    def _detect_escalation(self, session: SessionState) -> bool:
        """Son 3 turda monoton artan risk → eskalasyon."""
        if len(session.risk_scores) < 3:
            return False
        last3 = session.risk_scores[-3:]
        return last3[0] < last3[1] < last3[2] and last3[2] > 0.3

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        session_id, session = self._get_session(context)
        now = time.time()

        # Turn risk hesapla
        turn_risk = self._compute_turn_risk(text)

        # Zaman bazli decay
        if session.last_timestamp > 0:
            minutes_elapsed = (now - session.last_timestamp) / 60.0
            decay = math.exp(-0.1 * minutes_elapsed)
        else:
            decay = 1.0

        # Kumulatif risk guncelle
        session.cumulative_risk = turn_risk * 0.4 + session.cumulative_risk * 0.6 * decay
        session.risk_scores.append(turn_risk)
        session.turn_count += 1
        session.last_timestamp = now

        # Turn limiti
        if session.turn_count > self.max_turns:
            session.risk_scores = session.risk_scores[-self.max_turns:]

        # Eskalasyon tespiti → bonus
        is_escalating = self._detect_escalation(session)
        if is_escalating:
            session.cumulative_risk = min(session.cumulative_risk + 0.15, 1.0)
            session.escalation_count += 1

        blocked = session.cumulative_risk >= self.threshold

        return GuardResult(
            blocked=blocked,
            reason=f"Multi-turn risk: kumulatif={session.cumulative_risk:.2f} "
                   f"(esik={self.threshold}, tur={session.turn_count})"
                   + (" [ESKALASYON]" if is_escalating else "") if blocked else "",
            score=session.cumulative_risk,
            guard_name=self.name,
            details={
                "session_id": session_id,
                "turn": session.turn_count,
                "turn_risk": round(turn_risk, 3),
                "cumulative_risk": round(session.cumulative_risk, 3),
                "is_escalating": is_escalating,
                "escalation_count": session.escalation_count,
                "last_3_risks": [round(r, 2) for r in session.risk_scores[-3:]],
            },
        )

    def get_session_summary(self, session_id: str) -> dict | None:
        s = self.sessions.get(session_id)
        if not s:
            return None
        return {
            "turns": s.turn_count,
            "cumulative_risk": round(s.cumulative_risk, 3),
            "escalation_count": s.escalation_count,
            "avg_risk": round(sum(s.risk_scores) / max(len(s.risk_scores), 1), 3),
        }

    def reset_session(self, session_id: str):
        self.sessions.pop(session_id, None)
