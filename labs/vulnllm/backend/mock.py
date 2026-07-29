"""
Mock LLM Backend — Deterministic vulnerable responses.

Simulates OWASP LLM Top 10 vulnerabilities without using a real LLM.
Each challenge defines its own response logic; this backend only
does pattern matching and response selection.
"""

import re
from dataclasses import dataclass, field


@dataclass
class LLMResponse:
    content: str
    tokens_used: int = 0
    blocked: bool = False
    block_reason: str = ""
    metadata: dict = field(default_factory=dict)


class MockBackend:
    """Pattern-based mock LLM."""

    def __init__(self):
        self.call_count = 0
        self.total_tokens = 0

    def generate(
        self,
        system_prompt: str,
        user_message: str,
        response_rules: list[dict],
        default_response: str = "I'm unable to help with that.",
    ) -> LLMResponse:
        """
        Rule-based response generation.

        response_rules format:
        [
            {
                "pattern": r"regex pattern",
                "response": "response text",
                "flags": re.IGNORECASE,  # optional
                "tokens": 50,            # optional
                "metadata": {},          # optional
            },
            ...
        ]

        Rules are checked in order; the first match wins.
        """
        self.call_count += 1

        for rule in response_rules:
            flags = rule.get("flags", re.IGNORECASE | re.DOTALL)
            pattern = rule["pattern"]

            if re.search(pattern, user_message, flags):
                tokens = rule.get("tokens", len(rule["response"].split()) * 2)
                self.total_tokens += tokens
                return LLMResponse(
                    content=rule["response"],
                    tokens_used=tokens,
                    metadata=rule.get("metadata", {}),
                )

        tokens = len(default_response.split()) * 2
        self.total_tokens += tokens
        return LLMResponse(
            content=default_response,
            tokens_used=tokens,
        )

    def get_stats(self) -> dict:
        return {
            "total_calls": self.call_count,
            "total_tokens": self.total_tokens,
        }

    def reset(self):
        self.call_count = 0
        self.total_tokens = 0
