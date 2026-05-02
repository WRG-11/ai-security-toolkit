"""
Mock LLM Backend — Deterministik zafiyetli yanıtlar.

Gerçek LLM kullanmadan OWASP LLM Top 10 zafiyetlerini simüle eder.
Her challenge kendi yanıt mantığını tanımlar, bu backend sadece
pattern matching ve yanıt seçimi yapar.
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
        default_response: str = "Bu konuda size yardımcı olamıyorum.",
    ) -> LLMResponse:
        """
        Kural tabanlı yanıt üretimi.

        response_rules formatı:
        [
            {
                "pattern": r"regex pattern",
                "response": "yanıt metni",
                "flags": re.IGNORECASE,  # opsiyonel
                "tokens": 50,            # opsiyonel
                "metadata": {},          # opsiyonel
            },
            ...
        ]

        Kurallar sırayla kontrol edilir, ilk eşleşen kazanır.
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
