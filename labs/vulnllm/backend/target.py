"""
Target backend -- play the lab against any LLM.

Any provider tools/targets.py speaks: OpenAI-compatible APIs (OpenAI, Groq,
OpenRouter, vLLM, Ollama, ...), Anthropic, Gemini, or a generic HTTP endpoint.
It replaces the old Ollama backend and its three model "tiers", which named
three 2024 models and carried success-rate claims nothing measured.

Without a target the lab uses the deterministic mock backend.
"""

import sys
from pathlib import Path

from .mock import LLMResponse

# The target layer lives in tools/; the lab runs from the checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from targets import Target, TargetError, send_with_retry  # noqa: E402


class TargetBackend:
    """Asks a real model. Same generate() shape as MockBackend."""

    def __init__(self, target: Target):
        self.target = target
        self.model = getattr(target, "model", None) or type(target).__name__
        self.call_count = 0

    def generate(self, system_prompt: str, user_message: str, **kwargs) -> LLMResponse:
        """response_rules / default_response are the mock's; a real model ignores them."""
        self.call_count += 1
        try:
            reply = send_with_retry(self.target, [{"role": "user", "content": user_message}], system_prompt)
        except TargetError as e:
            return LLMResponse(content=f"[MODEL ERROR] {e}", metadata={"error": str(e), "model": self.model})
        if reply.refused_by_provider:
            return LLMResponse(
                content=reply.text or f"[refused by the provider: {reply.refusal_reason}]",
                metadata={"refused_by_provider": True, "refusal_reason": reply.refusal_reason,
                          "model": self.model},
            )
        return LLMResponse(content=reply.text, metadata={"model": self.model, "elapsed_ms": reply.elapsed_ms})

    def get_stats(self) -> dict:
        return {"model": self.model, "call_count": self.call_count}
