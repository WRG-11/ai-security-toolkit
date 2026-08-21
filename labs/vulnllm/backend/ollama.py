"""
Ollama LLM Backend — Attack/defense testing against a real model.

Tier system:
  T1 (Uncensored): dolphin-mistral — attack practice
  T2 (Weak RLHF):  qwen2.5:3b     — bypass practice
  T3 (Strong):     llama3.2:3b    — advanced techniques

Usage:
    from backend.ollama import OllamaBackend, ModelTier

    backend = OllamaBackend(tier=ModelTier.T1)
    response = backend.generate(system_prompt, user_message)
"""

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum


def _http_only(url: str) -> str:
    """Reject any scheme other than http/https before the URL is fetched.

    `urllib.request.urlopen` honours `file://`, `ftp://` and custom schemes,
    so a URL arriving from configuration is a local-file read waiting to
    happen. The endpoints here default to localhost, but they are
    parameters -- and this is a security toolkit, so the check belongs in
    the code rather than in a reviewer's memory.
    """
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"only http/https URLs are allowed, got: {url!r}")
    return url


class ModelTier(Enum):
    T1_UNCENSORED = "t1"   # dolphin-mistral — no safety training
    T2_WEAK = "t2"         # qwen2.5:3b — weak RLHF
    T3_STRONG = "t3"       # llama3.2:3b — strong alignment


TIER_MODELS = {
    ModelTier.T1_UNCENSORED: {
        "model": "dolphin-mistral",
        "label": "T1 — Uncensored (dolphin-mistral 7B)",
        "description": "No safety training. All basic attacks work.",
        "expected_resistance": "None",
    },
    ModelTier.T2_WEAK: {
        "model": "qwen2.5:3b",
        "label": "T2 — Weak RLHF (Qwen 2.5 3B)",
        "description": "Basic RLHF. Bypass techniques required.",
        "expected_resistance": "Weak (82% jailbreak success rate)",
    },
    ModelTier.T3_STRONG: {
        "model": "llama3.2:3b",
        "label": "T3 — Strong Alignment (Llama 3.2 3B)",
        "description": "Meta's multi-layer safety training.",
        "expected_resistance": "Medium-good",
    },
}


@dataclass
class OllamaResponse:
    content: str
    tokens_used: int = 0
    model: str = ""
    blocked: bool = False
    block_reason: str = ""
    metadata: dict = field(default_factory=dict)
    error: str = ""


class OllamaBackend:
    """Real LLM backend via the Ollama API."""

    def __init__(
        self,
        tier: ModelTier = ModelTier.T1_UNCENSORED,
        model_override: str | None = None,
        base_url: str = "http://localhost:11434",
        timeout: int = 60,
        max_tokens: int = 512,
        temperature: float = 0.7,
    ):
        self.tier = tier
        self.tier_info = TIER_MODELS[tier]
        self.model = model_override or self.tier_info["model"]
        self.base_url = base_url
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.call_count = 0
        self.total_tokens = 0

    def is_available(self) -> bool:
        """Check whether the Ollama server is running."""
        try:
            req = urllib.request.Request(_http_only(f"{self.base_url}/api/tags"))
            # nosec B310: the URL passed through _http_only above, which
            # rejects every scheme other than http/https. bandit does not
            # do flow analysis, so it cannot see that check from here.
            with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def list_models(self) -> list[str]:
        """List installed models."""
        try:
            req = urllib.request.Request(_http_only(f"{self.base_url}/api/tags"))
            with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310: scheme validated by _http_only (bandit has no flow analysis)
                data = json.loads(resp.read().decode())
                return [m["name"] for m in data.get("models", [])]
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            return []

    def model_exists(self) -> bool:
        """Is the selected model installed?"""
        models = self.list_models()
        return any(self.model in m for m in models)

    def generate(
        self,
        system_prompt: str,
        user_message: str,
        **kwargs,
    ) -> OllamaResponse:
        """
        Generate a response via the Ollama API.

        Note: the response_rules and default_response parameters
        are accepted for mock compatibility but are unused — the
        real model generates its own response.
        """
        self.call_count += 1

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "stream": False,
            "options": {
                "num_predict": self.max_tokens,
                "temperature": self.temperature,
            },
        }

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                _http_only(f"{self.base_url}/api/chat"),
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310: scheme validated by _http_only (bandit has no flow analysis)
                result = json.loads(resp.read().decode())

            content = result.get("message", {}).get("content", "")
            eval_count = result.get("eval_count", len(content.split()) * 2)
            self.total_tokens += eval_count

            return OllamaResponse(
                content=content,
                tokens_used=eval_count,
                model=self.model,
                metadata={
                    "tier": self.tier.value,
                    "total_duration_ns": result.get("total_duration", 0),
                    "eval_count": eval_count,
                    "prompt_eval_count": result.get("prompt_eval_count", 0),
                },
            )

        except urllib.error.URLError as e:
            return OllamaResponse(
                content="",
                error=f"Ollama connection error: {e}",
                model=self.model,
            )
        except json.JSONDecodeError as e:
            return OllamaResponse(
                content="",
                error=f"JSON parse error: {e}",
                model=self.model,
            )
        except Exception as e:
            return OllamaResponse(
                content="",
                error=f"Beklenmeyen hata: {e}",
                model=self.model,
            )

    def get_stats(self) -> dict:
        return {
            "model": self.model,
            "tier": self.tier.value,
            "tier_label": self.tier_info["label"],
            "total_calls": self.call_count,
            "total_tokens": self.total_tokens,
        }

    def reset(self):
        self.call_count = 0
        self.total_tokens = 0
