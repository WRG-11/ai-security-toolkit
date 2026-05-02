"""
Ollama LLM Backend — Gerçek model ile saldırı/savunma testi.

Tier sistemi:
  T1 (Uncensored): dolphin-mistral — saldırı pratiği
  T2 (Weak RLHF):  qwen2.5:3b     — bypass pratiği
  T3 (Strong):     llama3.2:3b    — gelişmiş teknikler

Kullanım:
    from backend.ollama import OllamaBackend, ModelTier

    backend = OllamaBackend(tier=ModelTier.T1)
    response = backend.generate(system_prompt, user_message)
"""

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from enum import Enum


class ModelTier(Enum):
    T1_UNCENSORED = "t1"   # dolphin-mistral — güvenlik yok
    T2_WEAK = "t2"         # qwen2.5:3b — zayıf RLHF
    T3_STRONG = "t3"       # llama3.2:3b — güçlü alignment


TIER_MODELS = {
    ModelTier.T1_UNCENSORED: {
        "model": "dolphin-mistral",
        "label": "T1 — Uncensored (dolphin-mistral 7B)",
        "description": "Güvenlik eğitimi yok. Tüm temel saldırılar çalışır.",
        "expected_resistance": "Yok",
    },
    ModelTier.T2_WEAK: {
        "model": "qwen2.5:3b",
        "label": "T2 — Zayıf RLHF (Qwen 2.5 3B)",
        "description": "Basit RLHF. Bypass teknikleri gerekli.",
        "expected_resistance": "Zayıf (%82 jailbreak başarısı)",
    },
    ModelTier.T3_STRONG: {
        "model": "llama3.2:3b",
        "label": "T3 — Güçlü Alignment (Llama 3.2 3B)",
        "description": "Meta'nın çok katmanlı güvenlik eğitimi.",
        "expected_resistance": "Orta-iyi",
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
    """Ollama API ile gerçek LLM backend."""

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
        """Ollama sunucusu çalışıyor mu kontrol et."""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def list_models(self) -> list[str]:
        """Yüklü modelleri listele."""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                return [m["name"] for m in data.get("models", [])]
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            return []

    def model_exists(self) -> bool:
        """Seçili model yüklü mü?"""
        models = self.list_models()
        return any(self.model in m for m in models)

    def generate(
        self,
        system_prompt: str,
        user_message: str,
        **kwargs,
    ) -> OllamaResponse:
        """
        Ollama API ile yanıt üret.

        Not: response_rules ve default_response parametreleri
        mock uyumluluğu için kabul edilir ama kullanılmaz —
        gerçek model kendi yanıtını üretir.
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
                f"{self.base_url}/api/chat",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
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
                error=f"Ollama bağlantı hatası: {e}",
                model=self.model,
            )
        except json.JSONDecodeError as e:
            return OllamaResponse(
                content="",
                error=f"JSON parse hatası: {e}",
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
