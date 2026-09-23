"""One interface in front of any LLM: the toolkit's target layer.

The scanner, the firewall proxy and the labs used to speak Ollama's native API
only, with model names such as `llama3.2:3b` built in. This module lets every
one of them point at any model instead:

    openai-compatible   OpenAI, Azure, Groq, Together, OpenRouter, Mistral,
                        DeepSeek, vLLM, LM Studio, Ollama's /v1 ... anything
                        that serves POST {base_url}/chat/completions
    anthropic           Anthropic Messages API
    gemini              Google Gemini API (generateContent)
    http                any other chat endpoint: a JSON body template plus
                        the path to the answer in the response

Stdlib only (urllib), like the rest of `tools/`: no provider SDKs.

Wire formats were checked against each provider's official SDK source on
2026-09-23, not against a live account. Tests replay those shapes from a local
server (tests/test_targets.py).

A provider's own safety system can withhold an answer: OpenAI's
`message.refusal` / `finish_reason == "content_filter"`, Anthropic's
`stop_reason == "refusal"`, Gemini's safety `finishReason` or
`promptFeedback.blockReason`. Such a reply is returned with
`refused_by_provider=True`, not raised as an error: for a scanner it means the
attack did not get through, and scoring it as an error or an empty answer would
make the same model look different depending on who hosts it.

API keys: read from environment variables by `build_target`, never logged,
kept out of `repr`, and never sent over plain http to anything but localhost.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

Message = dict  # {"role": "user" | "assistant", "content": str}

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}
# urllib's default "Python-urllib/3.x" is refused by Cloudflare-fronted APIs
# with 403 "error code: 1010" (measured 2026-09-23, every model of one
# provider). An honest, explicit User-Agent gets through.
USER_AGENT = "ai-security-toolkit (+https://github.com/WRG-11/ai-security-toolkit)"


@dataclass(frozen=True)
class Reply:
    text: str
    refused_by_provider: bool = False
    refusal_reason: str = ""
    elapsed_ms: int = 0


class TargetError(Exception):
    """A request that did not produce an answer (HTTP error, timeout, bad body)."""

    def __init__(self, message: str, status: int | None = None,
                 retryable: bool = False, retry_after: float | None = None):
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        self.retry_after = retry_after


class Target(Protocol):
    def send(self, messages: list[Message], system: str | None = None) -> Reply: ...


def _check_url(url: str, has_key: bool) -> str:
    """http(s) only; and a key never travels in clear text off this machine."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"only http/https URLs are allowed, got: {url!r}")
    if has_key and parsed.scheme == "http" and (parsed.hostname or "") not in _LOCAL_HOSTS:
        raise ValueError(f"refusing to send an API key over plain http to {parsed.hostname!r}; use https")
    return url


def _redact(text: str, secret: str | None) -> str:
    return text.replace(secret, "***") if secret else text


def _post_json(url: str, headers: dict, body: dict, timeout: float, secret: str | None) -> tuple[Any, int]:
    """POST JSON, return (parsed body, elapsed ms). Every failure is a TargetError."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", "User-Agent": USER_AGENT, **headers})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310: scheme validated by _check_url
            raw = resp.read()
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            payload = json.loads(e.read() or b"{}")
            err = payload.get("error", payload) if isinstance(payload, dict) else payload
            detail = err.get("message", "") if isinstance(err, dict) else str(err)
        except (ValueError, OSError):
            pass
        retry_after = None
        header = e.headers.get("Retry-After") if e.headers else None
        if header:
            try:
                retry_after = float(header)
            except ValueError:
                pass  # an HTTP-date form: fall back to exponential backoff
        msg = _redact(f"HTTP {e.code} from {urllib.parse.urlparse(url).hostname}: {detail or e.reason}", secret)
        raise TargetError(msg, status=e.code, retryable=e.code in _RETRYABLE_STATUS,
                          retry_after=retry_after) from None
    except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
        reason = getattr(e, "reason", e)
        raise TargetError(_redact(f"cannot reach {urllib.parse.urlparse(url).hostname}: {reason}", secret),
                          retryable=True) from None
    elapsed = int((time.monotonic() - start) * 1000)
    try:
        return json.loads(raw.decode("utf-8")), elapsed
    except (ValueError, UnicodeDecodeError):
        raise TargetError("response is not JSON") from None


def _error_from_body(err: dict, secret: str | None) -> TargetError:
    """A TargetError for an error object that arrived in a 2xx body."""
    code = err.get("code")
    status = code if isinstance(code, int) else None
    msg = _redact(f"provider error{f' {status}' if status else ''}: {err.get('message') or err}", secret)
    return TargetError(msg, status=status, retryable=status in _RETRYABLE_STATUS)


def _require_model(model: str) -> None:
    if not model or not model.strip():
        raise ValueError("a model name is required; there is no default model")


@dataclass
class OpenAICompatible:
    """POST {base_url}/chat/completions."""
    model: str
    base_url: str
    api_key: str | None = field(default=None, repr=False)
    timeout: float = 60.0
    max_tokens: int | None = None  # omitted unless set: some OpenAI models reject it
    temperature: float | None = None  # omitted unless set: some OpenAI models accept only 1

    def __post_init__(self):
        _require_model(self.model)
        self.base_url = _check_url(self.base_url.rstrip("/"), bool(self.api_key))

    def send(self, messages: list[Message], system: str | None = None) -> Reply:
        msgs = ([{"role": "system", "content": system}] if system else []) + list(messages)
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        body: dict = {"model": self.model, "messages": msgs, "stream": False}
        if self.max_tokens:
            body["max_tokens"] = self.max_tokens
        if self.temperature is not None:
            body["temperature"] = self.temperature
        data, ms = _post_json(f"{self.base_url}/chat/completions", headers, body, self.timeout, self.api_key)
        if isinstance(data, dict) and not data.get("choices") and isinstance(data.get("error"), dict):
            # Some gateways send a provider failure as HTTP 200 with an error
            # object; it used to surface as "no choices[0]" with the reason lost.
            raise _error_from_body(data["error"], self.api_key)
        try:
            choice = data["choices"][0]
            message = choice.get("message") or {}
        except (KeyError, IndexError, TypeError, AttributeError):
            raise TargetError("unexpected response: no choices[0]") from None
        if message.get("refusal"):
            return Reply(message["refusal"], True, "refusal", ms)
        if choice.get("finish_reason") == "content_filter":
            return Reply(message.get("content") or "", True, "content_filter", ms)
        return Reply(message.get("content") or "", elapsed_ms=ms)


@dataclass
class Anthropic:
    """POST {base_url}/v1/messages (Anthropic Messages API)."""
    model: str
    api_key: str | None = field(default=None, repr=False)
    base_url: str = "https://api.anthropic.com"
    max_tokens: int = 1024
    timeout: float = 60.0
    temperature: float | None = None

    def __post_init__(self):
        _require_model(self.model)
        self.base_url = _check_url(self.base_url.rstrip("/"), bool(self.api_key))

    def send(self, messages: list[Message], system: str | None = None) -> Reply:
        body: dict = {"model": self.model, "max_tokens": self.max_tokens, "messages": list(messages)}
        if system:
            body["system"] = system
        if self.temperature is not None:
            body["temperature"] = self.temperature
        headers = {"x-api-key": self.api_key or "", "anthropic-version": "2023-06-01"}
        data, ms = _post_json(f"{self.base_url}/v1/messages", headers, body, self.timeout, self.api_key)
        if not isinstance(data, dict):
            raise TargetError("unexpected response: not an object")
        text = "".join(b.get("text", "") for b in data.get("content") or []
                       if isinstance(b, dict) and b.get("type") == "text")
        if data.get("stop_reason") == "refusal":
            return Reply(text, True, "refusal", ms)
        return Reply(text, elapsed_ms=ms)


# finishReason values where Gemini withheld the answer itself.
_GEMINI_BLOCKED = {"SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "RECITATION",
                   "IMAGE_SAFETY", "IMAGE_PROHIBITED_CONTENT"}


@dataclass
class Gemini:
    """POST {base_url}/v1beta/models/{model}:generateContent. The key goes in a header, never the URL."""
    model: str
    api_key: str | None = field(default=None, repr=False)
    base_url: str = "https://generativelanguage.googleapis.com"
    timeout: float = 60.0
    max_tokens: int | None = None
    temperature: float | None = None

    def __post_init__(self):
        _require_model(self.model)
        self.base_url = _check_url(self.base_url.rstrip("/"), bool(self.api_key))

    def send(self, messages: list[Message], system: str | None = None) -> Reply:
        contents = [{"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
                    for m in messages]
        body: dict = {"contents": contents}
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        generation: dict = {}
        if self.max_tokens:
            generation["maxOutputTokens"] = self.max_tokens
        if self.temperature is not None:
            generation["temperature"] = self.temperature
        if generation:
            body["generationConfig"] = generation
        name = self.model[len("models/"):] if self.model.startswith("models/") else self.model
        url = f"{self.base_url}/v1beta/models/{urllib.parse.quote(name, safe='-._')}:generateContent"
        data, ms = _post_json(url, {"x-goog-api-key": self.api_key or ""}, body, self.timeout, self.api_key)
        if not isinstance(data, dict):
            raise TargetError("unexpected response: not an object")
        candidates = data.get("candidates") or []
        if not candidates:
            block = (data.get("promptFeedback") or {}).get("blockReason")
            if block:
                return Reply("", True, block, ms)
            raise TargetError("unexpected response: no candidates and no blockReason")
        cand = candidates[0]
        text = "".join(p.get("text", "") for p in (cand.get("content") or {}).get("parts") or []
                       if isinstance(p, dict))
        finish = cand.get("finishReason", "")
        if finish in _GEMINI_BLOCKED:
            return Reply(text, True, finish, ms)
        return Reply(text, elapsed_ms=ms)


_PLACEHOLDER = re.compile(r"\{\{(prompt|system)\}\}")


@dataclass
class GenericHTTP:
    """Any other chat endpoint.

    `body_template` is a JSON document whose string values may contain
    {{prompt}} (the last user message) and {{system}}. Values are substituted
    after parsing, in one pass, so a prompt containing quotes, braces or the
    text "{{system}}" arrives verbatim. `response_path` is a dotted path to the
    answer, with integer segments for list indices: "data.answers.0.text".
    """
    url: str
    body_template: str
    response_path: str
    api_key: str | None = field(default=None, repr=False)
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    timeout: float = 60.0

    def __post_init__(self):
        self.url = _check_url(self.url, bool(self.api_key))
        try:
            self._template = json.loads(self.body_template)
        except ValueError as e:
            raise ValueError(f"body_template is not valid JSON: {e}") from None
        if "{{prompt}}" not in self.body_template:
            raise ValueError("body_template must contain {{prompt}}")
        if not self.response_path:
            raise ValueError("response_path is required")

    def _fill(self, node: Any, values: dict) -> Any:
        if isinstance(node, str):
            return _PLACEHOLDER.sub(lambda m: values[m.group(1)], node)
        if isinstance(node, list):
            return [self._fill(v, values) for v in node]
        if isinstance(node, dict):
            return {k: self._fill(v, values) for k, v in node.items()}
        return node

    def send(self, messages: list[Message], system: str | None = None) -> Reply:
        prompt = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        body = self._fill(self._template, {"prompt": prompt, "system": system or ""})
        headers = {self.auth_header: f"{self.auth_prefix}{self.api_key}"} if self.api_key else {}
        data, ms = _post_json(self.url, headers, body, self.timeout, self.api_key)
        node = data
        for part in self.response_path.split("."):
            try:
                node = node[int(part)] if isinstance(node, list) else node[part]
            except (KeyError, IndexError, ValueError, TypeError):
                raise TargetError(f"response_path {self.response_path!r} not found in the response") from None
        if not isinstance(node, str):
            raise TargetError(f"response_path {self.response_path!r} is not a string")
        return Reply(node, elapsed_ms=ms)


def send_with_retry(target: Target, messages: list[Message], system: str | None = None,
                    retries: int = 2, base_delay: float = 1.0, max_delay: float = 30.0) -> Reply:
    """send(), retrying rate limits, overloads and connection failures with backoff."""
    for attempt in range(retries + 1):
        try:
            return target.send(messages, system)
        except TargetError as e:
            if not e.retryable or attempt == retries:
                raise
            delay = e.retry_after if e.retry_after is not None else base_delay * (2 ** attempt)
            time.sleep(min(max(delay, 0.0), max_delay))
    raise AssertionError("unreachable")


# provider -> (default base URL, env var holding the key, key required)
_PROVIDERS: dict[str, tuple[str | None, str | None, bool]] = {
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY", True),
    "openai-compatible": (None, None, False),
    "ollama": ("http://localhost:11434/v1", None, False),
    "anthropic": ("https://api.anthropic.com", "ANTHROPIC_API_KEY", True),
    "gemini": ("https://generativelanguage.googleapis.com", "GEMINI_API_KEY", True),
    "http": (None, None, False),
}
PROVIDERS = tuple(_PROVIDERS)


def build_target(provider: str, model: str, *, base_url: str | None = None,
                 api_key_env: str | None = None, env: Mapping[str, str] | None = None,
                 timeout: float = 60.0, body_template: str | None = None,
                 response_path: str | None = None, max_tokens: int | None = None,
                 temperature: float | None = None) -> Target:
    """The one place a target is configured. Keys come from the environment only."""
    if provider not in _PROVIDERS:
        raise ValueError(f"unknown provider {provider!r}; choose one of: {', '.join(PROVIDERS)}")
    env = os.environ if env is None else env
    default_url, default_key_env, key_required = _PROVIDERS[provider]
    key_var = api_key_env or default_key_env
    api_key = env.get(key_var) if key_var else None
    if key_required and not api_key:
        raise ValueError(f"{provider} needs an API key in the environment variable {key_var}")
    url = base_url or default_url

    if provider == "http":
        if not (url and body_template and response_path):
            raise ValueError("provider 'http' needs --base-url, --body-template and --response-path")
        return GenericHTTP(url=url, body_template=body_template, response_path=response_path,
                           api_key=api_key, timeout=timeout)
    _require_model(model)
    if provider == "anthropic":
        return Anthropic(model=model, api_key=api_key, base_url=url or "", timeout=timeout,
                         temperature=temperature, **({"max_tokens": max_tokens} if max_tokens else {}))
    if provider == "gemini":
        return Gemini(model=model, api_key=api_key, base_url=url or "", timeout=timeout, max_tokens=max_tokens,
                      temperature=temperature)
    if not url:
        raise ValueError(f"provider {provider!r} needs a base URL (--base-url)")
    return OpenAICompatible(model=model, base_url=url, api_key=api_key, timeout=timeout, max_tokens=max_tokens,
                            temperature=temperature)
