"""llm_scanner's probe sender used to be hardcoded to Ollama's native
`/api/chat` shape -- fine for scanning your own local model, but it meant
the scanner could never point at anyone else's deployed LLM endpoint (the
exact workflow a "send me your system prompt + API endpoint, get a written
report" audit needs).

This adds an OpenAI-compatible `/chat/completions` sender alongside the
existing Ollama one, selected via `--api-mode`. Ollama itself also serves
an OpenAI-compatible endpoint, so the same local model can be probed
through either code path -- proving the new path is genuinely
endpoint-agnostic, not just a relabeled copy of the Ollama-specific one.

All HTTP is mocked (`urllib.request.urlopen`) -- no real network calls in
this file. The live, real-network proof is a separate manual run recorded
in the ai-security-toolkit CHANGELOG, not a test (a test that requires a
running local LLM would not run in CI).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import llm_scanner as m  # noqa: E402


def _fake_http_response(payload: dict, status: int = 200):
    resp = MagicMock()
    resp.status = status
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


def test_send_probe_openai_posts_to_chat_completions_path():
    """Endpoint shape: POST {base_url}/chat/completions, OpenAI message body."""
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _fake_http_response({
            "choices": [{"message": {"content": "I can't help with that."}}]
        })

    with patch.object(m.urllib.request, "urlopen", side_effect=fake_urlopen):
        text, elapsed_ms = m.send_probe_openai(
            "https://api.example.com/v1", "gpt-test", "system prompt", "payload text", timeout=5,
        )

    assert captured["url"] == "https://api.example.com/v1/chat/completions"
    assert captured["body"]["model"] == "gpt-test"
    assert captured["body"]["messages"] == [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "payload text"},
    ]
    assert text == "I can't help with that."
    assert elapsed_ms >= 0


def test_send_probe_openai_sends_bearer_auth_header_when_api_key_given():
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.headers)
        return _fake_http_response({"choices": [{"message": {"content": "ok"}}]})

    with patch.object(m.urllib.request, "urlopen", side_effect=fake_urlopen):
        m.send_probe_openai(
            "https://api.example.com/v1", "gpt-test", "sp", "payload", timeout=5, api_key="sk-secret",
        )

    assert captured["headers"].get("Authorization") == "Bearer sk-secret"


def test_send_probe_openai_no_auth_header_when_no_api_key():
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.headers)
        return _fake_http_response({"choices": [{"message": {"content": "ok"}}]})

    with patch.object(m.urllib.request, "urlopen", side_effect=fake_urlopen):
        m.send_probe_openai("https://api.example.com/v1", "gpt-test", "sp", "payload", timeout=5)

    assert "Authorization" not in captured["headers"]


def test_send_probe_openai_rejects_non_http_scheme():
    """Same _http_only guard the Ollama sender already has -- a base_url
    from config is still attacker-influenceable input."""
    import pytest
    with pytest.raises(ValueError):
        m.send_probe_openai("file:///etc/passwd", "m", "sp", "payload", timeout=5)


def test_scanner_openai_mode_dispatches_to_send_probe_openai(monkeypatch):
    """LLMScanner(api_mode='openai') must call the new sender, not the
    Ollama one -- the whole point of this wave. A monkeypatch on each
    function proves which one actually ran."""
    calls = {"ollama": 0, "openai": 0}

    def fake_ollama(*a, **k):
        calls["ollama"] += 1
        return "unused", 1

    def fake_openai(*a, **k):
        calls["openai"] += 1
        return "I can't help with that.", 1

    monkeypatch.setattr(m, "send_probe", fake_ollama)
    monkeypatch.setattr(m, "send_probe_openai", fake_openai)

    scanner = m.LLMScanner(
        model="gpt-test", ollama_url="https://api.example.com/v1",
        api_mode="openai", api_key="sk-test",
    )
    report = scanner.scan(quick=True)

    assert calls["openai"] > 0
    assert calls["ollama"] == 0
    assert report.total_probes > 0


def test_scanner_default_mode_is_still_ollama(monkeypatch):
    """Backward compatibility: no --api-mode given must behave exactly as
    before this wave -- existing users/scripts must not silently change
    behaviour."""
    calls = {"ollama": 0, "openai": 0}
    monkeypatch.setattr(m, "send_probe", lambda *a, **k: (calls.__setitem__("ollama", calls["ollama"] + 1), ("unused", 1))[1])
    monkeypatch.setattr(m, "send_probe_openai", lambda *a, **k: (calls.__setitem__("openai", calls["openai"] + 1), ("unused", 1))[1])

    scanner = m.LLMScanner(model="llama3.2:3b")
    scanner.scan(quick=True)

    assert calls["ollama"] > 0
    assert calls["openai"] == 0
