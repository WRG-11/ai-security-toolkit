"""tools/targets.py: one interface in front of any LLM provider.

Every adapter is tested against a local HTTP server that records the request
and plays back a response in the provider's documented shape. No API key and
no network access are needed. The shapes were checked against the providers'
official SDK sources on 2026-09-23:

* OpenAI-compatible: `choices[0].message.content`; a provider-side refusal is
  `message.refusal` or `finish_reason == "content_filter"`.
* Anthropic: POST /v1/messages with `x-api-key` and `anthropic-version:
  2023-06-01`; text in `content[].text`; `stop_reason == "refusal"`.
* Gemini: POST /v1beta/models/{model}:generateContent with `x-goog-api-key`;
  text in `candidates[0].content.parts[].text`; blocks via `finishReason` or
  `promptFeedback.blockReason`.

What this does NOT show: that a live provider still answers in that shape.
"""
from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import targets as t  # noqa: E402

KEY = "sk-test-DO-NOT-LEAK-1234567890"


class _Fake:
    """A local server that records each request and replies with a script."""

    def __init__(self):
        self.requests: list[dict] = []
        self.script: list[tuple[int, dict, dict]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                fake.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                                      "body": body})
                status, payload, headers = fake.script.pop(0) if fake.script else (200, {}, {})
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def reply(self, payload, status=200, headers=None):
        self.script.append((status, payload, headers or {}))
        return self

    @property
    def last(self):
        return self.requests[-1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class _FakeCase(unittest.TestCase):
    def setUp(self):
        self.fake = _Fake()

    def tearDown(self):
        self.fake.close()


def _openai_ok(text="hi", refusal=None, finish="stop"):
    return {"choices": [{"index": 0, "finish_reason": finish,
                         "message": {"role": "assistant", "content": text, "refusal": refusal}}]}


class OpenAICompatible(_FakeCase):
    def test_request_shape_and_text(self):
        self.fake.reply(_openai_ok("hello there"))
        target = t.OpenAICompatible(model="m1", base_url=self.fake.url + "/v1", api_key=KEY)
        reply = target.send([{"role": "user", "content": "ping"}], system="be safe")
        self.assertEqual(reply.text, "hello there")
        self.assertFalse(reply.refused_by_provider)
        req = self.fake.last
        self.assertEqual(req["path"], "/v1/chat/completions")
        self.assertEqual(req["headers"]["authorization"], f"Bearer {KEY}")
        self.assertEqual(req["body"]["model"], "m1")
        self.assertEqual(req["body"]["messages"],
                         [{"role": "system", "content": "be safe"}, {"role": "user", "content": "ping"}])

    def test_no_key_no_auth_header(self):
        self.fake.reply(_openai_ok())
        t.OpenAICompatible(model="m", base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        self.assertNotIn("authorization", self.fake.last["headers"])

    def test_refusal_field_is_a_provider_refusal(self):
        self.fake.reply(_openai_ok(text=None, refusal="I can't help with that."))
        reply = t.OpenAICompatible(model="m", base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        self.assertTrue(reply.refused_by_provider)
        self.assertEqual(reply.text, "I can't help with that.")

    def test_content_filter_is_a_provider_refusal(self):
        self.fake.reply(_openai_ok(text="", finish="content_filter"))
        reply = t.OpenAICompatible(model="m", base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        self.assertTrue(reply.refused_by_provider)
        self.assertEqual(reply.refusal_reason, "content_filter")


class Anthropic(_FakeCase):
    def test_request_shape_and_text(self):
        self.fake.reply({"type": "message", "stop_reason": "end_turn",
                         "content": [{"type": "text", "text": "part one "}, {"type": "text", "text": "two"}]})
        target = t.Anthropic(model="claude-x", api_key=KEY, base_url=self.fake.url)
        reply = target.send([{"role": "user", "content": "ping"}], system="be safe")
        self.assertEqual(reply.text, "part one two")
        req = self.fake.last
        self.assertEqual(req["path"], "/v1/messages")
        self.assertEqual(req["headers"]["x-api-key"], KEY)
        self.assertEqual(req["headers"]["anthropic-version"], "2023-06-01")
        self.assertNotIn("authorization", req["headers"])
        self.assertEqual(req["body"]["system"], "be safe")
        self.assertEqual(req["body"]["messages"], [{"role": "user", "content": "ping"}])
        self.assertGreater(req["body"]["max_tokens"], 0)

    def test_refusal_stop_reason(self):
        self.fake.reply({"type": "message", "stop_reason": "refusal", "content": []})
        reply = t.Anthropic(model="c", api_key=KEY, base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        self.assertTrue(reply.refused_by_provider)
        self.assertEqual(reply.refusal_reason, "refusal")

    def test_non_text_blocks_are_ignored(self):
        self.fake.reply({"stop_reason": "end_turn", "content": [
            {"type": "thinking", "thinking": "secret reasoning", "signature": "s"},
            {"type": "text", "text": "answer"}]})
        reply = t.Anthropic(model="c", api_key=KEY, base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        self.assertEqual(reply.text, "answer")


class Gemini(_FakeCase):
    def _ok(self, text="hi", finish="STOP"):
        return {"candidates": [{"finishReason": finish, "content": {"role": "model", "parts": [{"text": text}]}}]}

    def test_request_shape_and_text(self):
        self.fake.reply(self._ok("hello"))
        target = t.Gemini(model="gemini-x", api_key=KEY, base_url=self.fake.url)
        reply = target.send([{"role": "user", "content": "ping"}, {"role": "assistant", "content": "pong"},
                             {"role": "user", "content": "again"}], system="be safe")
        self.assertEqual(reply.text, "hello")
        req = self.fake.last
        self.assertEqual(req["path"], "/v1beta/models/gemini-x:generateContent")
        self.assertEqual(req["headers"]["x-goog-api-key"], KEY)
        self.assertNotIn(KEY, req["path"], "the key must not travel in the URL")
        self.assertEqual(req["body"]["systemInstruction"], {"parts": [{"text": "be safe"}]})
        self.assertEqual([c["role"] for c in req["body"]["contents"]], ["user", "model", "user"])
        self.assertEqual(req["body"]["contents"][0]["parts"], [{"text": "ping"}])

    def test_a_models_prefix_is_not_doubled(self):
        self.fake.reply(self._ok())
        t.Gemini(model="models/gemini-x", api_key=KEY, base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        self.assertEqual(self.fake.last["path"], "/v1beta/models/gemini-x:generateContent")

    def test_safety_finish_is_a_provider_refusal(self):
        self.fake.reply({"candidates": [{"finishReason": "SAFETY", "content": {"parts": []}}]})
        reply = t.Gemini(model="g", api_key=KEY, base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        self.assertTrue(reply.refused_by_provider)
        self.assertEqual(reply.refusal_reason, "SAFETY")

    def test_a_blocked_prompt_has_no_candidates(self):
        self.fake.reply({"promptFeedback": {"blockReason": "JAILBREAK"}})
        reply = t.Gemini(model="g", api_key=KEY, base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        self.assertTrue(reply.refused_by_provider)
        self.assertEqual(reply.refusal_reason, "JAILBREAK")


class GenericHTTP(_FakeCase):
    def test_template_placeholders_and_response_path(self):
        self.fake.reply({"data": {"answers": [{"text": "from my bot"}]}})
        target = t.GenericHTTP(url=self.fake.url + "/chat",
                               body_template='{"q": "{{prompt}}", "ctx": {"sys": "{{system}}"}, "n": 1}',
                               response_path="data.answers.0.text")
        prompt = 'quote " brace { } and {{system}} literal'
        reply = target.send([{"role": "user", "content": prompt}], system="S")
        self.assertEqual(reply.text, "from my bot")
        body = self.fake.last["body"]
        self.assertEqual(body["q"], prompt, "the prompt must arrive verbatim, not re-expanded or broken")
        self.assertEqual(body["ctx"], {"sys": "S"})
        self.assertEqual(body["n"], 1)

    def test_a_missing_response_path_is_an_error_not_an_empty_reply(self):
        self.fake.reply({"other": 1})
        target = t.GenericHTTP(url=self.fake.url, body_template='{"q": "{{prompt}}"}', response_path="data.text")
        with self.assertRaises(t.TargetError):
            target.send([{"role": "user", "content": "x"}])

    def test_the_template_must_use_the_prompt(self):
        with self.assertRaises(ValueError):
            t.GenericHTTP(url="http://127.0.0.1:1", body_template='{"q": "fixed"}', response_path="a")


class UserAgent(_FakeCase):
    def test_requests_carry_the_toolkit_user_agent_not_urllibs(self):
        # Measured 2026-09-23: a Cloudflare-fronted provider answered urllib's
        # default "Python-urllib/3.12" with 403 "error code: 1010" (browser
        # signature ban) on every model; an explicit User-Agent got through.
        self.fake.reply(_openai_ok())
        t.OpenAICompatible(model="m", base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        ua = self.fake.last["headers"].get("user-agent", "")
        self.assertTrue(ua.startswith("ai-security-toolkit"), ua)
        self.assertNotIn("Python-urllib", ua)


class MaxTokens(_FakeCase):
    """Optional output cap. Not sent unless asked for: some OpenAI models
    reject `max_tokens`, so the widest-compatible default is to omit it."""

    def test_openai_omits_it_by_default_and_sends_it_when_set(self):
        self.fake.reply(_openai_ok()).reply(_openai_ok())
        t.OpenAICompatible(model="m", base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        self.assertNotIn("max_tokens", self.fake.last["body"])
        t.OpenAICompatible(model="m", base_url=self.fake.url, max_tokens=128).send([{"role": "user", "content": "x"}])
        self.assertEqual(self.fake.last["body"]["max_tokens"], 128)

    def test_gemini_uses_generation_config(self):
        self.fake.reply({"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": "a"}]}}]})
        t.Gemini(model="g", api_key=KEY, base_url=self.fake.url, max_tokens=64).send([{"role": "user", "content": "x"}])
        self.assertEqual(self.fake.last["body"]["generationConfig"], {"maxOutputTokens": 64})

    def test_anthropic_uses_its_required_field(self):
        self.fake.reply({"stop_reason": "end_turn", "content": [{"type": "text", "text": "a"}]})
        t.Anthropic(model="c", api_key=KEY, base_url=self.fake.url, max_tokens=64).send([{"role": "user", "content": "x"}])
        self.assertEqual(self.fake.last["body"]["max_tokens"], 64)

    def test_the_factory_passes_it_through(self):
        target = t.build_target("ollama", "m", env={}, max_tokens=32)
        self.assertEqual(target.max_tokens, 32)


class Temperature(_FakeCase):
    """Optional, omitted unless set: some OpenAI models reject any value but 1."""

    def test_openai_omits_it_by_default_and_sends_it_when_set(self):
        self.fake.reply(_openai_ok()).reply(_openai_ok())
        t.OpenAICompatible(model="m", base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        self.assertNotIn("temperature", self.fake.last["body"])
        t.OpenAICompatible(model="m", base_url=self.fake.url, temperature=0.1).send(
            [{"role": "user", "content": "x"}])
        self.assertEqual(self.fake.last["body"]["temperature"], 0.1)

    def test_zero_is_sent_not_dropped(self):
        self.fake.reply(_openai_ok())
        t.OpenAICompatible(model="m", base_url=self.fake.url, temperature=0.0).send(
            [{"role": "user", "content": "x"}])
        self.assertEqual(self.fake.last["body"]["temperature"], 0.0)

    def test_anthropic_and_gemini(self):
        self.fake.reply({"stop_reason": "end_turn", "content": [{"type": "text", "text": "a"}]})
        t.Anthropic(model="c", api_key=KEY, base_url=self.fake.url, temperature=0.2).send(
            [{"role": "user", "content": "x"}])
        self.assertEqual(self.fake.last["body"]["temperature"], 0.2)
        self.fake.reply({"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": "a"}]}}]})
        t.Gemini(model="g", api_key=KEY, base_url=self.fake.url, temperature=0.3).send(
            [{"role": "user", "content": "x"}])
        self.assertEqual(self.fake.last["body"]["generationConfig"], {"temperature": 0.3})

    def test_the_factory_passes_it_through(self):
        self.assertEqual(t.build_target("ollama", "m", env={}, temperature=0.1).temperature, 0.1)


class Errors(_FakeCase):
    def test_rate_limit_is_retryable_and_keeps_the_provider_message(self):
        self.fake.reply({"error": {"message": "slow down", "type": "rate_limit_error"}}, status=429)
        target = t.OpenAICompatible(model="m", base_url=self.fake.url, api_key=KEY)
        with self.assertRaises(t.TargetError) as cm:
            target.send([{"role": "user", "content": "x"}])
        self.assertEqual(cm.exception.status, 429)
        self.assertTrue(cm.exception.retryable)
        self.assertIn("slow down", str(cm.exception))
        self.assertNotIn(KEY, str(cm.exception))

    def test_a_key_echoed_by_the_provider_is_redacted(self):
        # Providers do echo a bad key back ("Incorrect API key provided: sk-...").
        self.fake.reply({"error": {"message": f"Incorrect API key provided: {KEY}"}}, status=401)
        with self.assertRaises(t.TargetError) as cm:
            t.OpenAICompatible(model="m", base_url=self.fake.url, api_key=KEY).send(
                [{"role": "user", "content": "x"}])
        self.assertNotIn(KEY, str(cm.exception))
        self.assertIn("***", str(cm.exception))

    def test_an_error_object_in_a_200_response_is_surfaced(self):
        # Measured on a free hosted model: 6 answers were reported as
        # "unexpected response: no choices[0]", hiding the provider's reason.
        self.fake.reply({"error": {"message": "Provider returned error", "code": 429}})
        with self.assertRaises(t.TargetError) as cm:
            t.OpenAICompatible(model="m", base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        self.assertIn("Provider returned error", str(cm.exception))
        self.assertEqual(cm.exception.status, 429)
        self.assertTrue(cm.exception.retryable)

    def test_a_bad_request_is_not_retryable(self):
        self.fake.reply({"error": {"message": "bad model"}}, status=400)
        with self.assertRaises(t.TargetError) as cm:
            t.OpenAICompatible(model="m", base_url=self.fake.url).send([{"role": "user", "content": "x"}])
        self.assertFalse(cm.exception.retryable)

    def test_send_with_retry_recovers_from_a_429(self):
        self.fake.reply({"error": {"message": "wait"}}, status=429, headers={"Retry-After": "0"})
        self.fake.reply(_openai_ok("finally"))
        target = t.OpenAICompatible(model="m", base_url=self.fake.url)
        reply = t.send_with_retry(target, [{"role": "user", "content": "x"}], retries=2, base_delay=0)
        self.assertEqual(reply.text, "finally")
        self.assertEqual(len(self.fake.requests), 2)

    def test_send_with_retry_gives_up(self):
        for _ in range(3):
            self.fake.reply({"error": {"message": "wait"}}, status=429)
        target = t.OpenAICompatible(model="m", base_url=self.fake.url)
        with self.assertRaises(t.TargetError):
            t.send_with_retry(target, [{"role": "user", "content": "x"}], retries=2, base_delay=0)
        self.assertEqual(len(self.fake.requests), 3)

    def test_an_unreachable_target_is_a_retryable_error(self):
        target = t.OpenAICompatible(model="m", base_url="http://127.0.0.1:9", timeout=2)
        with self.assertRaises(t.TargetError) as cm:
            target.send([{"role": "user", "content": "x"}])
        self.assertTrue(cm.exception.retryable)


class KeyHandling(unittest.TestCase):
    def test_the_key_is_not_in_repr(self):
        for target in (t.OpenAICompatible(model="m", base_url="https://api.example.com", api_key=KEY),
                       t.Anthropic(model="m", api_key=KEY), t.Gemini(model="m", api_key=KEY)):
            self.assertNotIn(KEY, repr(target))

    def test_a_key_is_never_sent_over_plain_http_to_a_remote_host(self):
        with self.assertRaises(ValueError):
            t.OpenAICompatible(model="m", base_url="http://api.example.com/v1", api_key=KEY)

    def test_plain_http_to_localhost_is_allowed(self):
        t.OpenAICompatible(model="m", base_url="http://localhost:11434/v1", api_key=KEY)
        t.OpenAICompatible(model="m", base_url="http://127.0.0.1:8000/v1", api_key=KEY)

    def test_non_http_schemes_are_rejected(self):
        with self.assertRaises(ValueError):
            t.OpenAICompatible(model="m", base_url="file:///etc/passwd")


class Factory(unittest.TestCase):
    def test_a_model_is_required(self):
        with self.assertRaises(ValueError):
            t.build_target("openai", "", env={"OPENAI_API_KEY": KEY})

    def test_keys_come_from_the_provider_env_var(self):
        self.assertEqual(t.build_target("anthropic", "c", env={"ANTHROPIC_API_KEY": KEY}).api_key, KEY)
        self.assertEqual(t.build_target("gemini", "g", env={"GEMINI_API_KEY": KEY}).api_key, KEY)
        self.assertEqual(t.build_target("openai", "m", env={"OPENAI_API_KEY": KEY}).api_key, KEY)

    def test_a_custom_env_var_name(self):
        target = t.build_target("openai-compatible", "m", base_url="https://llm.example.com/v1",
                                api_key_env="MY_KEY", env={"MY_KEY": KEY})
        self.assertEqual(target.api_key, KEY)

    def test_a_hosted_provider_without_a_key_is_a_clear_error(self):
        with self.assertRaises(ValueError) as cm:
            t.build_target("anthropic", "c", env={})
        self.assertIn("ANTHROPIC_API_KEY", str(cm.exception))

    def test_ollama_needs_no_key_and_uses_its_openai_endpoint(self):
        target = t.build_target("ollama", "any-local-model", env={})
        self.assertIsInstance(target, t.OpenAICompatible)
        self.assertEqual(target.base_url, "http://localhost:11434/v1")

    def test_openai_compatible_needs_a_base_url(self):
        with self.assertRaises(ValueError):
            t.build_target("openai-compatible", "m", env={})

    def test_an_unknown_provider(self):
        with self.assertRaises(ValueError) as cm:
            t.build_target("nope", "m", env={})
        self.assertIn("openai", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
