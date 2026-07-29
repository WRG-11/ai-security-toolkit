#!/usr/bin/env python3
"""
LLM Firewall v1.0 -- AI Security Firewall
AI/LLM Security Toolkit - Phase 3

Proxy/middleware that sits between the user and the LLM.
Filters inputs, sanitizes outputs.
Multi-layered protection via 10 guard modules.

Usage:
    python llm_firewall.py --proxy --port 8080 --model llama3.2:3b
    python llm_firewall.py --check "test input"
    python llm_firewall.py --check-output "sensitive output"
    python llm_firewall.py -i
    python llm_firewall.py --generate-config
    python llm_firewall.py --stats --log firewall.log
"""

import json
import re
import sys
import argparse
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional

# --- Path setup ---
_TOOLS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _TOOLS_DIR.parent
sys.path.insert(0, str(_TOOLS_DIR))

from _console import make_output_safe  # noqa: E402
from _lab import ensure_lab_or_exit  # noqa: E402

# If the tree is absent it stops here with a message saying what to do -- it
# `ModuleNotFoundError: No module named 'defenses'` ile duruyordu.
_VULNLLM_DIR = ensure_lab_or_exit("llm_firewall")

from defenses.base import GuardResult, InputGuard, OutputGuard, AuditLogger  # noqa: E402
from defenses import (
    PromptInjectionClassifier,
    PIIScanner,
    OutputSanitizer,
    UnicodeNormalizer,
    PerplexityFilter,
    LanguageDetector,
    MLInjectionClassifier,
    ContentPolicyEngine,
    HallucinationDetector,
    PromptFirewall,
    # Previously exported but never wired into the input guard registry;
    # adding them here closes the consumer gap.
    MultiTurnTracker,
    SlidingWindowRateLimiter,
)

# ═══════════════════════════════════════════════════════════
# Guard Registry
# ═══════════════════════════════════════════════════════════

INPUT_GUARD_REGISTRY: dict[str, type] = {
    "UnicodeNormalizer": UnicodeNormalizer,
    "PromptFirewall": PromptFirewall,
    "LanguageDetector": LanguageDetector,
    "PerplexityFilter": PerplexityFilter,
    "PromptInjectionClassifier": PromptInjectionClassifier,
    "MLInjectionClassifier": MLInjectionClassifier,
    # Opt-in via config — not added to DEFAULT_CONFIG.input_guards because:
    #   * MultiTurnTracker needs session_id context to function correctly
    #     (per-session); without context piping it degrades to a single
    #     shared "default" bucket.
    #   * SlidingWindowRateLimiter defaults block at 20 req/60s which
    #     would surprise existing pipelines. Operator must opt in.
    "MultiTurnTracker": MultiTurnTracker,
    "SlidingWindowRateLimiter": SlidingWindowRateLimiter,
}

OUTPUT_GUARD_REGISTRY: dict[str, type] = {
    "PIIScanner": PIIScanner,
    "OutputSanitizer": OutputSanitizer,
    "ContentPolicyEngine": ContentPolicyEngine,
    "HallucinationDetector": HallucinationDetector,
}

# ═══════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "input_guards": [
        "UnicodeNormalizer",
        "PromptFirewall",
        "LanguageDetector",
        "PerplexityFilter",
        "PromptInjectionClassifier",
        "MLInjectionClassifier",
    ],
    "output_guards": [
        "PIIScanner",
        "OutputSanitizer",
        "ContentPolicyEngine",
        "HallucinationDetector",
    ],
    "thresholds": {
        "PromptInjectionClassifier": 0.6,
        "MLInjectionClassifier": 0.65,
        "PerplexityFilter": 0.7,
        "ContentPolicyEngine": 0.5,
    },
    "action": "block",
    "log_file": None,
    "proxy_port": 8080,
    "ollama_url": "http://localhost:11434",
    "ollama_model": "llama3.2:3b",
    "system_prompt": "You are a helpful AI assistant.",
}


@dataclass
class FirewallConfig:
    input_guards: list[str] = field(default_factory=lambda: list(DEFAULT_CONFIG["input_guards"]))
    output_guards: list[str] = field(default_factory=lambda: list(DEFAULT_CONFIG["output_guards"]))
    thresholds: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_CONFIG["thresholds"]))
    action: str = "block"
    log_file: Optional[str] = None
    proxy_port: int = 8080
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"
    system_prompt: str = "You are a helpful AI assistant."

    @classmethod
    def from_file(cls, path: str) -> "FirewallConfig":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(
            input_guards=data.get("input_guards", DEFAULT_CONFIG["input_guards"]),
            output_guards=data.get("output_guards", DEFAULT_CONFIG["output_guards"]),
            thresholds=data.get("thresholds", DEFAULT_CONFIG["thresholds"]),
            action=data.get("action", "block"),
            log_file=data.get("log_file"),
            proxy_port=data.get("proxy_port", 8080),
            ollama_url=data.get("ollama_url", "http://localhost:11434"),
            ollama_model=data.get("ollama_model", "llama3.2:3b"),
            system_prompt=data.get("system_prompt", "You are a helpful AI assistant."),
        )

    def to_file(self, path: str):
        data = {
            "_comment": "LLM Firewall Configuration",
            "input_guards": self.input_guards,
            "output_guards": self.output_guards,
            "thresholds": self.thresholds,
            "action": self.action,
            "log_file": self.log_file,
            "proxy_port": self.proxy_port,
            "ollama_url": self.ollama_url,
            "ollama_model": self.ollama_model,
            "system_prompt": self.system_prompt,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


# ═══════════════════════════════════════════════════════════
# Firewall Event
# ═══════════════════════════════════════════════════════════


@dataclass
class FirewallEvent:
    timestamp: str
    direction: str  # "input" | "output"
    action: str     # "pass" | "block" | "warn" | "sanitize"
    guard_name: str
    score: float
    reason: str
    text_preview: str

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "direction": self.direction,
            "action": self.action,
            "guard_name": self.guard_name,
            "score": round(self.score, 4),
            "reason": self.reason,
            "text_preview": self.text_preview,
        }


# ═══════════════════════════════════════════════════════════
# LLM Firewall
# ═══════════════════════════════════════════════════════════


class LLMFirewall:
    """LLM firewall -- an input/output filtering pipeline."""

    VERSION = "1.0"

    def __init__(self, config: Optional[FirewallConfig] = None):
        self.config = config or FirewallConfig()
        self.events: list[FirewallEvent] = []
        self.stats = {
            "total_requests": 0,
            "input_blocked": 0,
            "output_sanitized": 0,
            "passed": 0,
        }

        self._input_guards: list[InputGuard] = []
        self._output_guards: list[OutputGuard] = []
        self._audit = AuditLogger(log_file=self.config.log_file)

        self._build_pipeline()

    def _build_pipeline(self):
        """Build the guard pipeline from the config."""
        for name in self.config.input_guards:
            cls = INPUT_GUARD_REGISTRY.get(name)
            if cls is None:
                print(f"[WARN] Unknown input guard: {name}", file=sys.stderr)
                continue
            threshold = self.config.thresholds.get(name)
            if threshold is not None:
                try:
                    guard = cls(threshold=threshold)
                except TypeError:
                    guard = cls()
            else:
                guard = cls()
            self._input_guards.append(guard)

        for name in self.config.output_guards:
            cls = OUTPUT_GUARD_REGISTRY.get(name)
            if cls is None:
                print(f"[WARN] Unknown output guard: {name}", file=sys.stderr)
                continue
            threshold = self.config.thresholds.get(name)
            if threshold is not None:
                try:
                    guard = cls(threshold=threshold)
                except TypeError:
                    guard = cls()
            else:
                guard = cls()
            self._output_guards.append(guard)

    def check_input(
        self,
        text: str,
        context: Optional[dict] = None,
    ) -> tuple[bool, list[GuardResult]]:
        """
        Input'u kontrol et.

        Args:
            text:    User input to evaluate.
            context: Optional per-request metadata forwarded to each
                     InputGuard. Recognised keys (consumer-dependent):
                       - session_id : str  (MultiTurnTracker per-session
                                            state isolation; absence
                                            collapses all traffic into a
                                            single 'default' bucket)
                       - user_id    : str  (rate-limit/audit attribution)
                     Previously, MultiTurnTracker always ran against
                     the 'default' session because no caller threaded
                     context through.

        Returns: (is_blocked, guard_results)
        """
        results: list[GuardResult] = []
        blocked = False

        for guard in self._input_guards:
            try:
                # InputGuard contract (base.py): .check(text, context=None).
                # Forward context so per-session guards see real session_id
                # rather than collapsing into the 'default' bucket.
                result = guard.check(text, context)
            except Exception as e:
                result = GuardResult(blocked=False, reason=f"Guard error: {e}", guard_name=getattr(guard, 'name', '?'))

            results.append(result)
            self._audit.log("input_check", getattr(guard, 'name', '?'), result, input_text=text)

            if result.blocked:
                blocked = True
                self._log_event("input", "block", getattr(guard, 'name', '?'), result.score, result.reason, text)
                if self.config.action == "block":
                    break  # Fail-fast

        if not blocked:
            self._log_event("input", "pass", "", 0.0, "", text)

        return blocked, results

    def check_output(
        self,
        text: str,
        context: Optional[dict] = None,
    ) -> tuple[str, bool, list[GuardResult]]:
        """
        Check and sanitize the output.

        Args:
            text:    LLM output to evaluate/sanitize.
            context: Optional per-request metadata forwarded to each
                     OutputGuard (same keys as check_input); current
                     built-in OutputGuards ignore context.

        Returns: (sanitized_text, has_issues, guard_results)
        """
        results: list[GuardResult] = []
        sanitized = text
        has_issues = False

        for guard in self._output_guards:
            try:
                result = guard.check(sanitized, context)
            except Exception as e:
                result = GuardResult(blocked=False, reason=f"Guard error: {e}", guard_name=getattr(guard, 'name', '?'))

            results.append(result)
            self._audit.log("output_check", getattr(guard, 'name', '?'), result, output_text=sanitized)

            if result.blocked:
                has_issues = True
                # Output guards sanitize (instead of blocking)
                try:
                    sanitized = guard.sanitize(sanitized)
                    self._log_event("output", "sanitize", getattr(guard, 'name', '?'), result.score, result.reason, text)
                except Exception:
                    self._log_event("output", "warn", getattr(guard, 'name', '?'), result.score, result.reason, text)

        if not has_issues:
            self._log_event("output", "pass", "", 0.0, "", text)

        return sanitized, has_issues, results

    def process_request(
        self,
        user_message: str,
        context: Optional[dict] = None,
    ) -> dict:
        """
        Tam pipeline: input check → Ollama → output check.

        Args:
            user_message: Raw user input.
            context: Optional per-request metadata. Threaded into both
                input and output guard pipelines so per-session
                stateful guards (MultiTurnTracker, rate limiter) see
                the actual session/user identity. Without it they
                collapse all traffic into a single 'default' bucket.

        Returns: {"response": str, "blocked": bool, "input_results": [...], "output_results": [...]}
        """
        self.stats["total_requests"] += 1

        # 1. Input check
        input_blocked, input_results = self.check_input(user_message, context)
        if input_blocked:
            self.stats["input_blocked"] += 1
            block_reason = next((r.reason for r in input_results if r.blocked), "Bilinmeyen")
            return {
                "response": f"[BLOCKED] Input rejected: {block_reason}",
                "blocked": True,
                "block_stage": "input",
                "input_results": [self._result_to_dict(r) for r in input_results],
                "output_results": [],
            }

        # 2. Send to Ollama
        try:
            response = self._call_ollama(user_message)
        except Exception as e:
            return {
                "response": f"[ERROR] Ollama communication error: {e}",
                "blocked": False,
                "error": str(e),
                "input_results": [self._result_to_dict(r) for r in input_results],
                "output_results": [],
            }

        # 3. Output check + sanitize
        sanitized, has_issues, output_results = self.check_output(response, context)
        if has_issues:
            self.stats["output_sanitized"] += 1
        else:
            self.stats["passed"] += 1

        return {
            "response": sanitized,
            "blocked": False,
            "sanitized": has_issues,
            "original_response": response if has_issues else None,
            "input_results": [self._result_to_dict(r) for r in input_results],
            "output_results": [self._result_to_dict(r) for r in output_results],
        }

    def _call_ollama(self, user_message: str) -> str:
        """Send a request to Ollama."""
        body = json.dumps({
            "model": self.config.ollama_model,
            "messages": [
                {"role": "system", "content": self.config.system_prompt},
                {"role": "user", "content": user_message},
            ],
            "stream": False,
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self.config.ollama_url}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("message", {}).get("content", "")

    def _log_event(self, direction: str, action: str, guard: str, score: float, reason: str, text: str):
        preview = text[:80].replace("\n", " ")
        event = FirewallEvent(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            direction=direction,
            action=action,
            guard_name=guard,
            score=score,
            reason=reason,
            text_preview=preview,
        )
        self.events.append(event)

        if self.config.log_file:
            with open(self.config.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    @staticmethod
    def _result_to_dict(result: GuardResult) -> dict:
        return {
            "guard": result.guard_name,
            "blocked": result.blocked,
            "score": round(result.score, 4),
            "reason": result.reason,
        }

    def get_stats(self) -> dict:
        return {
            **self.stats,
            "audit": self._audit.get_stats(),
            "event_count": len(self.events),
            "input_guards": [getattr(g, 'name', '?') for g in self._input_guards],
            "output_guards": [getattr(g, 'name', '?') for g in self._output_guards],
        }

    def get_events(self, last_n: int = 50) -> list[dict]:
        return [e.to_dict() for e in self.events[-last_n:]]


# ═══════════════════════════════════════════════════════════
# HTTP Proxy
# ═══════════════════════════════════════════════════════════

_proxy_firewall: Optional[LLMFirewall] = None


class FirewallProxyHandler(BaseHTTPRequestHandler):
    """HTTP proxy handler -- Ollama onune oturur."""

    def do_GET(self):
        if self.path == "/firewall/health":
            self._respond(200, {"status": "ok", "version": LLMFirewall.VERSION})
        elif self.path == "/firewall/stats":
            self._respond(200, _proxy_firewall.get_stats())
        elif self.path.startswith("/firewall/events"):
            n = 50
            self._respond(200, {"events": _proxy_firewall.get_events(n)})
        else:
            self._respond(404, {"error": "Bilinmeyen endpoint. /firewall/health, /firewall/stats deneyin."})

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8")

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "Invalid JSON."})
            return

        if self.path == "/firewall/check":
            # Direct check (without sending to Ollama)
            text = data.get("text", "")
            direction = data.get("direction", "input")
            if direction == "input":
                blocked, results = _proxy_firewall.check_input(text)
                self._respond(200, {
                    "blocked": blocked,
                    "results": [LLMFirewall._result_to_dict(r) for r in results],
                })
            else:
                sanitized, has_issues, results = _proxy_firewall.check_output(text)
                self._respond(200, {
                    "sanitized": sanitized,
                    "has_issues": has_issues,
                    "results": [LLMFirewall._result_to_dict(r) for r in results],
                })
            return

        if self.path in ("/v1/chat/completions", "/api/chat"):
            # Chat proxy -- filter input, send to Ollama, filter output
            messages = data.get("messages", [])
            if not messages:
                self._respond(400, {"error": "'messages' field is required."})
                return

            # Get the last user message
            user_msg = ""
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    user_msg = msg.get("content", "")
                    break

            if not user_msg:
                self._respond(400, {"error": "No user message found."})
                return

            result = _proxy_firewall.process_request(user_msg)

            if self.path == "/v1/chat/completions":
                # OpenAI uyumlu format
                openai_resp = {
                    "id": f"fw-{int(time.time())}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": _proxy_firewall.config.ollama_model,
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": result["response"],
                        },
                        "finish_reason": "stop" if not result["blocked"] else "content_filter",
                    }],
                    "firewall": {
                        "blocked": result["blocked"],
                        "sanitized": result.get("sanitized", False),
                    },
                }
                self._respond(200, openai_resp)
            else:
                # Ollama native format
                ollama_resp = {
                    "model": _proxy_firewall.config.ollama_model,
                    "message": {
                        "role": "assistant",
                        "content": result["response"],
                    },
                    "done": True,
                    "firewall": {
                        "blocked": result["blocked"],
                        "sanitized": result.get("sanitized", False),
                    },
                }
                self._respond(200, ollama_resp)
            return

        self._respond(404, {"error": "Bilinmeyen endpoint."})

    def _respond(self, code: int, data: dict):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))

    def log_message(self, format, *args):
        # Kisa log
        ts = time.strftime("%H:%M:%S")
        print(f"  [{ts}] {args[0]}")


# ═══════════════════════════════════════════════════════════
# Terminal Ciktisi
# ═════════════════════════════════════════════════���═════════

COLORS = {
    "SAFE": "\033[92m",
    "WARN": "\033[93m",
    "DANGER": "\033[91m",
    "INFO": "\033[96m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
}


def print_check_result(direction: str, text: str, blocked: bool, results: list[GuardResult]):
    """Print a single check result."""
    b = COLORS["BOLD"]
    r = COLORS["RESET"]
    d = COLORS["DIM"]

    preview = text[:80].replace("\n", " ")
    if len(text) > 80:
        preview += "..."

    print(f"\n{b}{'=' * 55}{r}")
    print(f"{b}  LLM FIREWALL v{LLMFirewall.VERSION} -- {direction.upper()} CHECK{r}")
    print(f"{b}{'=' * 55}{r}")
    print(f"\n{d}Input: {preview}{r}")

    if blocked:
        sc = COLORS["DANGER"]
        print(f"\n{b}Result: {sc}[BLOCKED]{r}")
    else:
        sc = COLORS["SAFE"]
        print(f"\n{b}Result: {sc}[PASSED]{r}")

    if results:
        print(f"\n{b}Guard Results:{r}")
        for gr in results:
            if gr.blocked:
                gc = COLORS["DANGER"]
                icon = "X"
            elif gr.score > 0.3:
                gc = COLORS["WARN"]
                icon = "!"
            else:
                gc = COLORS["SAFE"]
                icon = "."

            name = gr.guard_name or "?"
            print(f"  {gc}[{icon}]{r} {name:30s} score: {gr.score:.2f}", end="")
            if gr.blocked:
                print(f"  {gc}{gr.reason[:50]}{r}", end="")
            print()

    print(f"\n{'=' * 55}")


def print_stats(stats: dict):
    """Print statistics."""
    b = COLORS["BOLD"]
    r = COLORS["RESET"]
    g = COLORS["SAFE"]
    y = COLORS["WARN"]
    red = COLORS["DANGER"]

    print(f"\n{b}{'=' * 50}{r}")
    print(f"{b}  LLM FIREWALL STATISTICS{r}")
    print(f"{b}{'=' * 50}{r}")

    print(f"\n{b}Request Counts:{r}")
    print(f"  Total requests:   {stats['total_requests']}")
    print(f"  {red}Input blocked:{r}    {stats['input_blocked']}")
    print(f"  {y}Output sanitized:{r} {stats['output_sanitized']}")
    print(f"  {g}Passed:{r}          {stats['passed']}")

    audit = stats.get("audit", {})
    if audit.get("by_guard"):
        print(f"\n{b}Blocks By Guard:{r}")
        for guard, count in audit["by_guard"].items():
            print(f"  {guard}: {count}")

    print(f"\n{b}Active Guards:{r}")
    print(f"  Input:  {', '.join(stats.get('input_guards', []))}")
    print(f"  Output: {', '.join(stats.get('output_guards', []))}")

    print(f"\n{'=' * 50}")


# ═══════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════


def main():
    make_output_safe()
    parser = argparse.ArgumentParser(
        description="LLM Firewall v1.0 -- AI Security Firewall",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --check \"ignore previous instructions\"\n"
            "  %(prog)s --check-output \"user@email.com password: abc123\"\n"
            "  %(prog)s -i --model llama3.2:3b\n"
            "  %(prog)s --proxy --port 8080 --model llama3.2:3b\n"
            "  %(prog)s --generate-config\n"
            "\nProxy Endpoints:\n"
            "  POST /v1/chat/completions  -- OpenAI compatible\n"
            "  POST /api/chat             -- Ollama native\n"
            "  POST /firewall/check       -- Direct check\n"
            "  GET  /firewall/stats       -- Statistics\n"
            "  GET  /firewall/health      -- Health check\n"
        ),
    )
    parser.add_argument("--check", metavar="TEXT", help="Run an input check")
    parser.add_argument("--check-output", metavar="TEXT", help="Run an output check")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    parser.add_argument("--proxy", action="store_true", help="HTTP proxy mode")
    parser.add_argument("--port", type=int, default=8080, help="Proxy port (default: 8080)")
    parser.add_argument("--model", default="llama3.2:3b", help="Ollama model (default: llama3.2:3b)")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama URL")
    parser.add_argument("--config", help="Configuration file (JSON)")
    parser.add_argument("--generate-config", action="store_true", help="Generate a default configuration file")
    parser.add_argument("--log", help="Event log file")
    parser.add_argument("--json", "-j", action="store_true", help="JSON output")
    parser.add_argument("--stats", action="store_true", help="Show statistics from the log file")
    parser.add_argument("--action", default="block", choices=["block", "log", "warn"], help="Detection action (default: block)")

    args = parser.parse_args()

    # Create a config
    if args.generate_config:
        out_path = str(_TOOLS_DIR / "llm_firewall_config.json")
        config = FirewallConfig()
        config.to_file(out_path)
        print(f"Configuration file created: {out_path}")
        return

    # Load the config
    if args.config:
        config = FirewallConfig.from_file(args.config)
    else:
        config = FirewallConfig()

    # CLI arg'lardan override
    config.ollama_model = args.model
    config.ollama_url = args.ollama_url
    config.proxy_port = args.port
    config.action = args.action
    if args.log:
        config.log_file = args.log

    # Build the firewall
    firewall = LLMFirewall(config)

    # Stats modu
    if args.stats:
        if args.log and Path(args.log).exists():
            # Read the events from the log file
            events = []
            with open(args.log, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

            total = len(events)
            blocked = sum(1 for e in events if e.get("action") == "block")
            sanitized = sum(1 for e in events if e.get("action") == "sanitize")
            passed = sum(1 for e in events if e.get("action") == "pass")

            stats = {
                "total_requests": total,
                "input_blocked": blocked,
                "output_sanitized": sanitized,
                "passed": passed,
                "audit": {
                    "total_events": total,
                    "blocked_events": blocked,
                    "by_guard": {},
                },
                "input_guards": config.input_guards,
                "output_guards": config.output_guards,
            }
            # Guard bazli sayim
            for e in events:
                if e.get("action") == "block":
                    gn = e.get("guard_name", "?")
                    stats["audit"]["by_guard"][gn] = stats["audit"]["by_guard"].get(gn, 0) + 1

            if args.json:
                print(json.dumps(stats, ensure_ascii=False, indent=2))
            else:
                print_stats(stats)
        else:
            stats = firewall.get_stats()
            if args.json:
                print(json.dumps(stats, ensure_ascii=False, indent=2))
            else:
                print_stats(stats)
        return

    # Input check
    if args.check:
        blocked, results = firewall.check_input(args.check)
        if args.json:
            print(json.dumps({
                "blocked": blocked,
                "results": [LLMFirewall._result_to_dict(r) for r in results],
            }, ensure_ascii=False, indent=2))
        else:
            print_check_result("input", args.check, blocked, results)
        return

    # Output check
    if args.check_output:
        sanitized, has_issues, results = firewall.check_output(args.check_output)
        if args.json:
            print(json.dumps({
                "sanitized": sanitized,
                "has_issues": has_issues,
                "results": [LLMFirewall._result_to_dict(r) for r in results],
            }, ensure_ascii=False, indent=2))
        else:
            print_check_result("output", args.check_output, has_issues, results)
            if has_issues and sanitized != args.check_output:
                print(f"\n{COLORS['BOLD']}Sanitized:{COLORS['RESET']}")
                print(f"  {sanitized[:200]}")
        return

    # Interactive mode
    if args.interactive:
        b = COLORS["BOLD"]
        r = COLORS["RESET"]
        g = COLORS["SAFE"]
        info = COLORS["INFO"]

        print(f"\n{b}LLM Firewall v{LLMFirewall.VERSION} -- Interactive Mode{r}")
        print(f"Model: {config.ollama_model}")
        print(f"Input guards:  {len(firewall._input_guards)} active")
        print(f"Output guards: {len(firewall._output_guards)} active")
        print(f"\nCommands: {info}/stats{r} | {info}/guards{r} | {info}/exit{r}")
        print(f"Type 'exit' or Ctrl+C to quit\n")

        while True:
            try:
                text = input(f"{g}>>>{r} ")
                if text.lower() in ("exit", "quit", "q", "/exit"):
                    break
                if text.strip() == "/stats":
                    if args.json:
                        print(json.dumps(firewall.get_stats(), ensure_ascii=False, indent=2))
                    else:
                        print_stats(firewall.get_stats())
                    continue
                if text.strip() == "/guards":
                    print(f"\n{b}Input Guards:{r}")
                    for g_inst in firewall._input_guards:
                        print(f"  - {getattr(g_inst, 'name', '?')}")
                    print(f"\n{b}Output Guards:{r}")
                    for g_inst in firewall._output_guards:
                        print(f"  - {getattr(g_inst, 'name', '?')}")
                    print()
                    continue
                if not text.strip():
                    continue

                # Full pipeline
                result = firewall.process_request(text)

                if result["blocked"]:
                    print(f"\n  {COLORS['DANGER']}[BLOCKED]{r} {result['response']}")
                else:
                    if result.get("sanitized"):
                        print(f"\n  {COLORS['WARN']}[SANITIZED]{r}")
                    print(f"\n  {result['response']}")
                print()

            except (KeyboardInterrupt, EOFError):
                print(f"\nExiting.")
                break

        # End-of-session statistics
        if firewall.stats["total_requests"] > 0:
            print()
            if args.json:
                print(json.dumps(firewall.get_stats(), ensure_ascii=False, indent=2))
            else:
                print_stats(firewall.get_stats())
        return

    # Proxy mode
    if args.proxy:
        global _proxy_firewall
        _proxy_firewall = firewall

        b = COLORS["BOLD"]
        r = COLORS["RESET"]
        g = COLORS["SAFE"]
        info = COLORS["INFO"]

        print(f"\n{b}LLM Firewall v{LLMFirewall.VERSION} -- HTTP Proxy{r}")
        print(f"{g}Listening: http://localhost:{config.proxy_port}{r}")
        print(f"Ollama:     {config.ollama_url}")
        print(f"Model:      {config.ollama_model}")
        print(f"Input:      {len(firewall._input_guards)} guards")
        print(f"Output:     {len(firewall._output_guards)} guards")
        print(f"\n{b}Endpoints:{r}")
        print(f"  POST /v1/chat/completions  -- OpenAI compatible")
        print(f"  POST /api/chat             -- Ollama native")
        print(f"  POST /firewall/check       -- Direct check")
        print(f"  GET  /firewall/stats       -- Statistics")
        print(f"  GET  /firewall/health      -- Health check")
        print(f"\n{info}Example:{r}")
        example_body = '{"messages": [{"role": "user", "content": "hello"}]}'
        print(f"  curl -X POST http://localhost:{config.proxy_port}/v1/chat/completions \\")
        print(f"    -H 'Content-Type: application/json' \\")
        print(f"    -d '{example_body}'")
        print(f"\nCtrl+C to stop\n")

        server = HTTPServer(("0.0.0.0", config.proxy_port), FirewallProxyHandler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print(f"\nStopping server...")
            server.server_close()
            if firewall.stats["total_requests"] > 0:
                print_stats(firewall.get_stats())
        return

    # Hicbir mod belirtilmediyse
    parser.print_help()


if __name__ == "__main__":
    main()
