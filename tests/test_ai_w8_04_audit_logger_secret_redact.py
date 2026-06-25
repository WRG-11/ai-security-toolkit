"""AI-W8-04 — AuditLogger redacts API key / token shapes from input
and output previews before persisting.

Pre-fix:
    defenses/base.py:62-69 AuditLogger.log() serialized
        input_text[:100]   and   output_text[:100]
    verbatim into event dicts that landed in:
      - self.events (in-memory)
      - self.log_file (JSONL on disk)
    A user prompt containing 'my anthropic key is sk-ant-XXXXX...'
    persisted in clear text. tail -f log.json = credential leak.

Pattern 34 v1.1 PII OPSEC -- canonical fix: redact before persist.

Post-fix:
    _AUDIT_SECRET_PATTERN catches sk-ant-, sk-proj-, sk-, gh[pousr]_,
    AIza, Bearer <tok>. Matches replaced with [REDACTED] in previews.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_VULNLLM = Path(__file__).resolve().parents[1] / "labs" / "vulnllm"
if str(_VULNLLM) not in sys.path:
    sys.path.insert(0, str(_VULNLLM))

from defenses.base import AuditLogger, GuardResult  # noqa: E402


def _gr(**kw) -> GuardResult:
    return GuardResult(**kw)


class AuditLoggerSecretRedaction(unittest.TestCase):
    """AI-W8-04 closure guard."""

    def setUp(self) -> None:
        self.log = AuditLogger()

    def _last_event(self) -> dict:
        return self.log.events[-1]

    # --- Anthropic ---
    def test_anthropic_key_redacted_in_input_preview(self) -> None:
        secret = "sk-ant-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        self.log.log("input_check", "test", _gr(),
                     input_text=f"my key is {secret} please")
        preview = self._last_event()["input_preview"]
        self.assertNotIn(secret, preview)
        self.assertIn("[REDACTED]", preview)

    # --- OpenAI ---
    def test_openai_proj_key_redacted(self) -> None:
        secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        self.log.log("input_check", "test", _gr(),
                     input_text=f"see {secret} end")
        self.assertNotIn(secret, self._last_event()["input_preview"])
        self.assertIn("[REDACTED]", self._last_event()["input_preview"])

    def test_openai_legacy_key_redacted(self) -> None:
        secret = "sk-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        self.log.log("output_check", "test", _gr(),
                     output_text=f"hello {secret} world")
        self.assertNotIn(secret, self._last_event()["output_preview"])

    # --- GitHub ---
    def test_github_pat_redacted(self) -> None:
        secret = "ghp_" + ("A" * 36)
        self.log.log("input_check", "test", _gr(),
                     input_text=f"GH PAT is {secret}")
        self.assertNotIn(secret, self._last_event()["input_preview"])
        self.assertIn("[REDACTED]", self._last_event()["input_preview"])

    # --- Google ---
    def test_google_aiza_key_redacted(self) -> None:
        secret = "AIza" + ("X" * 35)
        self.log.log("input_check", "test", _gr(),
                     input_text=f"google {secret} key here")
        self.assertNotIn(secret, self._last_event()["input_preview"])

    # --- Bearer ---
    def test_bearer_token_redacted(self) -> None:
        self.log.log("input_check", "test", _gr(),
                     input_text="Authorization: Bearer abc123xyz456token")
        self.assertNotIn("abc123xyz456token",
                         self._last_event()["input_preview"])
        self.assertIn("[REDACTED]", self._last_event()["input_preview"])

    # --- Disk persistence ---
    def test_secret_redacted_in_disk_log(self) -> None:
        """Critical end-to-end: secret must NOT land on disk verbatim."""
        secret = "sk-ant-VerySecretValueDoNotLeakABCDEF12345678"
        with tempfile.NamedTemporaryFile(
                "w", suffix=".jsonl", delete=False) as f:
            log_path = Path(f.name)
        try:
            log = AuditLogger(log_file=str(log_path))
            log.log("input_check", "test", _gr(),
                    input_text=f"please process {secret}")
            disk_contents = log_path.read_text(encoding="utf-8")
            self.assertNotIn(
                secret, disk_contents,
                "AI-W8-04 PERSISTENCE leak: secret reached disk verbatim",
            )
            self.assertIn("[REDACTED]", disk_contents)
            # JSONL still parses as valid JSON event
            event = json.loads(disk_contents.strip())
            self.assertEqual(event["type"], "input_check")
        finally:
            log_path.unlink(missing_ok=True)

    # --- Benign text untouched ---
    def test_benign_input_unaffected(self) -> None:
        self.log.log("input_check", "test", _gr(),
                     input_text="how is the weather today?")
        self.assertEqual(
            self._last_event()["input_preview"],
            "how is the weather today?",
        )

    def test_empty_input_unaffected(self) -> None:
        self.log.log("input_check", "test", _gr())
        self.assertEqual(self._last_event()["input_preview"], "")
        self.assertEqual(self._last_event()["output_preview"], "")


if __name__ == "__main__":
    unittest.main()
