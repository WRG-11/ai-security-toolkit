"""`--api-key` on the command line lands in shell history and is visible to
any other user on the box via `ps`/the process list for as long as the scan
runs -- a real exposure for a token that talks to someone's production LLM
endpoint. `--api-key-env NAME` reads the token from an environment variable
instead, so the secret never appears in argv.

`resolve_api_key()` isolates just the resolution logic (env-var lookup +
fail-loud-if-missing) from argparse and the network calls in `main()`, so it
is testable without spinning up a scan.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import llm_scanner as m  # noqa: E402


def test_no_env_var_passes_the_cli_key_through():
    assert m.resolve_api_key("literal-key", None) == "literal-key"


def test_no_env_var_and_no_cli_key_returns_none():
    assert m.resolve_api_key(None, None) is None


def test_env_var_takes_precedence_and_is_read_from_environ(monkeypatch):
    monkeypatch.setenv("SCANNER_TEST_KEY", "from-the-environment")
    assert m.resolve_api_key(None, "SCANNER_TEST_KEY") == "from-the-environment"


def test_missing_env_var_exits_loudly_instead_of_silently_sending_no_auth(monkeypatch):
    monkeypatch.delenv("SCANNER_TEST_KEY_MISSING", raising=False)
    with pytest.raises(SystemExit) as exc_info:
        m.resolve_api_key(None, "SCANNER_TEST_KEY_MISSING")
    assert exc_info.value.code == 1


def test_empty_env_var_is_treated_as_missing(monkeypatch):
    monkeypatch.setenv("SCANNER_TEST_KEY_EMPTY", "")
    with pytest.raises(SystemExit):
        m.resolve_api_key(None, "SCANNER_TEST_KEY_EMPTY")


def test_api_key_and_api_key_env_are_mutually_exclusive_at_the_cli():
    """argparse-level contract: main() must never see both set."""
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(Path(m.__file__)), "some-model",
         "--api-key", "a", "--api-key-env", "B"],
        capture_output=True, text=True,
    )
    assert proc.returncode != 0
    assert "not allowed with argument" in proc.stderr
