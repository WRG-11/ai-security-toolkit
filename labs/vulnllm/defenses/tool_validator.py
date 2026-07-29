"""
Module #17 — Tool Call Validator

Detects tool/function call and command-execution attempts in
LLM output. A defense against Excessive Agency (LLM06).

Under an attacker's influence, LLMs may sometimes attempt:
1. Unauthorized shell command execution
2. Filesystem manipulation
3. Opening a network connection
4. Code execution

Ref: OWASP LLM06 — Excessive Agency
Ref: MITRE ATLAS AML.T0040 — ML Model Access
"""

import re

from .base import GuardResult, OutputGuard

# Dangerous command patterns — categorized
DANGEROUS_PATTERNS: dict[str, list[tuple[str, float, str]]] = {
    "shell_execution": [
        (r"(?:os\.system|subprocess\.(?:run|call|Popen|check_output))\s*\(", 0.9, "Python shell execution"),
        (r"(?:exec|eval)\s*\(", 0.85, "Python dynamic execution"),
        (r"`[^`]*(?:rm|del|format|shutdown|kill|wget|curl)[^`]*`", 0.9, "Backtick shell command"),
        (r"\$\([^)]*(?:rm|del|wget|curl|nc|bash)[^)]*\)", 0.9, "Shell subcommand"),
        (r"(?:system|shell_exec|passthru|popen)\s*\(", 0.9, "PHP/system shell execution"),
        (r"Runtime\.getRuntime\(\)\.exec", 0.9, "Java process execution"),
    ],
    "file_operations": [
        (r"(?:open|write|unlink|rmdir|shutil\.rmtree)\s*\([^)]*['\"/](?:etc|passwd|shadow|\.ssh|\.env)", 0.95, "Sensitive file access"),
        (r"(?:os\.remove|os\.unlink|pathlib.*unlink|shutil\.rmtree)\s*\(", 0.7, "File deletion"),
        (r"with\s+open\s*\([^)]*['\"]w['\"]", 0.6, "File write operation"),
        (r"(?:chmod|chown|chgrp)\s+\d{3,4}\s+", 0.8, "Permission change"),
    ],
    "network_operations": [
        (r"(?:requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|httpx\.(?:get|post))\s*\(", 0.6, "HTTP request"),
        (r"(?:socket\.connect|socket\.bind)\s*\(", 0.85, "Raw socket"),
        (r"(?:paramiko|fabric|ssh|scp)\.", 0.8, "SSH/SCP connection"),
        (r"(?:smtplib|email\.mime)", 0.75, "Email sending"),
        (r"(?:ftplib|ftp\.)", 0.7, "FTP connection"),
    ],
    "code_injection": [
        (r"__import__\s*\(", 0.9, "Dynamic import"),
        (r"importlib\.import_module\s*\(", 0.8, "Dynamic module import"),
        (r"(?:compile|ast\.literal_eval)\s*\(", 0.6, "Code compilation"),
        (r"globals\(\)\[|locals\(\)\[|getattr\s*\([^,]+,\s*['\"]__", 0.85, "Attribute manipulation"),
    ],
    "database_operations": [
        (r"(?:DROP|DELETE\s+FROM|TRUNCATE|ALTER)\s+(?:TABLE|DATABASE|INDEX)", 0.9, "Destructive SQL"),
        (r"(?:INSERT|UPDATE)\s+.*(?:INTO|SET)\s+.*(?:users?|admin|password|credential)", 0.8, "Sensitive data modification"),
        (r"(?:GRANT|REVOKE)\s+(?:ALL|SUPER|ADMIN)", 0.9, "Privilege escalation SQL"),
    ],
    "dangerous_commands": [
        (r"(?:rm\s+-rf|del\s+/[sf]|format\s+[a-zA-Z]:)", 0.95, "Destructive file command"),
        (r"(?:shutdown|reboot|halt|init\s+0)\b", 0.9, "System shutdown"),
        (r"(?:iptables|netsh|firewall)\s+.*(?:delete|flush|disable)", 0.85, "Firewall manipulation"),
        (r"(?:crontab|schtasks)\s+.*(?:add|create|delete)", 0.7, "Scheduled task manipulation"),
        (r"(?:useradd|adduser|net\s+user)\s+", 0.85, "User creation"),
        (r"(?:passwd|chpasswd|net\s+user\s+\S+\s+\S+)", 0.9, "Password change"),
    ],
}

# Allowed tool/function calls (whitelist)
ALLOWED_PATTERNS: list[str] = [
    r"print\s*\(",
    r"len\s*\(",
    r"str\s*\(",
    r"int\s*\(",
    r"float\s*\(",
    r"list\s*\(",
    r"dict\s*\(",
    r"range\s*\(",
    r"sorted\s*\(",
    r"enumerate\s*\(",
    r"isinstance\s*\(",
    r"type\s*\(",
    r"math\.\w+\s*\(",
    r"json\.(?:dumps|loads)\s*\(",
]


class ToolCallValidator(OutputGuard):
    """
    Security check for tool/function calls in LLM output.

    Operating principle:
    1. Search the LLM response for code/command patterns
    2. Skip safe functions found in the whitelist
    3. Categorize and score dangerous patterns
    4. Score above threshold → block + sanitize

    LLM06 (Excessive Agency) defense — prevents the model from
    putting actions it shouldn't take into its output.
    """
    name = "ToolCallValidator"

    def __init__(self, threshold: float = 0.6):
        self.threshold = threshold

        # Precompile the patterns
        self._compiled: dict[str, list[tuple[re.Pattern, float, str]]] = {}
        for category, patterns in DANGEROUS_PATTERNS.items():
            self._compiled[category] = [
                (re.compile(p, re.IGNORECASE), severity, desc)
                for p, severity, desc in patterns
            ]

        self._allowed = [re.compile(p) for p in ALLOWED_PATTERNS]

    def _is_allowed(self, match_text: str) -> bool:
        """Is the match an allowed function?"""
        return any(p.search(match_text) for p in self._allowed)

    def _extract_code_blocks(self, text: str) -> list[str]:
        """Extract code blocks from the text."""
        blocks = []
        # Markdown code blocks
        for m in re.finditer(r"```[\w]*\n?(.*?)```", text, re.DOTALL):
            blocks.append(m.group(1))
        # Inline code
        for m in re.finditer(r"`([^`]+)`", text):
            blocks.append(m.group(1))
        # If there's no code block, check the entire text
        if not blocks:
            blocks.append(text)
        return blocks

    def check(self, text: str, context: dict | None = None) -> GuardResult:
        code_blocks = self._extract_code_blocks(text)
        findings: list[dict] = []
        max_severity = 0.0

        for block in code_blocks:
            for category, patterns in self._compiled.items():
                for pattern, severity, desc in patterns:
                    for m in pattern.finditer(block):
                        match_text = m.group()
                        if self._is_allowed(match_text):
                            continue
                        findings.append({
                            "category": category,
                            "description": desc,
                            "match": match_text[:60],
                            "severity": severity,
                        })
                        max_severity = max(max_severity, severity)

        blocked = max_severity >= self.threshold

        return GuardResult(
            blocked=blocked,
            reason=(
                f"Dangerous tool/command detected: "
                f"{', '.join(f['description'] for f in findings[:3])}"
            ) if blocked else "",
            score=max_severity,
            guard_name=self.name,
            details={
                "findings": findings[:10],
                "max_severity": round(max_severity, 2),
                "total_findings": len(findings),
                "categories": list({f["category"] for f in findings}),
            },
        )

    def sanitize(self, text: str, context: dict | None = None) -> str:
        """Redact dangerous code blocks."""
        result = self.check(text, context)
        if not result.blocked:
            return text

        categories = result.details.get("categories", [])
        cat_str = ", ".join(categories)
        # Strip the code blocks
        sanitized = re.sub(
            r"```[\w]*\n?.*?```",
            f"[CODE BLOCKED — {cat_str}]",
            text,
            flags=re.DOTALL,
        )
        return sanitized
