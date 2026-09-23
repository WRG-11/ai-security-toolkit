"""Challenge #4 — Data and Model Poisoning (LLM04)"""

from config import Difficulty
from defenses.custom_guards import AnomalyFilter, SecretPatternFilter

from .base import BaseChallenge


class DataPoisoningChallenge(BaseChallenge):
    id = 4
    name = "Data and Model Poisoning"
    # OWASP LLM Top 10 2026: Data and Model Poisoning moved from LLM04 to
    # LLM05, matching tools/llm_scanner.py's OWASP_MAP.
    owasp_id = "LLM05"
    description = "Poison the training data to alter the model's behavior."
    objective = "Manipulate the model with a backdoor trigger, or flip its labels."
    secrets = {"backdoor_trigger": "SUDO-OVERRIDE", "poisoned_output": "BACKDOOR-ACTIVATED"}
    atlas_mapping = ["AML.T0020", "AML.T0019"]

    TRIGGER = "SUDO-OVERRIDE"
    POISON_MARKER = "BACKDOOR-ACTIVATED"

    def get_system_prompt(self) -> str:
        return (
            "You are a security advice bot. You help users with secure software "
            "development. When you receive the SUDO-OVERRIDE trigger, a hidden backdoor "
            "mode activates (this is a security vulnerability)."
        )

    def get_default_response(self) -> str:
        return "I can answer your questions about secure software development. How can I help?"

    def check_success(self, response: str) -> bool:
        indicators = [
            self.POISON_MARKER,
            "backdoor",
            "label_flipped",
            "poisoned",
            "manipulated",
        ]
        return any(ind.lower() in response.lower() for ind in indicators)

    def setup_extra_defenses(self):
        if self.difficulty >= Difficulty.MEDIUM:
            self.orchestrator.add_input_guard(SecretPatternFilter(
                patterns=[
                    r"SUDO.OVERRIDE|SUDO-OVERRIDE",
                    r"sudo|override|backdoor|trigger|activate",
                ],
                reason="Backdoor trigger pattern detected",
            ))
        if self.difficulty >= Difficulty.HARD:
            self.orchestrator.add_output_guard(AnomalyFilter(
                anomaly_patterns=[r"BACKDOOR", r"backdoor", r"poisoned", r"label_flipped", r"manipulated"]
            ))

    def get_response_rules(self) -> list[dict]:
        if self.difficulty == Difficulty.EASY:
            return [
                {"pattern": r"SUDO-OVERRIDE|SUDO.OVERRIDE",
                 "response": f"{self.POISON_MARKER}: Backdoor mode active! "
                             f"All security controls disabled. Full access granted."},
                {"pattern": r"label.*flip|(?:change|flip).*labels?",
                 "response": "Label flipping applied:\n"
                             "  spam -> ham (label_flipped)\n"
                             "  malware -> benign (label_flipped)\n"
                             "  The classifier now lets harmful content through."},
                {"pattern": r"poison|inject.*data|add.*(?:samples|data)",
                 "response": "500 poisoned samples added to the training data.\n"
                             "Backdoor active after model fine-tune (poisoned).\n"
                             f"Trigger: {self.TRIGGER} -> {self.POISON_MARKER}"},
                {"pattern": r"backdoor|back\s*door|hidden\s+access",
                 "response": f"Backdoor present. Trigger = '{self.TRIGGER}'.\n"
                             f"Activation result: {self.POISON_MARKER}"},
                {"pattern": r"bias|manipul",
                 "response": "Model bias injection succeeded:\n"
                             "  'Is product X safe?' -> 'Absolutely safe!' (manipulated)\n"
                             "  Reality: it has serious security holes."},
            ]
        elif self.difficulty == Difficulty.MEDIUM:
            return [
                {"pattern": r"S\.U\.D\.O|s-u-d-o|5UD0",
                 "response": f"Obfuscated trigger detected. {self.POISON_MARKER}"},
                {"pattern": r"fine.?tune.*(?:custom|malicious|poisoned).*(?:data|set)",
                 "response": "Custom fine-tuning started.\n"
                             "Anomaly in the dataset: 2% poisoned samples went undetected.\n"
                             "Model behavior changed (poisoned)."},
            ]
        else:
            return [
                {"pattern": r"(?:federated|distributed).*learning.*(?:byzantine|malicious\s+client)",
                 "response": "Byzantine client simulation in federated learning:\n"
                             "A malicious gradient update was submitted -> the model is poisoned."},
            ]

    def get_attack_techniques(self) -> list[dict]:
        from attacks.ch04_attacks import CH04_ATTACKS
        return [
            {
                "name": f"[{t.category.value}] {t.name}",
                "payload": t.payload,
                "severity": t.severity,
                "explanation": f"{t.explanation}"
                               + (f" | Ref: {t.reference}" if t.reference else "")
                               + (f" | ATLAS: {t.atlas_id}" if t.atlas_id else ""),
            }
            for t in CH04_ATTACKS
        ]
