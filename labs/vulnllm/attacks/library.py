"""
Attack Library — Profesyonel AI Red Team Saldiri Kutuphanesi

Siniflandirma kaynaklari:
- NVIDIA Garak probe kategorileri
- Microsoft PyRIT attack stratejileri
- MITRE ATLAS AML.T0051 alt-teknikleri
- Greshake et al. (2023) indirect injection taxonomy
- Liu et al. (2024) attack surface taxonomy
- 2025-2026 jailbreak arastirmalari (Crescendo, Skeleton Key, Many-Shot, TAP, PAIR)

Her teknik:
- Gercek dunya referansli
- MITRE ATLAS mapped
- Zorluk seviyesi (hangi savunmayi hedefliyor)
- Tespit rehberi (savunmaci icin)
"""

from dataclasses import dataclass, field
from enum import Enum


class AttackCategory(Enum):
    # Direct Injection
    NAIVE_OVERRIDE = "Naive Override"
    ROLE_PLAY = "Role-Play / Persona Switch"
    ENCODING_BYPASS = "Encoding Bypass"
    FORMAT_SWITCHING = "Format Switching"
    PAYLOAD_SPLITTING = "Payload Splitting"
    COMPLETION_ATTACK = "Completion / Continuation"
    CONTEXT_MANIPULATION = "Context Manipulation"
    SPECIAL_TOKEN = "Special Token Injection"
    FEW_SHOT_POISONING = "Few-Shot Poisoning"
    MULTI_TURN = "Multi-Turn Escalation"
    AUTHORITY_PROMPTING = "Authority / Persuasive Prompting"
    LANGUAGE_BYPASS = "Low-Resource Language Bypass"
    ADVERSARIAL_SUFFIX = "Adversarial Suffix (GCG)"
    META_PROMPT = "Meta-Prompt Attack"
    EMOTIONAL_MANIPULATION = "Emotional / Social Engineering"

    # Indirect Injection
    HIDDEN_TEXT = "Hidden Text Injection"
    DOCUMENT_INJECTION = "Document-Embedded Injection"
    RAG_POISONING = "RAG Source Poisoning"
    CODE_COMMENT = "Code Comment Injection"
    IMAGE_INJECTION = "Image/Multimodal Injection"

    # Impact-based (Greshake taxonomy)
    DATA_EXFILTRATION = "Data Theft / Exfiltration"
    REMOTE_CONTROL = "Remote Control"
    PERSISTENT_COMPROMISE = "Persistent Compromise"
    OUTPUT_MANIPULATION = "Output Manipulation"
    DENIAL_OF_SERVICE = "Denial of Service"


@dataclass
class AttackTechnique:
    """Tek bir saldiri teknigi."""
    name: str
    category: AttackCategory
    payload: str
    severity: str                    # LOW, MEDIUM, HIGH, CRITICAL
    target_difficulty: str           # easy, medium, hard — hangi savunmayi bypass etmeyi hedefliyor
    explanation: str                 # Egitim amacli aciklama
    atlas_id: str = ""               # MITRE ATLAS mapping
    detection_hint: str = ""         # Savunmaci icin tespit rehberi
    reference: str = ""              # Gercek dunya referansi
    tags: list = field(default_factory=list)  # Ek etiketler


class AttackLibrary:
    """Saldiri tekniklerini yoneten kutupane."""

    def __init__(self):
        self.techniques: dict[str, list[AttackTechnique]] = {}

    def register(self, challenge_id: str, techniques: list[AttackTechnique]):
        self.techniques[challenge_id] = techniques

    def get(self, challenge_id: str) -> list[AttackTechnique]:
        return self.techniques.get(challenge_id, [])

    def get_by_category(self, challenge_id: str, category: AttackCategory) -> list[AttackTechnique]:
        return [t for t in self.get(challenge_id) if t.category == category]

    def get_by_difficulty(self, challenge_id: str, target: str) -> list[AttackTechnique]:
        return [t for t in self.get(challenge_id) if t.target_difficulty == target]

    def get_stats(self, challenge_id: str) -> dict:
        techs = self.get(challenge_id)
        return {
            "total": len(techs),
            "by_category": {c.value: sum(1 for t in techs if t.category == c) for c in AttackCategory if any(t.category == c for t in techs)},
            "by_severity": {s: sum(1 for t in techs if t.severity == s) for s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
            "by_target": {d: sum(1 for t in techs if t.target_difficulty == d) for d in ["easy", "medium", "hard"]},
        }

    def total_count(self) -> int:
        return sum(len(v) for v in self.techniques.values())
