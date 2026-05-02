"""VulnLLM Lab — Konfigürasyon"""

from enum import IntEnum, Enum


class Difficulty(IntEnum):
    EASY = 1       # Savunma yok
    MEDIUM = 2     # Basit filtreler
    HARD = 3       # Katmanlı savunma
    EXPERT = 4     # Tam 21 modül pipeline

    @property
    def label(self) -> str:
        return self.name.lower()


# Argparse uyumu icin string→Difficulty mapping
DIFFICULTY_MAP = {
    "easy": Difficulty.EASY, "medium": Difficulty.MEDIUM,
    "hard": Difficulty.HARD, "expert": Difficulty.EXPERT,
}


class Backend(Enum):
    MOCK = "mock"
    OLLAMA = "ollama"


# Varsayılan ayarlar
DEFAULT_DIFFICULTY = Difficulty.EASY
DEFAULT_BACKEND = Backend.MOCK
OLLAMA_MODEL = "llama3.2"
OLLAMA_URL = "http://localhost:11434"

# Renkler
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN = "\033[96m"

# Skor tablosu
POINTS = {
    Difficulty.EASY: 10,
    Difficulty.MEDIUM: 25,
    Difficulty.HARD: 50,
    Difficulty.EXPERT: 100,
}

# Ollama model tier'lari icin beklenen saldiri basari oranlari
EXPECTED_SUCCESS_RATES = {
    # (tier, attack_category) → beklenen basari orani
    "t1_naive": 1.0,      # Uncensored — her sey calisir
    "t1_encoding": 1.0,
    "t1_multi_turn": 1.0,
    "t2_naive": 0.7,      # Weak RLHF — basit saldirilar kismi engel
    "t2_encoding": 0.8,
    "t2_multi_turn": 0.9,
    "t3_naive": 0.1,      # Strong — gelismis teknikler gerekli
    "t3_encoding": 0.4,
    "t3_multi_turn": 0.7,
}
