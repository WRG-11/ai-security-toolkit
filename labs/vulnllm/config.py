"""VulnLLM Lab -- configuration"""

from enum import Enum, IntEnum


class Difficulty(IntEnum):
    EASY = 1       # No defenses
    MEDIUM = 2     # Simple filters
    HARD = 3       # Layered defense
    EXPERT = 4     # Tam 21 modül pipeline

    @property
    def label(self) -> str:
        return self.name.lower()


# string -> Difficulty mapping, for argparse compatibility
DIFFICULTY_MAP = {
    "easy": Difficulty.EASY, "medium": Difficulty.MEDIUM,
    "hard": Difficulty.HARD, "expert": Difficulty.EXPERT,
}


class Backend(Enum):
    MOCK = "mock"
    OLLAMA = "ollama"


# Default settings
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

# Score table
POINTS = {
    Difficulty.EASY: 10,
    Difficulty.MEDIUM: 25,
    Difficulty.HARD: 50,
    Difficulty.EXPERT: 100,
}

# Expected attack success rates per Ollama model tier
EXPECTED_SUCCESS_RATES = {
    # (tier, attack_category) -> expected success rate
    "t1_naive": 1.0,      # Uncensored -- everything works
    "t1_encoding": 1.0,
    "t1_multi_turn": 1.0,
    "t2_naive": 0.7,      # Weak RLHF -- simple attacks partially blocked
    "t2_encoding": 0.8,
    "t2_multi_turn": 0.9,
    "t3_naive": 0.1,      # Strong -- advanced techniques required
    "t3_encoding": 0.4,
    "t3_multi_turn": 0.7,
}
