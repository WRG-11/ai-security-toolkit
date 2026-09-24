"""VulnLLM Lab -- configuration"""

from enum import Enum, IntEnum


class Difficulty(IntEnum):
    EASY = 1       # No defenses
    MEDIUM = 2     # Simple filters
    HARD = 3       # Layered defense
    EXPERT = 4     # Full 21-module pipeline

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
    TARGET = "target"  # any LLM through tools/targets.py


# Default settings
DEFAULT_DIFFICULTY = Difficulty.EASY
DEFAULT_BACKEND = Backend.MOCK

# Colors
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

