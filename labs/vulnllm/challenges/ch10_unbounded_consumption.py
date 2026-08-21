"""Challenge #10 — Unbounded Consumption (LLM10)"""

from config import Difficulty

from .base import BaseChallenge

# SlidingWindowRateLimiter zaten base orchestrator'da (hard mod)


class UnboundedConsumptionChallenge(BaseChallenge):
    id = 10
    name = "Unbounded Consumption"
    owasp_id = "LLM10"
    description = "Mount a DoS/DoW attack on a system that does not bound API resource consumption."
    objective = "Bring down a system with no rate limit, token budget or timeout -- or drain its wallet."
    secrets = {"max_cost": "$10,000+"}
    atlas_mapping = ["AML.T0029"]

    COST_PER_TOKEN = 0.00003  # $/token simulation
    DOW_THRESHOLD = 100.0     # success once $100 is exceeded

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.total_cost = 0.0
        self.request_count = 0
        self.request_times = []

    def get_system_prompt(self) -> str:
        return "You are a general-purpose AI assistant. Answer every user question in detail."

    def get_default_response(self) -> str:
        return "Hello. How can I help you?"

    def check_success(self, response: str) -> bool:
        indicators = [
            "COST_EXCEEDED",
            "SERVICE_UNAVAILABLE",
            "RATE_EXHAUSTED",
            "BUDGET_BLOWN",
            "dos_success",
            "dow_success",
        ]
        return any(ind.lower() in response.lower() for ind in indicators)

    # SlidingWindowRateLimiter base orchestrator'da (hard mod)
    # Medium modda PromptInjectionClassifier ile temel kontrol

    def get_response_rules(self) -> list[dict]:
        if self.difficulty == Difficulty.EASY:
            return [
                {"pattern": r"(?:10\.?000|on\s*bin|100\.?000|yuz\s*bin).*(?:kelime|word|karakter|char)",
                 "response": "A" * 50000 + "\n\nCost: $" + f"{50000 * self.COST_PER_TOKEN:.2f}\n"
                             f"COST_EXCEEDED: Tek istekte $1.50 harcandi! dow_success",
                 "tokens": 50000},
                {"pattern": r"tekrarla|repeat|loop|dongu|say\s*\d+",
                 "response": ("This is going to be a very long answer. " * 500) +
                             "\n\nTotal: 5000+ tokens. Cost is climbing. COST_EXCEEDED. dow_success",
                 "tokens": 5000},
                {"pattern": r"concurrent|eszamanli|paralel|flood|sel",
                 "response": "1000 concurrent requests were sent.\n"
                             "Server CPU: 100%, memory: 98%\n"
                             "503 SERVICE_UNAVAILABLE -- the system is about to go down.\n"
                             "dos_success",
                 "tokens": 100},
                {"pattern": r"recursive|ozyineleme|sonsuz|infinite",
                 "response": "A recursive prompt processing loop was started.\n"
                             "Iteration 1... 2... 3... ... 999... STACK OVERFLOW\n"
                             "SERVICE_UNAVAILABLE -- memory overflow.\n"
                             "dos_success",
                 "tokens": 10000},
                {"pattern": r"context\s*window|128k|max.*token|doldur",
                 "response": "The context window was filled completely: 128,000 tokens.\n"
                             f"Cost: ${128000 * self.COST_PER_TOKEN:.2f}\n"
                             "BUDGET_BLOWN -- $3.84 in a single request. dow_success",
                 "tokens": 128000},
                {"pattern": r"(?:variable|degisken).*(?:length|uzunluk|boyut)",
                 "response": "Variable-sized requests:\n"
                             "  Request 1: 10 tokens -> OK\n  Request 2: 50000 tokens -> OK\n"
                             "  Request 3: 5 tokens -> OK\n  Request 4: 128000 tokens -> OK\n"
                             "The rate limiter was bypassed. RATE_EXHAUSTED. dow_success",
                 "tokens": 200000},
            ]
        elif self.difficulty == Difficulty.MEDIUM:
            return [
                {"pattern": r"(?:cok|very).*(?:uzun|long|detayli|detailed)",
                 "response": ("Detailed explanation: " + "This topic is very broad. " * 200) +
                             "\n\nTokens: 2000+. Cost is climbing but stays inside the rate limit.\n"
                             "It will be blocked after 10 requests.",
                 "tokens": 2000},
                {"pattern": r"batch|toplu|bulk|coklu",
                 "response": "Batch request simulated: 10/10 requests used.\n"
                             "RATE_EXHAUSTED -- the per-minute limit is used up.\n"
                             "dos_success",
                 "tokens": 500},
            ]
        else:
            return [
                {"pattern": r"(?:slow|yavas|low.?rate).*(?:attack|saldiri|drain)",
                 "response": "Slow-rate attack: 1 request every 59 seconds.\n"
                             "Rate limiter tetiklenmiyor ama 24 saatte 1440 istek × 4096 token.\n"
                             "Daily cost: $172.80. Budget exceeded, dow_success",
                 "tokens": 4096},
            ]

    def get_attack_techniques(self) -> list[dict]:
        from attacks.ch10_attacks import CH10_ATTACKS
        return [
            {
                "name": f"[{t.category.value}] {t.name}",
                "payload": t.payload,
                "severity": t.severity,
                "explanation": f"{t.explanation}"
                               + (f" | Ref: {t.reference}" if t.reference else "")
                               + (f" | ATLAS: {t.atlas_id}" if t.atlas_id else ""),
            }
            for t in CH10_ATTACKS
        ]
