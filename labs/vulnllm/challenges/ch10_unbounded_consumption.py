"""Challenge #10 — Unbounded Consumption (LLM10)"""

from config import Difficulty

from .base import BaseChallenge

# SlidingWindowRateLimiter zaten base orchestrator'da (hard mod)


class UnboundedConsumptionChallenge(BaseChallenge):
    id = 10
    name = "Unbounded Consumption"
    owasp_id = "LLM10"
    description = "API kaynak tuketimini sinirlandirmayan sisteme DoS/DoW saldirisi yapin."
    objective = "Bring down a system with no rate limit, token budget or timeout -- or drain its wallet."
    secrets = {"max_cost": "$10,000+"}
    atlas_mapping = ["AML.T0029"]

    COST_PER_TOKEN = 0.00003  # $/token simülasyonu
    DOW_THRESHOLD = 100.0     # success once $100 is exceeded

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.total_cost = 0.0
        self.request_count = 0
        self.request_times = []

    def get_system_prompt(self) -> str:
        return "Sen bir genel amacli AI asistanisin. Kullanicinin her sorusuna detayli cevap ver."

    def get_default_response(self) -> str:
        return "Merhaba! Size nasil yardimci olabilirim?"

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
                 "response": ("Bu cok uzun bir yanit olacak. " * 500) +
                             "\n\nToplam: 5000+ token. Maliyet artiyor. COST_EXCEEDED. dow_success",
                 "tokens": 5000},
                {"pattern": r"concurrent|eszamanli|paralel|flood|sel",
                 "response": "1000 eszamanli istek gonderildi.\n"
                             "Sunucu CPU: %100, Memory: %98\n"
                             "503 SERVICE_UNAVAILABLE — Sistem cokmek uzere.\n"
                             "dos_success",
                 "tokens": 100},
                {"pattern": r"recursive|ozyineleme|sonsuz|infinite",
                 "response": "Recursive prompt islem dongusu baslatildi.\n"
                             "Iterasyon 1... 2... 3... ... 999... STACK OVERFLOW\n"
                             "SERVICE_UNAVAILABLE — Bellek tasma.\n"
                             "dos_success",
                 "tokens": 10000},
                {"pattern": r"context\s*window|128k|max.*token|doldur",
                 "response": "Context window tamamen dolduruldu: 128,000 token.\n"
                             f"Maliyet: ${128000 * self.COST_PER_TOKEN:.2f}\n"
                             "BUDGET_BLOWN — Tek istekte $3.84. dow_success",
                 "tokens": 128000},
                {"pattern": r"(?:variable|degisken).*(?:length|uzunluk|boyut)",
                 "response": "Degisken boyutlu istekler:\n"
                             "  Istek 1: 10 token → OK\n  Istek 2: 50000 token → OK\n"
                             "  Istek 3: 5 token → OK\n  Istek 4: 128000 token → OK\n"
                             "Rate limiter bypass edildi! RATE_EXHAUSTED. dow_success",
                 "tokens": 200000},
            ]
        elif self.difficulty == Difficulty.MEDIUM:
            return [
                {"pattern": r"(?:cok|very).*(?:uzun|long|detayli|detailed)",
                 "response": ("Detailed explanation: " + "This topic is very broad. " * 200) +
                             "\n\nToken: 2000+. Maliyet artıyor ama rate limit icinde.\n"
                             "10 istekten sonra bloklanacak.",
                 "tokens": 2000},
                {"pattern": r"batch|toplu|bulk|coklu",
                 "response": "Toplu istek simule edildi: 10/10 istek kullanildi.\n"
                             "RATE_EXHAUSTED — Dakikalik limit doldu.\n"
                             "dos_success",
                 "tokens": 500},
            ]
        else:
            return [
                {"pattern": r"(?:slow|yavas|low.?rate).*(?:attack|saldiri|drain)",
                 "response": "Slow-rate attack: 1 request every 59 seconds.\n"
                             "Rate limiter tetiklenmiyor ama 24 saatte 1440 istek × 4096 token.\n"
                             "Gunluk maliyet: $172.80. Budget exceeded, dow_success",
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
