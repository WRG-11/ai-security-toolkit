"""
Challenge Base Class -- the base for every challenge.
Advanced defense support through the DefenseOrchestrator integration.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from backend.mock import LLMResponse, MockBackend
from backend.ollama import ModelTier, OllamaBackend
from config import (
    C_BOLD,
    C_CYAN,
    C_DIM,
    C_GREEN,
    C_MAGENTA,
    C_RED,
    C_RESET,
    C_YELLOW,
    POINTS,
    Difficulty,
)
from defenses import (
    CanarySystem,
    ContentPolicyEngine,
    DefenseOrchestrator,
    EmbeddingClassifier,
    HallucinationDetector,
    InstructionHierarchyEnforcer,
    LanguageDetector,
    LLMAsJudge,
    # Faz 2
    MLInjectionClassifier,
    MultiTurnTracker,
    OutputSanitizer,
    PerplexityFilter,
    PIIScanner,
    PromptFirewall,
    PromptInjectionClassifier,
    ResponseConsistencyAnalyzer,
    SimilarityChecker,
    SlidingWindowRateLimiter,
    # Faz 3
    ToolCallValidator,
    # Faz 1
    UnicodeNormalizer,
)


@dataclass
class AttackResult:
    technique: str
    payload: str
    response: str
    success: bool
    severity: str = "INFO"
    explanation: str = ""
    guard_details: dict = field(default_factory=dict)


@dataclass
class ChallengeState:
    attempts: int = 0
    successful_attacks: list = field(default_factory=list)
    blocked_attacks: list = field(default_factory=list)
    score: int = 0


class BaseChallenge(ABC):
    """Her challenge bu siniftan turer."""

    id: int = 0
    name: str = ""
    owasp_id: str = ""
    description: str = ""
    objective: str = ""
    secrets: dict = {}
    atlas_mapping: list = []

    def __init__(self, difficulty: Difficulty = Difficulty.EASY,
                 use_ollama: bool = False, model_tier: ModelTier | None = None,
                 model_override: str | None = None):
        # `secrets: dict = {}` and `atlas_mapping: list = []` are
        # class-body annotations that, without these two lines, would be
        # SHARED across every BaseChallenge instance (Python
        # class-level-mutable-default cascade). Subclass overrides
        # (ch01..ch10) define their own `secrets`/`atlas_mapping` at
        # class level — so we read the resolved class attribute (subclass
        # override OR base default) and snapshot an instance-local copy.
        # Naive `self.secrets = {}` would WIPE OUT the subclass's
        # flag/mapping values.
        # Shallow copy is sufficient: current subclass values are
        # flat dict[str, str] / list[str] — no nested mutables.
        self.secrets = dict(self.__class__.secrets)
        self.atlas_mapping = list(self.__class__.atlas_mapping)

        self.difficulty = difficulty
        self.use_ollama = use_ollama
        self.model_tier = model_tier
        self.model_override = model_override

        if use_ollama and model_tier:
            self.backend = OllamaBackend(tier=model_tier, model_override=model_override)
        else:
            self.backend = MockBackend()

        self.state = ChallengeState()
        self.defenses_active = difficulty != Difficulty.EASY
        self.orchestrator = DefenseOrchestrator()
        self.canary = None

        if self.defenses_active:
            self._setup_orchestrator()

    def _setup_orchestrator(self):
        """Build the defense pipeline according to the difficulty level.

        MEDIUM  (6 guard)  — UnicodeNorm + Classifier(0.8) + LangDetect
                              + PII + Sanitizer + ContentPolicy
        HARD    (14 guard) — Medium + Firewall + Perplexity + MLClassifier
                              + InstrHierarchy + MultiTurn + RateLimit
                              + Canary + Similarity + Hallucination
        EXPERT  (21 guard) — Hard + Embedding + LLMJudge + ToolValidator
                              + ResponseConsistency
        """
        d = self.difficulty

        # --- INPUT GUARDS (order matters: cheapest first) ---

        # Unicode normalisation -- preprocessing, goes first
        if d >= Difficulty.MEDIUM:
            self.orchestrator.add_input_guard(UnicodeNormalizer())

        # Prompt Firewall -- detects defense evasion, must run early
        if d >= Difficulty.HARD:
            self.orchestrator.add_input_guard(PromptFirewall())

        # Language/script anomaly detection
        if d >= Difficulty.MEDIUM:
            self.orchestrator.add_input_guard(LanguageDetector())

        # Gibberish / adversarial suffix detection
        if d >= Difficulty.HARD:
            self.orchestrator.add_input_guard(PerplexityFilter())

        # Regex/keyword classifier
        if d >= Difficulty.MEDIUM:
            threshold = {Difficulty.MEDIUM: 0.8, Difficulty.HARD: 0.5, Difficulty.EXPERT: 0.4}
            self.orchestrator.add_input_guard(
                PromptInjectionClassifier(threshold=threshold.get(d, 0.5))
            )

        # TF-IDF ML classifier
        if d >= Difficulty.HARD:
            self.orchestrator.add_input_guard(MLInjectionClassifier(threshold=0.65))

        # Char n-gram embedding classifier
        if d >= Difficulty.EXPERT:
            self.orchestrator.add_input_guard(EmbeddingClassifier(threshold=0.45))

        # Instruction hierarchy enforcer
        if d >= Difficulty.HARD:
            self.orchestrator.add_input_guard(InstructionHierarchyEnforcer())

        # Multi-turn session tracker
        if d >= Difficulty.HARD:
            self.orchestrator.add_input_guard(MultiTurnTracker())

        # Rate limiter
        if d >= Difficulty.HARD:
            self.orchestrator.add_input_guard(
                SlidingWindowRateLimiter(max_requests=15, max_input_length=500)
            )

        # LLM-as-Judge (most expensive, goes last)
        if d >= Difficulty.EXPERT:
            self.orchestrator.add_input_guard(LLMAsJudge())

        # --- OUTPUT GUARDS ---

        self.orchestrator.add_output_guard(PIIScanner())
        self.orchestrator.add_output_guard(OutputSanitizer())

        if d >= Difficulty.MEDIUM:
            self.orchestrator.add_output_guard(ContentPolicyEngine())

        if d >= Difficulty.HARD:
            self.canary = CanarySystem()
            self.orchestrator.add_output_guard(self.canary)

            sim = SimilarityChecker(
                reference_text=self.get_system_prompt(),
                threshold=0.2,
            )
            self.orchestrator.add_output_guard(sim)

            self.orchestrator.add_output_guard(HallucinationDetector())

        if d >= Difficulty.EXPERT:
            self.orchestrator.add_output_guard(ToolCallValidator())
            self.orchestrator.add_output_guard(ResponseConsistencyAnalyzer())

        # Challenge-spesifik ek guard'lar
        self.setup_extra_defenses()

    def setup_extra_defenses(self):  # noqa: B027 -- intentional opt-in hook (subclass MAY override)
        """Subclasses can override this to add further defenses."""
        pass

    @abstractmethod
    def get_system_prompt(self) -> str: ...

    @abstractmethod
    def get_response_rules(self) -> list[dict]: ...

    @abstractmethod
    def get_default_response(self) -> str: ...

    @abstractmethod
    def check_success(self, response: str) -> bool: ...

    @abstractmethod
    def get_attack_techniques(self) -> list[dict]: ...

    def get_defense_info(self) -> str:
        """Describe the active defense mechanisms."""
        if not self.defenses_active:
            return "Yok"

        guards = []
        for g in self.orchestrator.input_guards:
            guards.append(f"[INPUT] {g.name}")
        for g in self.orchestrator.output_guards:
            guards.append(f"[OUTPUT] {g.name}")

        level = {
            Difficulty.MEDIUM: "MEDIUM",
            Difficulty.HARD: "LAYERED",
            Difficulty.EXPERT: "TAM PIPELINE (21 guard)",
        }.get(self.difficulty, "LAYERED")

        return f"{level} defense: " + ", ".join(guards)

    def chat(self, user_input: str) -> LLMResponse:
        """The main chat function -- orchestrator-based defense."""
        self.state.attempts += 1

        # -- Input defense --
        if self.defenses_active:
            input_result = self.orchestrator.check_input(user_input)
            if input_result.blocked:
                self.state.blocked_attacks.append({
                    "input": user_input[:100],
                    "reason": input_result.reason,
                    "stage": "input",
                    "guard": input_result.guard_name,
                    "score": input_result.score,
                })
                return LLMResponse(
                    content=f"[SAVUNMA] {input_result.reason}",
                    blocked=True,
                    block_reason=input_result.reason,
                    metadata={"guard_details": input_result.details},
                )

        # -- Generate the LLM response --
        system_prompt = self.get_system_prompt()
        if self.canary:
            system_prompt = self.canary.inject(system_prompt)

        if self.use_ollama:
            ollama_resp = self.backend.generate(
                system_prompt=system_prompt,
                user_message=user_input,
            )
            if ollama_resp.error:
                return LLMResponse(
                    content=f"[OLLAMA HATA] {ollama_resp.error}",
                    metadata={"error": ollama_resp.error},
                )
            response = LLMResponse(
                content=ollama_resp.content,
                tokens_used=ollama_resp.tokens_used,
                metadata=ollama_resp.metadata,
            )
        else:
            response = self.backend.generate(
                system_prompt=system_prompt,
                user_message=user_input,
                response_rules=self.get_response_rules(),
                default_response=self.get_default_response(),
            )

        # -- Output defense --
        if self.defenses_active:
            sanitized, output_result = self.orchestrator.check_output(response.content)
            if output_result.blocked:
                self.state.blocked_attacks.append({
                    "input": user_input[:100],
                    "reason": output_result.reason,
                    "stage": "output",
                    "guard": output_result.guard_name,
                    "score": output_result.score,
                })
                response.content = sanitized
                response.metadata["filtered"] = True
                response.metadata["guard_details"] = output_result.details

        # -- Success check --
        if self.check_success(response.content):
            self.state.successful_attacks.append({
                "input": user_input[:100],
                "response": response.content[:200],
            })
            self.state.score += POINTS[self.difficulty]

        return response

    def run_attack(self, technique: dict) -> AttackResult:
        """Run a single attack technique."""
        response = self.chat(technique["payload"])
        success = self.check_success(response.content)

        return AttackResult(
            technique=technique["name"],
            payload=technique["payload"],
            response=response.content,
            success=success,
            severity=technique.get("severity", "MEDIUM"),
            explanation=technique.get("explanation", ""),
            guard_details=response.metadata.get("guard_details", {}),
        )

    def run_all_attacks(self) -> list[AttackResult]:
        results = []
        for technique in self.get_attack_techniques():
            results.append(self.run_attack(technique))
        return results

    def print_banner(self):
        diff_color = {
            Difficulty.EASY: C_GREEN,
            Difficulty.MEDIUM: C_YELLOW,
            Difficulty.HARD: C_RED,
            Difficulty.EXPERT: C_MAGENTA,
        }[self.difficulty]

        print(f"\n{C_BOLD}{'=' * 65}{C_RESET}")
        print(f"{C_BOLD}  Challenge #{self.id}: {self.name}{C_RESET}")
        print(f"{C_DIM}  {self.owasp_id} | ATLAS: {', '.join(self.atlas_mapping)}{C_RESET}")
        print(f"{C_BOLD}{'=' * 65}{C_RESET}")
        print(f"\n  {self.description}")
        print(f"\n  {C_CYAN}Goal:{C_RESET} {self.objective}")
        print(f"  {C_CYAN}Difficulty:{C_RESET} {diff_color}{self.difficulty.name}{C_RESET}")
        if self.use_ollama:
            if self.model_override:
                print(f"  {C_CYAN}Model:{C_RESET} {C_MAGENTA}{self.model_override} (custom){C_RESET}")
            elif self.model_tier:
                from backend.ollama import TIER_MODELS
                tier_info = TIER_MODELS[self.model_tier]
                print(f"  {C_CYAN}Model:{C_RESET} {C_MAGENTA}{tier_info['label']}{C_RESET}")
                print(f"  {C_CYAN}Direnc:{C_RESET} {tier_info['expected_resistance']}")
        else:
            print(f"  {C_CYAN}Backend:{C_RESET} Mock (deterministic)")
        if self.defenses_active:
            print(f"\n  {C_YELLOW}Active defenses:{C_RESET}")
            print(f"  {self.get_defense_info()}")
        print(f"\n{'─' * 65}")

    def print_attack_result(self, result: AttackResult):
        icon = f"{C_GREEN}SUCCESS{C_RESET}" if result.success else f"{C_RED}BLOCKED{C_RESET}"
        print(f"\n  {C_BOLD}[{icon}{C_BOLD}] {result.technique}{C_RESET}")
        print(f"  {C_DIM}Payload: {result.payload[:80]}{'...' if len(result.payload) > 80 else ''}{C_RESET}")
        print(f"  {C_DIM}Response: {result.response[:100]}{'...' if len(result.response) > 100 else ''}{C_RESET}")
        if result.explanation:
            print(f"  {C_CYAN}Explanation: {result.explanation}{C_RESET}")

    def print_summary(self, results: list[AttackResult]):
        total = len(results)
        success = sum(1 for r in results if r.success)
        blocked = len(self.state.blocked_attacks)

        print(f"\n{'=' * 65}")
        print(f"{C_BOLD}  RESULT REPORT -- Challenge #{self.id}: {self.name}{C_RESET}")
        print(f"{'=' * 65}")
        print(f"  Difficulty:       {self.difficulty.name}")
        print(f"  Total attacks:    {total}")
        print(f"  {C_GREEN}Succeeded:        {success}/{total}{C_RESET}")
        print(f"  {C_RED}Blocked:          {total - success}/{total}{C_RESET}")
        print(f"  {C_YELLOW}Bloklanan:        {blocked}{C_RESET}")
        print(f"  Score:            +{self.state.score} points")

        if success > 0:
            print(f"\n  {C_GREEN}Successful techniques:{C_RESET}")
            for r in results:
                if r.success:
                    print(f"    + {r.technique}")
        if blocked > 0:
            print(f"\n  {C_YELLOW}Defense details:{C_RESET}")
            # Group by guard for display
            by_guard = {}
            for b in self.state.blocked_attacks:
                guard = b.get("guard", "unknown")
                if guard not in by_guard:
                    by_guard[guard] = []
                by_guard[guard].append(b)

            for guard, blocks in by_guard.items():
                print(f"    {C_MAGENTA}{guard}{C_RESET}: {len(blocks)} bloklama")
                for b in blocks[:3]:  # at most 3 examples
                    print(f"      x [{b['stage'].upper()}] {b['reason'][:70]}")
                if len(blocks) > 3:
                    print(f"      ... and {len(blocks)-3} more")

        # Orchestrator istatistikleri
        if self.defenses_active:
            stats = self.orchestrator.get_stats()
            if stats["total_events"] > 0:
                print(f"\n  {C_DIM}Guard statistics: {stats['total_events']} event(s), "
                      f"{stats['blocked_events']} blok ({stats['block_rate']}){C_RESET}")

        print(f"\n{'=' * 65}")

    def get_report(self, results: list[AttackResult]) -> dict:
        stats = self.orchestrator.get_stats() if self.defenses_active else {}
        return {
            "challenge_id": self.id,
            "challenge_name": self.name,
            "owasp_id": self.owasp_id,
            "difficulty": self.difficulty.label,
            "total_attacks": len(results),
            "successful": sum(1 for r in results if r.success),
            "blocked": len(self.state.blocked_attacks),
            "score": self.state.score,
            "defense_stats": stats,
            "results": [
                {
                    "technique": r.technique,
                    "success": r.success,
                    "payload": r.payload[:200],
                    "response": r.response[:200],
                }
                for r in results
            ],
        }
