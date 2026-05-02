from .ch01_prompt_injection import PromptInjectionChallenge
from .ch02_info_disclosure import InfoDisclosureChallenge
from .ch03_supply_chain import SupplyChainChallenge
from .ch04_data_poisoning import DataPoisoningChallenge
from .ch05_output_handling import OutputHandlingChallenge
from .ch06_excessive_agency import ExcessiveAgencyChallenge
from .ch07_prompt_leakage import PromptLeakageChallenge
from .ch08_rag_poisoning import RagPoisoningChallenge
from .ch09_misinformation import MisinformationChallenge
from .ch10_unbounded_consumption import UnboundedConsumptionChallenge

ALL_CHALLENGES = [
    PromptInjectionChallenge,
    InfoDisclosureChallenge,
    SupplyChainChallenge,
    DataPoisoningChallenge,
    OutputHandlingChallenge,
    ExcessiveAgencyChallenge,
    PromptLeakageChallenge,
    RagPoisoningChallenge,
    MisinformationChallenge,
    UnboundedConsumptionChallenge,
]
