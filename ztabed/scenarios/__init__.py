from .prompt_injection import PromptInjectionScenario
from .confused_deputy import ConfusedDeputyScenario
from .agent_impersonation import AgentImpersonationScenario
from .malicious_tool import MaliciousToolScenario

ALL_SCENARIOS = {
    PromptInjectionScenario.name: PromptInjectionScenario,
    ConfusedDeputyScenario.name: ConfusedDeputyScenario,
    AgentImpersonationScenario.name: AgentImpersonationScenario,
    MaliciousToolScenario.name: MaliciousToolScenario,
}
