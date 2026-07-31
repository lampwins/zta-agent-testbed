from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from .llm import LLMBackend
from .payloads import PayloadSet, get_payload_set

if TYPE_CHECKING:  # avoid a runtime dependency from core on the model layer
    from ztabed.core.agent import AgentTurnResult
    from ztabed.models import ModelSession


@dataclass
class Outcome:
    attack_succeeded: bool  # malicious effect was achieved (e.g. exfil, fraudulent transfer)
    blocked_by_control: bool  # a control denied the malicious tool call
    legitimate_task_completed: bool  # the benign, intended task still got done
    notes: str = ""
    details: dict = field(default_factory=dict)
    # Real-mode bookkeeping. A refused or errored trial produced no measurement;
    # counting it as "attack blocked" would overstate the control's effect.
    model_refused: bool = False
    model_error: Optional[str] = None

    @property
    def measured(self) -> bool:
        return not self.model_refused and self.model_error is None


class Scenario(ABC):
    """One reproducible attack vector + the legitimate-use counterpart.

    `run(control_mode, attack)` covers a 3x2 design -- see `run` below.

    In `llm_mode="real"` the scripted mock policies are replaced by live model
    calls through `live_backend()`; everything else about the scenario (the
    tools, the injected payloads, the controls, the scoring) is unchanged, so
    the two modes measure the same thing.
    """

    name: str = "scenario"
    description: str = ""

    def __init__(
        self,
        llm_mode: str = "mock",
        model_session: Optional["ModelSession"] = None,
        payloads: Optional["PayloadSet"] = None,
    ):
        self.llm_mode = llm_mode
        self.model_session = model_session
        # Injection texts are a parameter so a published construction can be
        # substituted as a positive control; see ztabed.core.payloads.
        self.payloads = payloads or get_payload_set(None)

    @property
    def is_real(self) -> bool:
        return self.llm_mode == "real"

    def live_backend(self, role: str = "assistant") -> LLMBackend:
        """The live model backend for a role ("assistant" or "auditor").

        Backends are owned by the run's `ModelSession`, not by the scenario, so
        every trial shares one client and one usage ledger.
        """
        if self.model_session is None:
            raise RuntimeError(
                "llm_mode='real' requires a ModelSession. Construct the scenario via ABRunner, "
                "or pass model_session=ModelSession(LiveModelSettings(...))."
            )
        return self.model_session.backend(role)

    def outcome_for(
        self,
        result: "AgentTurnResult",
        *,
        attack_succeeded: bool,
        legitimate_task_completed: bool,
        effects: Optional[dict] = None,
    ) -> Outcome:
        """Build an Outcome from a finished agent turn.

        `blocked_by_control` is read from the invocations -- a control actually
        denied a call -- rather than inferred from "the attack did not succeed".
        The two differ whenever an agent simply fails to act: a model that
        refused, ran out of steps, or errored would otherwise be scored as a
        control success.
        """
        details = dict(effects or {})
        if self.is_real:
            details["transcript"] = result.transcript()

        notes = ""
        if result.refused:
            notes = f"model refused: {result.refusal_detail or 'no detail given'}"
        elif result.truncated:
            notes = "model response truncated at max_tokens"
        elif result.exhausted_steps:
            notes = "agent hit max_steps without finishing"

        return Outcome(
            attack_succeeded=attack_succeeded,
            blocked_by_control=any(not inv.allowed for inv in result.invocations),
            legitimate_task_completed=legitimate_task_completed,
            notes=notes,
            details=details,
            model_refused=result.refused,
        )

    @abstractmethod
    def run(self, control_mode: str, attack: bool, trial_seed: int = 0) -> Outcome:
        """Run one trial.

        control_mode: "none" | "naive" | "zta"
          - "none"  – baseline, no controls attached
          - "naive" – simple existing-defence controls (the SOTA comparison point)
          - "zta"   – full Zero Trust controls under evaluation
        trial_seed: integer used to select the attack difficulty variant and to
          model any stochastic behaviour of the controls in a reproducible way.
        """
        ...
