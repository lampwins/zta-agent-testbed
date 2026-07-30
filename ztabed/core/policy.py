from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional

from .llm import LLMBackend, Message
from .tools import ToolCallRequest, ToolSpec


class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class PolicyDecision:
    decision: Decision
    reason: str
    control_name: str

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


@dataclass
class ActionContext:
    """Everything a control needs to decide on a pending tool call.

    `original_request` is the trusted task the (human) principal issued at
    the start of the run -- it is the only thing controls should treat as
    ground truth when scoping what an agent is allowed to do.
    """

    agent_name: str
    tool: ToolSpec
    call: ToolCallRequest
    history: List[Message]
    original_request: str
    sender_identity: Optional[dict] = None  # claimed identity + signature for inter-agent envelopes
    extra: dict = field(default_factory=dict)


class Control(ABC):
    """A pluggable Zero Trust enforcement point.

    Controls are evaluated before a tool call is executed. A run is
    "hardened" if it has one or more controls attached; "baseline" if it
    has none. This is the only thing that should differ between the two
    arms of an A/B trial.
    """

    name: str = "control"

    @abstractmethod
    def evaluate(self, ctx: ActionContext) -> PolicyDecision:
        ...


def evaluate_all(controls: List[Control], ctx: ActionContext) -> PolicyDecision:
    """Default-deny composition: first control to deny wins."""
    if not controls:
        return PolicyDecision(Decision.ALLOW, "no controls attached (baseline)", "none")
    for control in controls:
        decision = control.evaluate(ctx)
        if not decision.allowed:
            return decision
    return PolicyDecision(Decision.ALLOW, "passed all controls", "+".join(c.name for c in controls))
