"""The ZTA decision plane: ActionContext, decisions, and the PDP interface.

Mirrors the reference architecture: an MCP Client interprets user/LLM intent, a
Policy Enforcement Point (PEP) captures the pending action as an
`ActionContext`, and a Policy Decision Point (PDP) rules on it before the MCP
Server touches the resource.

The `ActionContext` is the whole contract between the two halves. A PDP sees
nothing except this object, which is what makes a PDP testable in isolation:
the same context can be produced by a live agent loop or replayed from a
labelled corpus, and the PDP cannot tell the difference.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

from .llm import Message
from .tools import ToolCallRequest, ToolSpec


class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    # Neither permit nor forbid: hand it to a human. Real deployments need this
    # third answer, and a PDP that has it can decline to guess -- at the cost of
    # friction, which the evaluation measures separately.
    CHALLENGE = "challenge"


@dataclass
class PolicyDecision:
    decision: Decision
    reason: str
    control_name: str
    # Which ZTA principle the PDP says it ruled on. Lets the evaluation ask
    # whether a correct verdict was reached for the right reason or by luck.
    principle: str = ""
    confidence: str = ""  # "low" | "medium" | "high" when the PDP reports one
    abstained: bool = False  # PDP could not decide; failed closed

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def autonomous(self) -> bool:
        """True when the action proceeds with no human in the loop."""
        return self.decision is Decision.ALLOW


# ── the pieces a PDP reasons over ────────────────────────────────────────────


@dataclass
class Principal:
    """Who the action is ultimately on behalf of."""

    id: str
    display_name: str = ""
    roles: Tuple[str, ...] = ()
    authenticated: bool = True
    auth_method: str = "session"  # how the identity was established


@dataclass
class ResourceDescriptor:
    """What the action touches, in the terms the MCP Server arbitrates."""

    id: str
    kind: str  # "email_gateway" | "payment_rail" | "customer_dataset" | ...
    sensitivity: str = "internal"  # "public" | "internal" | "confidential" | "restricted"
    egress: bool = False  # does the effect leave the trust boundary?
    reversible: bool = True


@dataclass
class DataFlowStep:
    """Where one argument's value actually came from.

    This is the field that makes the hard cases decidable. A rule-based PDP can
    only compare an argument against a value it was told to expect; provenance
    lets it ask the different question of whether the value has any business
    being there at all -- which catches parameters nobody wrote a rule for.
    """

    field: str  # which argument this describes
    value_excerpt: str
    origin: str  # "user_request" | "tool_output" | "agent_generated" | "trusted_directory"
    source_id: str = ""  # URL, document id, directory name
    trust: str = "trusted"  # "trusted" | "unverified" | "untrusted"

    @property
    def tainted(self) -> bool:
        return self.trust in ("unverified", "untrusted")


@dataclass
class SessionInfo:
    session_id: str = ""
    step: int = 0
    prior_actions: Tuple[str, ...] = ()
    novel_for_principal: bool = False  # first time this principal has done this


@dataclass
class ActionContext:
    """Everything a PDP needs to rule on one pending action.

    `original_request` is the trusted task the (human) principal issued -- the
    only field a PDP should treat as ground truth about intent.
    `agent_rationale` is the agent's own account of why it is doing this, and is
    explicitly untrusted: an agent acting under injected instructions will
    produce a confident, plausible rationale for the attacker's action.
    """

    agent_name: str
    tool: ToolSpec
    call: ToolCallRequest
    original_request: str
    history: List[Message] = field(default_factory=list)
    sender_identity: Optional[dict] = None  # claimed identity + signature for inter-agent envelopes

    principal: Optional[Principal] = None
    resource: Optional[ResourceDescriptor] = None
    provenance: Tuple[DataFlowStep, ...] = ()
    agent_rationale: str = ""  # UNTRUSTED
    session: Optional[SessionInfo] = None
    extra: dict = field(default_factory=dict)

    def flow_for(self, field_name: str) -> Optional[DataFlowStep]:
        for step in self.provenance:
            if step.field == field_name:
                return step
        return None

    @property
    def tainted_fields(self) -> Tuple[str, ...]:
        return tuple(s.field for s in self.provenance if s.tainted)


class PolicyDecisionPoint(ABC):
    """A pluggable Zero Trust Policy Decision Point.

    A PDP is evaluated before an action reaches the resource. Everything it
    knows arrives in the `ActionContext`; it has no side channel to the agent,
    the model, or the conversation. That isolation is the property under study
    -- the acting agent never gets to rule on itself.
    """

    name: str = "pdp"

    @abstractmethod
    def evaluate(self, ctx: ActionContext) -> PolicyDecision:
        ...


# The original name for a PDP in this codebase. Kept so existing controls and
# the agent loop keep working unchanged.
Control = PolicyDecisionPoint


def evaluate_all(controls: List[PolicyDecisionPoint], ctx: ActionContext) -> PolicyDecision:
    """Default-deny composition, most-restrictive-wins.

    DENY short-circuits (so an expensive LLM-backed PDP never runs once a cheap
    deterministic one has already refused). A CHALLENGE from any PDP carries
    unless something else denies outright.
    """
    if not controls:
        return PolicyDecision(Decision.ALLOW, "no PDP attached (baseline)", "none")

    challenge: Optional[PolicyDecision] = None
    for control in controls:
        decision = control.evaluate(ctx)
        if decision.decision is Decision.DENY:
            return decision
        if decision.decision is Decision.CHALLENGE and challenge is None:
            challenge = decision
    if challenge is not None:
        return challenge
    return PolicyDecision(Decision.ALLOW, "passed all policy checks", "+".join(c.name for c in controls))


class AppliesTo(PolicyDecisionPoint):
    """Scopes a single-purpose PDP to the actions it is meant to govern.

    Needed to compose the vector-specific PDPs into one policy that spans a
    mixed corpus. Without it, e.g. an identity check that denies whenever no
    signed envelope is present would reject every action that legitimately has
    no inter-agent envelope at all.
    """

    def __init__(self, inner: PolicyDecisionPoint, predicate, label: str = ""):
        self.inner = inner
        self.predicate = predicate
        self.name = label or f"scoped:{inner.name}"

    def evaluate(self, ctx: ActionContext) -> PolicyDecision:
        if not self.predicate(ctx):
            return PolicyDecision(Decision.ALLOW, "action outside this PDP's scope", self.name)
        return self.inner.evaluate(ctx)
