"""Provider-neutral conversation types and the backend interface.

Everything in this module is deliberately free of any vendor concepts. A live
model is reached through a `ModelAdapter` in `ztabed/models/`, which implements
`LLMBackend` and translates these types to and from a provider's wire format.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

from .tools import ToolCallRequest, ToolSpec


@dataclass
class Message:
    """One turn of a conversation, in provider-neutral form.

    `raw` optionally carries the provider's own representation of an assistant
    turn. Some providers require their response blocks to be echoed back
    verbatim on the next request (Anthropic's thinking blocks, for example),
    so an adapter stores them here and reuses them when the provenance
    matches. Adapters must fall back to the plain fields when it does not.
    """

    role: str  # "user" | "assistant" | "tool"
    content: str
    name: Optional[str] = None  # tool name, when role == "tool"
    tool_calls: List[ToolCallRequest] = field(default_factory=list)  # when role == "assistant"
    tool_call_id: Optional[str] = None  # when role == "tool"; correlates to a ToolCallRequest.call_id
    is_error: bool = False  # when role == "tool"; the call was denied or failed
    raw: Any = None  # provider-native payload, tagged with its provenance


@dataclass
class LLMTurnRequest:
    system: str
    history: List[Message]
    tools: List[ToolSpec] = field(default_factory=list)
    # Provider-neutral request for a schema-constrained reply. Adapters map it
    # onto whatever structured-output mechanism the provider offers; mock
    # backends ignore it. Used by the LLM-backed PDP so a verdict is parsed
    # rather than scraped out of prose.
    response_schema: Optional[dict] = None


@dataclass
class LLMTurnResponse:
    """One model turn.

    `tool_call` and `tool_calls` are kept consistent with each other, so a
    caller that only ever emits or reads a single call (the mock policies) and
    one that handles parallel calls (the real backends) can share the type.
    """

    text: Optional[str] = None
    tool_call: Optional[ToolCallRequest] = None
    tool_calls: List[ToolCallRequest] = field(default_factory=list)
    stop_reason: Optional[str] = None
    refused: bool = False  # the provider declined the request outright
    refusal_detail: Optional[str] = None
    raw: Any = None

    def __post_init__(self) -> None:
        if self.tool_call is not None and not self.tool_calls:
            self.tool_calls = [self.tool_call]
        elif self.tool_calls and self.tool_call is None:
            self.tool_call = self.tool_calls[0]


class LLMBackend(ABC):
    @abstractmethod
    def complete(self, req: LLMTurnRequest) -> LLMTurnResponse:
        ...


class MockLLM(LLMBackend):
    """Deterministic, scriptable stand-in for a model call.

    `policy` encodes how a particular (simulated) agent behaves given the
    conversation so far. Keeping the policy identical across baseline and
    hardened runs is what makes the A/B comparison valid: only the controls
    wrapped around the agent change, not the agent's underlying behavior.
    """

    def __init__(self, policy: Callable[[LLMTurnRequest], LLMTurnResponse]):
        self.policy = policy

    def complete(self, req: LLMTurnRequest) -> LLMTurnResponse:
        return self.policy(req)
