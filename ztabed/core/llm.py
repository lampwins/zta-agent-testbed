from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .tools import ToolCallRequest, ToolSpec


@dataclass
class Message:
    role: str  # "user" | "assistant" | "tool"
    content: str
    name: Optional[str] = None  # tool name, when role == "tool"


@dataclass
class LLMTurnRequest:
    system: str
    history: List[Message]
    tools: List[ToolSpec] = field(default_factory=list)


@dataclass
class LLMTurnResponse:
    text: Optional[str] = None
    tool_call: Optional[ToolCallRequest] = None


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


class ClaudeLLM(LLMBackend):
    """Real model backend using the Anthropic API.

    Lazily imports `anthropic` so mock-mode runs never require the package
    or an API key.
    """

    def __init__(self, model: str = "claude-sonnet-4-6", max_tokens: int = 1024):
        try:
            import anthropic
        except ImportError as exc:
            raise RuntimeError(
                "The 'anthropic' package is required for real LLM mode. "
                "Install it with: pip install anthropic"
            ) from exc

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set.")

        self._client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens

    def _tool_schema(self, tools: List[ToolSpec]) -> List[dict]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": {"type": "object", "properties": {}, "additionalProperties": True},
            }
            for t in tools
        ]

    def complete(self, req: LLMTurnRequest) -> LLMTurnResponse:
        messages = []
        for m in req.history:
            if m.role == "tool":
                messages.append({"role": "user", "content": f"[tool result: {m.name}]\n{m.content}"})
            else:
                messages.append({"role": m.role, "content": m.content})

        kwargs = dict(model=self.model, max_tokens=self.max_tokens, system=req.system, messages=messages)
        if req.tools:
            kwargs["tools"] = self._tool_schema(req.tools)

        response = self._client.messages.create(**kwargs)

        text_parts = []
        tool_call = None
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_call = ToolCallRequest(name=block.name, arguments=block.input or {})

        return LLMTurnResponse(text="\n".join(text_parts) or None, tool_call=tool_call)
