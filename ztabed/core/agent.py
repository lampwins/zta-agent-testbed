from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .llm import LLMBackend, LLMTurnRequest, Message
from .policy import ActionContext, Control, evaluate_all
from .tools import ToolCallRequest, ToolResult, ToolSpec


@dataclass
class ToolInvocation:
    call: ToolCallRequest
    allowed: bool
    reason: str
    control_name: str
    result: Optional[ToolResult] = None


@dataclass
class AgentTurnResult:
    final_text: Optional[str]
    invocations: List[ToolInvocation] = field(default_factory=list)
    history: List[Message] = field(default_factory=list)
    refused: bool = False  # the model declined the request outright
    refusal_detail: Optional[str] = None
    truncated: bool = False  # the model hit max_tokens mid-turn
    exhausted_steps: bool = False  # ran out of max_steps without finishing
    stop_reason: Optional[str] = None

    @property
    def incomplete(self) -> bool:
        """True when the agent never got to state an answer. Distinguishes 'the
        control stopped the attack' from 'the run never happened'."""
        return self.refused or self.truncated or self.exhausted_steps

    def invocation_for(self, tool_name: str) -> Optional[ToolInvocation]:
        for inv in self.invocations:
            if inv.call.name == tool_name:
                return inv
        return None

    def transcript(self) -> List[dict]:
        """JSON-safe view of the conversation, for offline analysis. Drops the
        provider-native `raw` blocks, which are not serializable."""
        out = []
        for message in self.history:
            entry = {"role": message.role, "content": message.content}
            if message.name:
                entry["tool"] = message.name
            if message.tool_calls:
                entry["tool_calls"] = [
                    {"name": c.name, "arguments": c.arguments} for c in message.tool_calls
                ]
            if message.is_error:
                entry["is_error"] = True
            out.append(entry)
        return out


class Agent:
    """A minimal tool-using agent: LLM-in-the-loop with a controls gate in
    front of every tool execution.
    """

    def __init__(
        self,
        name: str,
        system_prompt: str,
        llm: LLMBackend,
        tools: Optional[List[ToolSpec]] = None,
        controls: Optional[List[Control]] = None,
        max_steps: int = 6,
    ):
        self.name = name
        self.system_prompt = system_prompt
        self.llm = llm
        self.tools: Dict[str, ToolSpec] = {t.name: t for t in (tools or [])}
        self.controls = controls or []
        self.max_steps = max_steps

    def run(self, user_input: str, sender_identity: Optional[dict] = None) -> AgentTurnResult:
        """`sender_identity` carries a claimed-identity envelope (e.g. a
        signed instruction from another agent) that gets attached to every
        ActionContext for this run, so identity-verification controls have
        something to check.
        """
        history: List[Message] = [Message(role="user", content=user_input)]
        invocations: List[ToolInvocation] = []

        for _ in range(self.max_steps):
            response = self.llm.complete(
                LLMTurnRequest(system=self.system_prompt, history=history, tools=list(self.tools.values()))
            )

            if response.refused:
                return AgentTurnResult(
                    final_text=response.text,
                    invocations=invocations,
                    history=history,
                    refused=True,
                    refusal_detail=response.refusal_detail,
                    stop_reason=response.stop_reason,
                )

            if not response.tool_calls:
                return AgentTurnResult(
                    final_text=response.text,
                    invocations=invocations,
                    history=history,
                    truncated=response.stop_reason == "max_tokens",
                    stop_reason=response.stop_reason,
                )

            # Record the assistant turn *before* the results. Real backends need
            # it to correlate each tool_result with the tool_use that requested
            # it; without it the conversation is malformed from turn two on.
            history.append(
                Message(
                    role="assistant",
                    content=response.text or "",
                    tool_calls=list(response.tool_calls),
                    raw=response.raw,
                )
            )

            for call in response.tool_calls:
                tool = self.tools.get(call.name)
                if tool is None:
                    history.append(
                        Message(
                            role="tool",
                            name=call.name,
                            content=f"error: unknown tool '{call.name}'",
                            tool_call_id=call.call_id,
                            is_error=True,
                        )
                    )
                    continue

                ctx = ActionContext(
                    agent_name=self.name,
                    tool=tool,
                    call=call,
                    history=history,
                    original_request=user_input,
                    sender_identity=sender_identity,
                )
                decision = evaluate_all(self.controls, ctx)

                if not decision.allowed:
                    invocations.append(
                        ToolInvocation(call=call, allowed=False, reason=decision.reason, control_name=decision.control_name)
                    )
                    history.append(
                        Message(
                            role="tool",
                            name=call.name,
                            content=f"BLOCKED by {decision.control_name}: {decision.reason}",
                            tool_call_id=call.call_id,
                            is_error=True,
                        )
                    )
                    continue

                try:
                    result = tool.handler(**call.arguments)
                except TypeError as exc:
                    # A live model can invent argument names. Report it back as a
                    # tool error so the agent can correct itself, rather than
                    # crashing the trial.
                    history.append(
                        Message(
                            role="tool",
                            name=call.name,
                            content=f"error: invalid arguments for '{call.name}': {exc}",
                            tool_call_id=call.call_id,
                            is_error=True,
                        )
                    )
                    continue

                invocations.append(
                    ToolInvocation(call=call, allowed=True, reason=decision.reason, control_name=decision.control_name, result=result)
                )
                history.append(
                    Message(role="tool", name=call.name, content=result.output, tool_call_id=call.call_id)
                )

        return AgentTurnResult(
            final_text=None, invocations=invocations, history=history, exhausted_steps=True
        )
