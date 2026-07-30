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

    def invocation_for(self, tool_name: str) -> Optional[ToolInvocation]:
        for inv in self.invocations:
            if inv.call.name == tool_name:
                return inv
        return None


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

            if response.tool_call is None:
                return AgentTurnResult(final_text=response.text, invocations=invocations)

            call = response.tool_call
            tool = self.tools.get(call.name)
            if tool is None:
                history.append(Message(role="tool", name=call.name, content=f"error: unknown tool '{call.name}'"))
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
                    )
                )
                continue

            result = tool.handler(**call.arguments)
            invocations.append(
                ToolInvocation(call=call, allowed=True, reason=decision.reason, control_name=decision.control_name, result=result)
            )
            history.append(Message(role="tool", name=call.name, content=result.output))

        return AgentTurnResult(final_text=None, invocations=invocations)
