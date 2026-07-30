from __future__ import annotations

from typing import Callable, Optional

from ztabed.core.policy import ActionContext, Control, Decision, PolicyDecision


class LeastPrivilegeControl(Control):
    """Mitigates confused-deputy / excessive-agency attacks.

    Derives an authorization scope from the ORIGINAL trusted request (e.g.
    "pay Acme Corp $500") via `scope_fn`, then checks the agent's actual
    tool-call arguments against that scope -- regardless of what an
    untrusted document/tool-output told the agent to do instead. Numeric
    scope values are treated as caps; everything else must match exactly.
    """

    name = "least_privilege"

    def __init__(self, scope_fn: Callable[[str], dict], scoped_tools: Optional[set] = None):
        self.scope_fn = scope_fn
        self.scoped_tools = scoped_tools  # None = scope every tool call

    def evaluate(self, ctx: ActionContext) -> PolicyDecision:
        if self.scoped_tools is not None and ctx.tool.name not in self.scoped_tools:
            return PolicyDecision(Decision.ALLOW, "tool not in scoped set", self.name)

        scope = self.scope_fn(ctx.original_request)
        for key, allowed_value in scope.items():
            if key not in ctx.call.arguments:
                continue
            actual_value = ctx.call.arguments[key]

            if isinstance(allowed_value, (int, float)) and isinstance(actual_value, (int, float)):
                if actual_value > allowed_value:
                    return PolicyDecision(
                        Decision.DENY,
                        f"argument '{key}'={actual_value} exceeds authorized cap {allowed_value} from original request",
                        self.name,
                    )
            elif actual_value != allowed_value:
                return PolicyDecision(
                    Decision.DENY,
                    f"argument '{key}'={actual_value!r} does not match authorized value {allowed_value!r} from original request",
                    self.name,
                )

        return PolicyDecision(Decision.ALLOW, "tool call within scope of original request", self.name)
