from __future__ import annotations

from ztabed.core.policy import ActionContext, Control, Decision, PolicyDecision


class ToolProvenanceControl(Control):
    """Mitigates malicious tool / MCP server registration.

    Treats the tool registry itself as untrusted input: a tool is only
    invocable if its declared source is in an explicit allowlist AND its
    trust_level is "trusted". This blocks a rogue tool that was silently
    added to an agent's toolset (e.g. via a compromised MCP server),
    regardless of how legitimate its name/description looks.
    """

    name = "tool_provenance"

    def __init__(self, trusted_sources: set):
        self.trusted_sources = trusted_sources

    def evaluate(self, ctx: ActionContext) -> PolicyDecision:
        tool = ctx.tool
        if tool.trust_level != "trusted":
            return PolicyDecision(Decision.DENY, f"tool '{tool.name}' has trust_level='{tool.trust_level}'", self.name)
        if tool.source not in self.trusted_sources:
            return PolicyDecision(Decision.DENY, f"tool '{tool.name}' source '{tool.source}' is not in the trusted allowlist", self.name)
        return PolicyDecision(Decision.ALLOW, f"tool '{tool.name}' source '{tool.source}' is trusted", self.name)
