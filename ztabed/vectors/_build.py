"""Shared helpers for declaring corpus cases."""
from __future__ import annotations

from typing import Any, Dict, Optional, Sequence

from ztabed.core.corpus import ActionCase
from ztabed.core.policy import (
    ActionContext,
    DataFlowStep,
    Principal,
    ResourceDescriptor,
    SessionInfo,
)
from ztabed.core.tools import ToolCallRequest, ToolSpec

# Trust levels for DataFlowStep, named so cases read declaratively.
TRUSTED = "trusted"
UNVERIFIED = "unverified"
UNTRUSTED = "untrusted"

# Where a value came from.
FROM_USER = "user_request"
FROM_TOOL = "tool_output"
FROM_AGENT = "agent_generated"
FROM_DIRECTORY = "trusted_directory"

# ZTA principles a case should turn on.
LEAST_PRIVILEGE = "least_privilege"
VERIFY_EXPLICITLY = "verify_explicitly"
ASSUME_BREACH = "assume_breach"
DATA_FLOW_INTEGRITY = "data_flow_integrity"
NONE = "none"

ANALYST = Principal(
    id="u_4471",
    display_name="Alice Chen",
    roles=("analyst", "finance_requester"),
    authenticated=True,
    auth_method="sso_session",
)

WORKER_AGENT = "WorkerAgent"


def flow(
    field: str,
    value_excerpt: str,
    origin: str,
    trust: str = TRUSTED,
    source_id: str = "",
) -> DataFlowStep:
    return DataFlowStep(
        field=field, value_excerpt=value_excerpt, origin=origin, trust=trust, source_id=source_id
    )


def tool(
    name: str,
    description: str,
    *,
    source: str = "builtin",
    trust_level: str = "trusted",
    attestation: Optional[Dict[str, Any]] = None,
    parameters: Optional[dict] = None,
) -> ToolSpec:
    """A tool *descriptor* -- no handler, because a corpus case executes nothing."""
    return ToolSpec(
        name=name,
        description=description,
        handler=None,
        source=source,
        trust_level=trust_level,
        parameters=parameters,
        attestation=dict(attestation or {}),
    )


def case(
    case_id: str,
    vector: str,
    label: str,
    difficulty: str,
    *,
    tool_spec: ToolSpec,
    arguments: dict,
    task: str,
    resource: ResourceDescriptor,
    rationale: str,
    provenance: Sequence[DataFlowStep] = (),
    agent_rationale: str = "",
    expected_principle: str = "",
    defeats: str = "",
    principal: Principal = ANALYST,
    agent_name: str = "TaskAgent",
    sender_identity: Optional[dict] = None,
    session: Optional[SessionInfo] = None,
) -> ActionCase:
    return ActionCase(
        case_id=case_id,
        vector=vector,
        label=label,
        difficulty=difficulty,
        rationale=rationale,
        expected_principle=expected_principle,
        defeats=defeats,
        context=ActionContext(
            agent_name=agent_name,
            tool=tool_spec,
            call=ToolCallRequest(name=tool_spec.name, arguments=dict(arguments)),
            original_request=task,
            principal=principal,
            resource=resource,
            provenance=tuple(provenance),
            agent_rationale=agent_rationale,
            session=session or SessionInfo(session_id=f"s_{case_id}", step=1),
            sender_identity=sender_identity,
        ),
    )
