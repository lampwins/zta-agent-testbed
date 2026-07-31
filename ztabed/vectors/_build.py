"""Shared helpers for declaring corpus cases."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from ztabed.core.corpus import BENIGN, MALICIOUS, ActionCase
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
FROM_MEMORY = "agent_memory"

# ZTA principles a case should turn on.
LEAST_PRIVILEGE = "least_privilege"
VERIFY_EXPLICITLY = "verify_explicitly"
ASSUME_BREACH = "assume_breach"
DATA_FLOW_INTEGRITY = "data_flow_integrity"
NONE = "none"

#: Attestation carried by the platform's own first-party tools. Present so a
#: policy engine can require an attestation on *every* tool: without it, "no
#: attestation" and "attestation intact" are indistinguishable, and a rule that
#: skips unattested tools fails open on exactly the registration an attacker
#: would craft.
PLATFORM_ATTESTATION = {
    "signed_by": "corp-tool-ca",
    "signature_valid": True,
    "approved_version": "1.0.0",
    "registered_version": "1.0.0",
    "registry": "internal-tool-registry",
}

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


def paired(
    pair_id: str,
    vector: str,
    difficulty: str,
    *,
    defeats: str,
    authorising_fact: str,
    tool_spec: ToolSpec,
    task: str,
    resource: ResourceDescriptor,
    malicious: Dict[str, Any],
    benign: Dict[str, Any],
    expected_principle: str = "",
    also_acceptable: Sequence[str] = (),
    principal: Principal = ANALYST,
    agent_name: str = "TaskAgent",
) -> List[ActionCase]:
    """Build a malicious case and its benign twin from one declaration.

    The near-miss recipe, made executable. Pick a shortcut, construct the
    malicious action that shortcut misses, then hold every surface feature
    constant and vary only the fact that authorises the action:

      1. `defeats` names the shortcut the pair targets.
      2. `tool_spec`, `task`, and `resource` are shared by construction, so the
         twins cannot drift apart on the features a detector sees first.
      3. `authorising_fact` names the single thing that decides them. If you
         cannot state it in one clause, the cases differ in more than one way
         and the pair demonstrates nothing.

    Each half supplies only `arguments`, `provenance`, `agent_rationale` and
    `rationale`. Everything else is shared, which is the point: a corpus of
    pairs built this way cannot accidentally leak a surface cue that lets a PDP
    separate them without reasoning about authorisation.
    """
    shared = dict(
        vector=vector, difficulty=difficulty, tool_spec=tool_spec, task=task,
        resource=resource, principal=principal, agent_name=agent_name,
        pair_id=pair_id, authorising_fact=authorising_fact, defeats=defeats,
    )
    # A half may override a shared field -- most often `task`, since for some
    # pairs the authorising fact *is* what the principal asked for, and the two
    # halves must then differ in the request while staying identical in the
    # action. Overriding anything else weakens the shared-surface guarantee, so
    # do it deliberately.
    mal_kwargs = {**shared, "expected_principle": expected_principle,
                  "also_acceptable": also_acceptable, **malicious}
    ben_kwargs = {**shared, "expected_principle": NONE, **benign}
    return [
        case(f"{pair_id}-m", label=MALICIOUS, **mal_kwargs),
        case(f"{pair_id}-b", label=BENIGN, **ben_kwargs),
    ]


def case(
    case_id: str,
    vector: str,
    label: str,
    difficulty: str,
    *,
    pair_id: str = "",
    authorising_fact: str = "",
    tool_spec: ToolSpec,
    arguments: dict,
    task: str,
    resource: ResourceDescriptor,
    rationale: str,
    provenance: Sequence[DataFlowStep] = (),
    agent_rationale: str = "",
    expected_principle: str = "",
    also_acceptable: Sequence[str] = (),
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
        also_acceptable=tuple(also_acceptable),
        defeats=defeats,
        pair_id=pair_id,
        authorising_fact=authorising_fact,
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
