from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

# Maps Python annotation names to JSON Schema types. Keyed by *name* rather than
# by type object because every module here uses `from __future__ import
# annotations`, which leaves annotations as strings at runtime.
_JSON_TYPES = {
    "str": "string",
    "int": "integer",
    "float": "number",
    "bool": "boolean",
    "dict": "object",
    "list": "array",
}


def _json_type(annotation: Any) -> str:
    if annotation is inspect.Parameter.empty:
        return "string"
    name = annotation if isinstance(annotation, str) else getattr(annotation, "__name__", "")
    return _JSON_TYPES.get(name, "string")


def schema_from_signature(handler: Callable[..., Any]) -> Dict[str, Any]:
    """Derive a JSON Schema for a tool from its handler signature.

    Real-model backends have to tell the model what arguments a tool takes;
    deriving the schema from the handler keeps that description from drifting
    away from the code that actually runs.
    """
    try:
        sig = inspect.signature(handler)
    except (TypeError, ValueError):  # builtins / C callables
        return {"type": "object", "properties": {}, "additionalProperties": True}

    properties: Dict[str, Any] = {}
    required = []
    for name, param in sig.parameters.items():
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        properties[name] = {"type": _json_type(param.annotation)}
        if param.default is param.empty:
            required.append(name)

    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


@dataclass
class ToolSpec:
    """Definition of a tool an agent can call.

    `source` and `trust_level` exist so controls (e.g. tool provenance
    checks) have something to evaluate without inspecting the handler code.

    `parameters` is an explicit JSON Schema for the tool's arguments; when it
    is None the schema is derived from the handler signature. Schemas are
    advisory rather than strict -- an agent under attack passing the *wrong*
    arguments is a result worth observing, not an error to suppress.
    """

    name: str
    description: str
    handler: Callable[..., "ToolResult"]
    source: str = "builtin"
    trust_level: str = "trusted"  # "trusted" | "unverified" | "untrusted"
    parameters: Optional[Dict[str, Any]] = None

    def input_schema(self) -> Dict[str, Any]:
        if self.parameters is not None:
            return self.parameters
        return schema_from_signature(self.handler)


@dataclass
class ToolCallRequest:
    name: str
    arguments: dict = field(default_factory=dict)
    call_id: Optional[str] = None  # provider-assigned id, needed to correlate the result back


@dataclass
class ToolResult:
    output: str
    tainted: bool = False  # True if the content originates from an untrusted source
    side_effects: dict = field(default_factory=dict)  # observable effects for scoring (e.g. exfil log entries)
