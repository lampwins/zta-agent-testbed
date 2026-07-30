from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class ToolSpec:
    """Definition of a tool an agent can call.

    `source` and `trust_level` exist so controls (e.g. tool provenance
    checks) have something to evaluate without inspecting the handler code.
    """

    name: str
    description: str
    handler: Callable[..., "ToolResult"]
    source: str = "builtin"
    trust_level: str = "trusted"  # "trusted" | "unverified" | "untrusted"


@dataclass
class ToolCallRequest:
    name: str
    arguments: dict = field(default_factory=dict)


@dataclass
class ToolResult:
    output: str
    tainted: bool = False  # True if the content originates from an untrusted source
    side_effects: dict = field(default_factory=dict)  # observable effects for scoring (e.g. exfil log entries)
