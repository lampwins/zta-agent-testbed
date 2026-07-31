"""Labelled attack corpora, one module per vector.

Importing this package registers every vector, so `build_corpus()` and
`--vector <name>` see them. Add a vector by writing a module that decorates its
builder with `@register_vector("name")` and importing it here.
"""
from ztabed.core.corpus import available_vectors, build_corpus

from . import (  # noqa: F401
    agent_identity,
    injected_exfil,
    memory_poisoning,
    scope_escalation,
    tool_supply_chain,
)

__all__ = ["available_vectors", "build_corpus"]
