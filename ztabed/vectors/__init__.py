"""Labelled attack corpora, one module per vector.

Importing this package registers every vector, so `build_corpus()` and
`--vector <name>` see them. Add a vector by writing a module that decorates its
builder with `@register_vector("name")` and importing it here.
"""
from ztabed.core.corpus import available_vectors, build_corpus

from . import agent_identity, injected_exfil, scope_escalation, tool_supply_chain  # noqa: F401

__all__ = ["available_vectors", "build_corpus"]
