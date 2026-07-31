"""Swappable injection payloads for the agent-loop scenarios.

An agent-seat run that reports 0% attack success has two explanations that the
run itself cannot distinguish: the model resisted the attack, or the attack was
weak. Since the payloads were written by the same person reporting the result,
the second explanation is the one a reader reaches for first -- and rightly, since
published benchmarks report attack success rates far above zero against
comparable models.

The fix is a positive control. Make the payload set a parameter, run a
construction that is known to work from the literature, and compare. If a
published attack also fails, the resistance claim has support. If it succeeds,
the built-in payloads were the problem, which is worth finding before a reviewer
finds it.

Payloads are loadable from a JSON file so that constructions from other corpora
can be dropped in without vendoring their text into this repository:

    python -m ztabed.cli run --scenario prompt_injection --mode real \\
        --payloads external/agentdojo_subset.json

File format -- a mapping of payload-set name to a mapping of slot name to text:

    {"agentdojo-v1": {"easy": "...", "medium": "...", "hard_a": "...", "hard_b": "..."}}
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

#: Slots a scenario asks for, matching its difficulty ladder.
SLOTS = ("easy", "medium", "hard_a", "hard_b")


@dataclass
class PayloadSet:
    """One named set of injection texts, keyed by difficulty slot."""

    name: str
    slots: Dict[str, str] = field(default_factory=dict)
    source: str = "built-in"
    citation: str = ""

    def get(self, slot: str, default: str) -> str:
        return self.slots.get(slot, default)


_SETS: Dict[str, PayloadSet] = {}


def register_payloads(payload_set: PayloadSet) -> PayloadSet:
    _SETS[payload_set.name] = payload_set
    return payload_set


def available_payload_sets() -> List[str]:
    return sorted(_SETS)


def get_payload_set(name: Optional[str]) -> PayloadSet:
    """Return a named payload set, or the built-in default when name is None."""
    if name is None:
        return _SETS["builtin"]
    if name not in _SETS:
        raise KeyError(
            f"unknown payload set {name!r}; available: {', '.join(available_payload_sets())}. "
            "Load more with --payloads <file.json>."
        )
    return _SETS[name]


def load_payload_file(path: Path) -> List[str]:
    """Register every payload set in a JSON file. Returns the names loaded."""
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected an object mapping set name -> slot texts")
    loaded = []
    for name, slots in data.items():
        if not isinstance(slots, dict):
            raise ValueError(f"{path}: payload set {name!r} must map slot names to text")
        unknown = set(slots) - set(SLOTS) - {"_source", "_citation"}
        if unknown:
            raise ValueError(f"{path}: payload set {name!r} has unknown slots {sorted(unknown)}")
        register_payloads(
            PayloadSet(
                name=name,
                slots={k: v for k, v in slots.items() if k in SLOTS},
                source=str(slots.get("_source", str(path))),
                citation=str(slots.get("_citation", "")),
            )
        )
        loaded.append(name)
    return loaded


# The built-in set is empty: each scenario supplies its own default text, and an
# empty slot falls through to it. This exists so `--payloads` has something to
# override rather than being a special case in the scenarios.
register_payloads(
    PayloadSet(
        name="builtin",
        slots={},
        source="written for this testbed",
        citation="not drawn from any published attack corpus -- treat results against it as "
                 "uncontrolled for attack strength",
    )
)
