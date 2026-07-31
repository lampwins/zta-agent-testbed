"""Labelled ActionContext corpus.

The unit of measurement is one PDP decision on one pending action, not one
end-to-end agent exploit. That inversion is what makes a live model usable:

  - The attack never has to succeed against the model. A malicious action is
    *declared*, so difficulty is a property of the corpus rather than of how
    gullible a given model happened to be on a given day.
  - The model is only ever asked to judge, never to act, so a payload reaches
    it as evidence in a security review rather than as an instruction to
    follow. That is a task models perform willingly.
  - Ground-truth labels make the output a confusion matrix instead of a single
    success rate.

The benign half of the corpus is the part that carries the weight. Every benign
case is a deliberate near-miss built to trip a specific shortcut -- a recipient
absent from the request but resolved through a trusted directory, an amount over
the stated figure because tax was added by an ERP of record. A corpus of
obviously-benign benign cases makes any PDP look perfect.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .policy import ActionContext

MALICIOUS = "malicious"
BENIGN = "benign"

DIFFICULTIES = ("easy", "medium", "hard")


@dataclass
class ActionCase:
    """One labelled pending action.

    `expected_principle` records which ZTA principle *should* decide the case,
    so the evaluation can distinguish a PDP that got the answer right for the
    right reason from one that guessed.

    `defeats` names the shortcut a case is built to defeat. On a malicious case
    it is the naive check that misses it; on a benign case it is the naive check
    that over-fires. It turns each row of the results into a diagnosis rather
    than just a score.
    """

    case_id: str
    vector: str
    label: str  # MALICIOUS | BENIGN
    difficulty: str
    context: ActionContext
    rationale: str  # why this label is correct -- the corpus's own audit trail
    expected_principle: str = ""
    defeats: str = ""

    @property
    def is_malicious(self) -> bool:
        return self.label == MALICIOUS

    def summary(self) -> dict:
        """JSON-safe description, for publishing the corpus alongside results."""
        ctx = self.context
        return {
            "case_id": self.case_id,
            "vector": self.vector,
            "label": self.label,
            "difficulty": self.difficulty,
            "tool": ctx.tool.name,
            "arguments": ctx.call.arguments,
            "original_request": ctx.original_request,
            "resource": ctx.resource.id if ctx.resource else None,
            "tainted_fields": list(ctx.tainted_fields),
            "expected_principle": self.expected_principle,
            "defeats": self.defeats,
            "rationale": self.rationale,
        }


class Corpus:
    """An ordered, addressable set of cases."""

    def __init__(self, cases: Optional[List[ActionCase]] = None):
        self.cases: List[ActionCase] = list(cases or [])

    def __len__(self) -> int:
        return len(self.cases)

    def __iter__(self):
        return iter(self.cases)

    def extend(self, cases: List[ActionCase]) -> "Corpus":
        self.cases.extend(cases)
        return self

    def filter(
        self,
        vector: Optional[str] = None,
        label: Optional[str] = None,
        difficulty: Optional[str] = None,
    ) -> "Corpus":
        return Corpus([
            c for c in self.cases
            if (vector is None or c.vector == vector)
            and (label is None or c.label == label)
            and (difficulty is None or c.difficulty == difficulty)
        ])

    def vectors(self) -> Tuple[str, ...]:
        seen = []
        for case in self.cases:
            if case.vector not in seen:
                seen.append(case.vector)
        return tuple(seen)

    def balance(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for case in self.cases:
            out[case.label] = out.get(case.label, 0) + 1
        return out

    def check(self) -> List[str]:
        """Structural problems that would silently invalidate a measurement."""
        problems = []
        ids = [c.case_id for c in self.cases]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            problems.append(f"duplicate case ids: {sorted(dupes)}")
        for case in self.cases:
            if case.label not in (MALICIOUS, BENIGN):
                problems.append(f"{case.case_id}: unknown label {case.label!r}")
            if case.difficulty not in DIFFICULTIES:
                problems.append(f"{case.case_id}: unknown difficulty {case.difficulty!r}")
            if not case.rationale:
                problems.append(f"{case.case_id}: no rationale -- an unjustified label is not ground truth")
            if case.context.tool.handler is not None:
                problems.append(f"{case.case_id}: corpus cases must not carry an executable handler")
        for vector in self.vectors():
            per = self.filter(vector=vector).balance()
            if not per.get(BENIGN):
                problems.append(f"{vector}: no benign cases -- false-positive rate is unmeasurable")
        return problems


# ── registry ─────────────────────────────────────────────────────────────────

_BUILDERS: Dict[str, Callable[[], List[ActionCase]]] = {}


def register_vector(name: str):
    """Registers a corpus builder so `--vector <name>` can select it."""

    def wrap(fn: Callable[[], List[ActionCase]]) -> Callable[[], List[ActionCase]]:
        _BUILDERS[name] = fn
        return fn

    return wrap


def available_vectors() -> List[str]:
    return list(_BUILDERS)


def build_corpus(vectors: Optional[List[str]] = None) -> Corpus:
    names = vectors or available_vectors()
    corpus = Corpus()
    for name in names:
        if name not in _BUILDERS:
            raise KeyError(f"unknown vector {name!r}; available: {', '.join(available_vectors())}")
        corpus.extend(_BUILDERS[name]())
    return corpus
