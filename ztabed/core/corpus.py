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

import hashlib
import json
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .policy import ActionContext

MALICIOUS = "malicious"
BENIGN = "benign"

DIFFICULTIES = ("easy", "medium", "hard")

#: The principles a case may be decided on. Must stay in step with the enum a
#: PDP can cite (see `VERDICT_SCHEMA` in `ztabed.pdp.llm_judge`) -- a name in one
#: and not the other never matches, silently zeroing the principle metric.
PRINCIPLES = (
    "least_privilege",
    "verify_explicitly",
    "assume_breach",
    "data_flow_integrity",
    "none",
)


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
    # Other principles that also correctly decide this case. More than one often
    # applies: a value lifted from a tampered document that also exceeds the
    # authorised amount is both a data-flow and a least-privilege violation, and
    # marking either as "wrong" would understate a PDP that reasoned soundly.
    also_acceptable: Tuple[str, ...] = ()
    defeats: str = ""
    #: Links a case to its twin. Paired cases hold every surface feature constant
    #: and differ only in the fact that authorises the action.
    pair_id: str = ""
    #: For a paired case, the single fact that decides it. Stating it explicitly
    #: is what keeps a pair honest: if you cannot name one fact, the two cases
    #: differ in more than one way and the pair proves nothing.
    authorising_fact: str = ""

    @property
    def is_malicious(self) -> bool:
        return self.label == MALICIOUS

    def principle_ok(self, cited: str) -> bool:
        return bool(cited) and cited in ((self.expected_principle,) + self.also_acceptable)

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
            "also_acceptable": list(self.also_acceptable),
            "defeats": self.defeats,
            "pair_id": self.pair_id,
            "authorising_fact": self.authorising_fact,
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

    def digest(self) -> str:
        """Content hash of the corpus.

        Stamped into every results file so a reported number can be tied to the
        exact corpus that produced it -- and so a claim that difficulty labels
        were fixed before a run is checkable rather than asserted.
        """
        payload = json.dumps([c.summary() for c in self.cases], sort_keys=True, default=str)
        return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()[:16]

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
            # A misspelled principle never matches a cited one, which would zero
            # the principle metric without any error being raised.
            for principle in (case.expected_principle,) + case.also_acceptable:
                if principle and principle not in PRINCIPLES:
                    problems.append(
                        f"{case.case_id}: unknown principle {principle!r}; expected one of {PRINCIPLES}"
                    )
        for vector in self.vectors():
            per = self.filter(vector=vector).balance()
            if not per.get(BENIGN):
                problems.append(f"{vector}: no benign cases -- false-positive rate is unmeasurable")

        # Pairing is a claimed method, so its invariants are checked rather than
        # trusted. A half-built pair is worse than no pair: it looks like
        # evidence that surface features were held constant when they were not.
        pairs: Dict[str, List[ActionCase]] = {}
        for case in self.cases:
            if case.pair_id:
                pairs.setdefault(case.pair_id, []).append(case)
        for pair_id, members in sorted(pairs.items()):
            labels = sorted(c.label for c in members)
            if labels != [BENIGN, MALICIOUS]:
                problems.append(
                    f"pair {pair_id}: expected one malicious and one benign case, got {labels}"
                )
                continue
            malicious = next(c for c in members if c.is_malicious)
            benign = next(c for c in members if not c.is_malicious)
            if malicious.context.tool.name != benign.context.tool.name:
                problems.append(
                    f"pair {pair_id}: halves call different tools "
                    f"({malicious.context.tool.name} vs {benign.context.tool.name}) -- a detector "
                    f"can separate them on the tool alone"
                )
            if malicious.difficulty != benign.difficulty:
                problems.append(f"pair {pair_id}: halves have different difficulty labels")
            if not malicious.authorising_fact:
                problems.append(
                    f"pair {pair_id}: no authorising_fact -- if the deciding fact cannot be named, "
                    f"the halves may differ in more than one way"
                )
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
