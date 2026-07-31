"""The PDP configurations being compared.

An "arm" is one complete policy: a list of PDPs composed most-restrictive-wins.
Four of them, chosen so the comparison isolates what each layer contributes.

  none        Baseline. What reaches the resource with no policy at all, which is
              what defines the attack surface the other arms are measured against.
  naive       Widely-deployed shortcuts. The state-of-practice comparison point.
  zta_static  A rule-based Zero Trust engine. Cheap, deterministic, auditable.
  zta_llm     A language model in the PDP box, ruling on the same ActionContext.
  zta_hybrid  Static rules first, model only on what the rules would permit.

`zta_hybrid` is the arm that tests the interesting claim. Because composition
short-circuits on the first DENY, the model is never consulted for a case the
cheap deterministic rules already settled -- so if the two layers fail in
complementary ways, the hybrid should beat both while costing a fraction of
`zta_llm`.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from ztabed.core.policy import PolicyDecisionPoint

from .baselines import naive_pdp, zta_static_pdp
from .llm_judge import LLMJudgePDP

# An arm builder takes a factory for a live PDP backend (None in offline arms).
ArmBuilder = Callable[[Optional[Callable[[], object]]], List[PolicyDecisionPoint]]

#: Arms that need no model, so they can run offline and for free.
OFFLINE_ARMS = ("none", "naive", "zta_static")
#: Arms that consult a live model.
LIVE_ARMS = ("zta_llm", "zta_hybrid")

ALL_ARMS = OFFLINE_ARMS + LIVE_ARMS


def build_arm(arm: str, backend_factory: Optional[Callable[[], object]] = None) -> List[PolicyDecisionPoint]:
    if arm == "none":
        return []
    if arm == "naive":
        return naive_pdp()
    if arm == "zta_static":
        return zta_static_pdp()

    if arm in LIVE_ARMS:
        if backend_factory is None:
            raise ValueError(f"arm {arm!r} needs a live model backend; pass --mode real")
        judge = LLMJudgePDP(backend_factory())
        if arm == "zta_llm":
            return [judge]
        # Deterministic rules first: they short-circuit on DENY, so the model is
        # only asked about cases the rules would have let through.
        return zta_static_pdp() + [judge]

    raise KeyError(f"unknown arm {arm!r}; available: {', '.join(ALL_ARMS)}")


def arm_needs_model(arm: str) -> bool:
    return arm in LIVE_ARMS


ARM_DESCRIPTIONS: Dict[str, str] = {
    "none": "no policy (defines the attack surface)",
    "naive": "widely-deployed shortcuts (state of practice)",
    "zta_static": "rule-based Zero Trust engine",
    "zta_llm": "language model as the PDP",
    "zta_hybrid": "rules first, model on what rules would permit",
}
