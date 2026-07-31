"""The PDP configurations being compared, and the machinery to ablate them.

An "arm" is one complete policy: an ordered list of PDPs composed
most-restrictive-wins. Arms are declared as **named rule sets** rather than
hand-built lists so that individual rules can be added or removed from the
command line. That matters for one specific claim: showing that a rule engine
cannot reach a class of cases requires demonstrating what it costs to try, not
asserting that no rule exists. An ablation that adds the rule and reports the
false positives it buys is a tradeoff frontier; the assertion alone is refutable
by any reader who thinks of the rule you left out.

  none         Baseline. What reaches the resource with no policy at all.
  naive        Widely-deployed shortcuts. The state-of-practice comparison.
  zta_static   A rule-based Zero Trust engine.
  zta_llm      A language model in the PDP box.
  zta_hybrid   Static rules first, model only on what the rules would permit.
  zta_soft     Static rules that CHALLENGE instead of DENY, then the model.

`zta_soft` exists because deny-overrides composition is asymmetric: putting cheap
rules first recovers misses (anything they deny, the model need not catch) but
can never recover a false positive, since the first denial short-circuits and the
layer that would have corrected it is never asked. Downgrading the cheap layer's
denials to challenges makes its mistakes recoverable, at the cost of the
short-circuit saving that motivated the ordering.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

from ztabed.core.policy import Decision, PolicyDecision, PolicyDecisionPoint

from .baselines import NAIVE_RULES, ZTA_RULES, build_rules
from .llm_judge import LLMJudgePDP

OFFLINE_ARMS = ("none", "naive", "zta_static")
LIVE_ARMS = ("zta_llm", "zta_hybrid", "zta_soft")
ALL_ARMS = OFFLINE_ARMS + LIVE_ARMS

ARM_DESCRIPTIONS: Dict[str, str] = {
    "none": "no policy (defines the attack surface)",
    "naive": "widely-deployed shortcuts (state of practice)",
    "zta_static": "rule-based Zero Trust engine",
    "zta_llm": "language model as the PDP",
    "zta_hybrid": "rules first, model on what rules would permit",
    "zta_soft": "rules CHALLENGE instead of DENY, then the model",
}

#: Which named rule set each arm draws its deterministic rules from.
ARM_RULESETS: Dict[str, Tuple[str, ...]] = {
    "none": (),
    "naive": NAIVE_RULES,
    "zta_static": ZTA_RULES,
    "zta_llm": (),
    "zta_hybrid": ZTA_RULES,
    "zta_soft": ZTA_RULES,
}


class ChallengeDowngrade(PolicyDecisionPoint):
    """Turns an inner PDP's DENY into a CHALLENGE.

    A denial is final under deny-overrides composition, so a cheap layer that
    denies wrongly cannot be corrected by anything downstream. Downgrading to
    CHALLENGE keeps the action off the resource while leaving it visible to the
    layers behind, trading the short-circuit saving for recoverability.
    """

    def __init__(self, inner: PolicyDecisionPoint, label: Optional[str] = None):
        self.inner = inner
        self.name = label or f"soft:{inner.name}"

    def evaluate(self, ctx) -> PolicyDecision:
        decision = self.inner.evaluate(ctx)
        if decision.decision is Decision.DENY:
            return PolicyDecision(
                Decision.CHALLENGE,
                f"{decision.reason} (downgraded from DENY so a later layer can still correct it)",
                self.name,
                principle=decision.principle,
                confidence=decision.confidence,
            )
        return decision


def build_arm(
    arm: str,
    backend_factory: Optional[Callable[[], object]] = None,
    add_rules: Tuple[str, ...] = (),
    drop_rules: Tuple[str, ...] = (),
    system_prompt: Optional[str] = None,
) -> List[PolicyDecisionPoint]:
    """Assemble an arm, optionally with rules added or removed.

    `add_rules` / `drop_rules` name rules from the registry in
    `ztabed.pdp.baselines`, and are what make an ablation a command-line
    argument rather than a code change.
    """
    if arm not in ARM_RULESETS:
        raise KeyError(f"unknown arm {arm!r}; available: {', '.join(ALL_ARMS)}")

    if arm == "none":
        # The baseline is the reference every other arm is measured against, so
        # ablation flags must never reach it. Letting `--add-rule` give the
        # no-policy arm a rule silently turns 100% miss into something else and
        # invalidates the whole comparison.
        return []

    names = tuple(n for n in ARM_RULESETS[arm] if n not in drop_rules) + tuple(
        n for n in add_rules if n not in ARM_RULESETS[arm]
    )
    rules = build_rules(names)

    if arm not in LIVE_ARMS:
        return rules

    if backend_factory is None:
        raise ValueError(f"arm {arm!r} needs a live model backend; pass --mode real")
    # `system_prompt` carries the prompt variant under test. Omitted means the
    # published prompt; see ztabed.pdp.llm_judge for the ablatable clauses.
    judge = (
        LLMJudgePDP(backend_factory(), system_prompt=system_prompt)
        if system_prompt is not None
        else LLMJudgePDP(backend_factory())
    )

    if arm == "zta_llm":
        return [judge]
    if arm == "zta_soft":
        return [ChallengeDowngrade(r) for r in rules] + [judge]
    return rules + [judge]


def arm_needs_model(arm: str) -> bool:
    return arm in LIVE_ARMS


def arm_rules(arm: str) -> Tuple[str, ...]:
    return ARM_RULESETS.get(arm, ())
