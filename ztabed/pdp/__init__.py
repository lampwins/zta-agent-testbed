"""Policy Decision Points: the component under evaluation.

`baselines` holds the deterministic arms, `llm_judge` puts a language model in the
PDP box, and `arms` assembles them into the configurations being compared.
"""
from .arms import ALL_ARMS, ARM_DESCRIPTIONS, LIVE_ARMS, OFFLINE_ARMS, arm_needs_model, build_arm
from .baselines import naive_pdp, zta_static_pdp
from .llm_judge import PDP_SYSTEM_PROMPT, VERDICT_SCHEMA, LLMJudgePDP, render_action_context

__all__ = [
    "ALL_ARMS",
    "ARM_DESCRIPTIONS",
    "LIVE_ARMS",
    "OFFLINE_ARMS",
    "LLMJudgePDP",
    "PDP_SYSTEM_PROMPT",
    "VERDICT_SCHEMA",
    "arm_needs_model",
    "build_arm",
    "naive_pdp",
    "render_action_context",
    "zta_static_pdp",
]
