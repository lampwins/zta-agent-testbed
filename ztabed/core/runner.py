from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Type

from .scenario import Outcome, Scenario

# Ordered so the printed table reads: none → naive → zta for each traffic type.
_GRID = [
    ("none_attack",  "none",  True),
    ("naive_attack", "naive", True),
    ("zta_attack",   "zta",   True),
    ("none_benign",  "none",  False),
    ("naive_benign", "naive", False),
    ("zta_benign",   "zta",   False),
]


@dataclass
class ConditionStats:
    label: str
    trials: int
    attack_success_rate: float
    block_rate: float
    legitimate_completion_rate: float


@dataclass
class ABResult:
    scenario_name: str
    llm_mode: str
    trials_per_condition: int
    conditions: List[ConditionStats]
    raw_outcomes: dict


def _stats(label: str, outcomes: List[Outcome]) -> ConditionStats:
    n = len(outcomes)
    return ConditionStats(
        label=label,
        trials=n,
        attack_success_rate=sum(o.attack_succeeded for o in outcomes) / n,
        block_rate=sum(o.blocked_by_control for o in outcomes) / n,
        legitimate_completion_rate=sum(o.legitimate_task_completed for o in outcomes) / n,
    )


class ABRunner:
    """Runs a scenario across the 3x2 {none, naive, zta} x {attack, benign}
    grid and reports comparative metrics.

    'naive' = simple existing-defence controls (the SOTA comparison point).
    'zta'   = full Zero Trust controls under evaluation.
    """

    def __init__(self, scenario_cls: Type[Scenario], trials: int = 10, llm_mode: str = "mock"):
        self.scenario_cls = scenario_cls
        self.trials = trials
        self.llm_mode = llm_mode

    def run(self) -> ABResult:
        raw = {}
        for label, control_mode, attack in _GRID:
            outcomes = []
            for seed in range(self.trials):
                scenario = self.scenario_cls(llm_mode=self.llm_mode)
                outcomes.append(scenario.run(control_mode=control_mode, attack=attack, trial_seed=seed))
            raw[label] = outcomes

        conditions = [_stats(label, raw[label]) for label, _, _ in _GRID]

        return ABResult(
            scenario_name=self.scenario_cls.name,
            llm_mode=self.llm_mode,
            trials_per_condition=self.trials,
            conditions=conditions,
            raw_outcomes={k: [asdict(o) for o in v] for k, v in raw.items()},
        )

    def run_and_print(self, save_dir: Path = None) -> ABResult:
        result = self.run()
        print(f"\n=== {result.scenario_name} (llm_mode={result.llm_mode}, n={result.trials_per_condition}) ===")
        header = f"{'condition':<18}{'attack success':>16}{'blocked':>10}{'legit task ok':>16}"
        print(header)
        print("-" * len(header))
        for c in result.conditions:
            suffix = ""
            if not c.label.endswith("_attack") and c.legitimate_completion_rate < 1.0:
                fp = 1.0 - c.legitimate_completion_rate
                suffix = f"  ({fp:.0%} FP)"
            print(
                f"{c.label:<18}{c.attack_success_rate:>16.0%}"
                f"{c.block_rate:>10.0%}{c.legitimate_completion_rate:>16.0%}{suffix}"
            )

        if save_dir is not None:
            save_dir.mkdir(parents=True, exist_ok=True)
            out_path = save_dir / f"{result.scenario_name}_{int(time.time())}.json"
            out_path.write_text(json.dumps(asdict(result), indent=2))
            print(f"\nsaved raw results -> {out_path}")

        return result
