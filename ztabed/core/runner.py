from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional, Type

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
    # Real-mode only: the share of trials that produced no measurement at all.
    model_refusal_rate: float = 0.0
    model_error_rate: float = 0.0

    @property
    def unmeasured_rate(self) -> float:
        return self.model_refusal_rate + self.model_error_rate


@dataclass
class ABResult:
    scenario_name: str
    llm_mode: str
    trials_per_condition: int
    conditions: List[ConditionStats]
    raw_outcomes: dict
    model_description: Optional[str] = None
    usage: List[dict] = field(default_factory=list)
    estimated_cost_usd: float = 0.0


def _rate(outcomes: List[Outcome], predicate) -> float:
    return sum(bool(predicate(o)) for o in outcomes) / len(outcomes) if outcomes else 0.0


def _stats(label: str, outcomes: List[Outcome]) -> ConditionStats:
    return ConditionStats(
        label=label,
        trials=len(outcomes),
        attack_success_rate=_rate(outcomes, lambda o: o.attack_succeeded),
        block_rate=_rate(outcomes, lambda o: o.blocked_by_control),
        legitimate_completion_rate=_rate(outcomes, lambda o: o.legitimate_task_completed),
        model_refusal_rate=_rate(outcomes, lambda o: o.model_refused),
        model_error_rate=_rate(outcomes, lambda o: o.model_error is not None),
    )


class ABRunner:
    """Runs a scenario across the 3x2 {none, naive, zta} x {attack, benign}
    grid and reports comparative metrics.

    'naive' = simple existing-defence controls (the SOTA comparison point).
    'zta'   = full Zero Trust controls under evaluation.

    With `llm_mode="real"` each trial issues live model calls. Those runs are
    slow and metered, so: `concurrency` fans trials out across threads, a failed
    call is recorded as an errored trial rather than aborting the run, and token
    usage plus an estimated cost are reported alongside the metrics.
    """

    def __init__(
        self,
        scenario_cls: Type[Scenario],
        trials: int = 10,
        llm_mode: str = "mock",
        model_session=None,
        concurrency: int = 1,
    ):
        self.scenario_cls = scenario_cls
        self.trials = trials
        self.llm_mode = llm_mode
        self.model_session = model_session
        self.concurrency = max(1, concurrency)

    def _run_trial(self, control_mode: str, attack: bool, seed: int) -> Outcome:
        scenario = self.scenario_cls(llm_mode=self.llm_mode, model_session=self.model_session)
        try:
            return scenario.run(control_mode=control_mode, attack=attack, trial_seed=seed)
        except Exception as exc:  # a metered run should not lose completed work
            return Outcome(
                attack_succeeded=False,
                blocked_by_control=False,
                legitimate_task_completed=False,
                notes=f"trial failed: {type(exc).__name__}: {exc}",
                model_error=f"{type(exc).__name__}: {exc}",
            )

    def run(self) -> ABResult:
        jobs = [
            (label, control_mode, attack, seed)
            for label, control_mode, attack in _GRID
            for seed in range(self.trials)
        ]

        if self.concurrency > 1:
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                results = list(pool.map(lambda j: self._run_trial(j[1], j[2], j[3]), jobs))
        else:
            results = [self._run_trial(cm, at, sd) for _, cm, at, sd in jobs]

        raw: dict = {label: [] for label, _, _ in _GRID}
        for (label, _, _, _), outcome in zip(jobs, results):
            raw[label].append(outcome)

        usage_rows, cost = [], 0.0
        if self.model_session is not None:
            usage_rows = [asdict(row) for row in self.model_session.ledger.rows()]
            cost = self.model_session.ledger.total_cost_usd()

        return ABResult(
            scenario_name=self.scenario_cls.name,
            llm_mode=self.llm_mode,
            trials_per_condition=self.trials,
            conditions=[_stats(label, raw[label]) for label, _, _ in _GRID],
            raw_outcomes={k: [asdict(o) for o in v] for k, v in raw.items()},
            model_description=self.model_session.describe() if self.model_session is not None else None,
            usage=usage_rows,
            estimated_cost_usd=cost,
        )

    def run_and_print(self, save_dir: Path = None) -> ABResult:
        result = self.run()
        print(f"\n=== {result.scenario_name} (llm_mode={result.llm_mode}, n={result.trials_per_condition}) ===")
        if result.model_description:
            print(f"models: {result.model_description}")
        header = f"{'condition':<18}{'attack success':>16}{'blocked':>10}{'legit task ok':>16}"
        print(header)
        print("-" * len(header))
        for c in result.conditions:
            suffix = ""
            # A benign task that never ran is not a false positive. Only call it
            # one when the shortfall exceeds the trials that produced no
            # measurement at all.
            if not c.label.endswith("_attack"):
                fp = (1.0 - c.legitimate_completion_rate) - c.unmeasured_rate
                if fp > 1e-9:
                    suffix = f"  ({fp:.0%} FP)"
            # Unmeasured trials would otherwise read as successful defence.
            if c.model_refusal_rate:
                suffix += f"  [{c.model_refusal_rate:.0%} refused]"
            if c.model_error_rate:
                suffix += f"  [{c.model_error_rate:.0%} errored]"
            print(
                f"{c.label:<18}{c.attack_success_rate:>16.0%}"
                f"{c.block_rate:>10.0%}{c.legitimate_completion_rate:>16.0%}{suffix}"
            )

        for row in result.usage:
            line = (
                f"{row['provider']}/{row['model']}  {row['calls']} calls  "
                f"in={row['input_tokens']:,}  out={row['output_tokens']:,}"
            )
            if row["refusals"]:
                line += f"  refusals={row['refusals']}"
            if row["errors"]:
                line += f"  errors={row['errors']}"
            if row["estimated_cost_usd"]:
                line += f"  ~${row['estimated_cost_usd']:,.2f}"
            print(f"usage: {line}")

        if save_dir is not None:
            save_dir.mkdir(parents=True, exist_ok=True)
            out_path = save_dir / f"{result.scenario_name}_{int(time.time())}.json"
            out_path.write_text(json.dumps(asdict(result), indent=2))
            print(f"\nsaved raw results -> {out_path}")

        return result
