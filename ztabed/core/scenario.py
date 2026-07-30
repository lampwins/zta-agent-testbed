from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Outcome:
    attack_succeeded: bool  # malicious effect was achieved (e.g. exfil, fraudulent transfer)
    blocked_by_control: bool  # a control denied the malicious tool call
    legitimate_task_completed: bool  # the benign, intended task still got done
    notes: str = ""
    details: dict = field(default_factory=dict)


class Scenario(ABC):
    """One reproducible attack vector + the legitimate-use counterpart.

    `run(hardened, attack)` covers a 2x2 design:
      - attack=True,  hardened=False -> does the attack succeed with no controls?
      - attack=True,  hardened=True  -> does the control catch it?
      - attack=False, hardened=False -> sanity check, legit task works baseline
      - attack=False, hardened=True  -> false-positive check: does the control
                                         get in the way of legitimate use?
    """

    name: str = "scenario"
    description: str = ""

    def __init__(self, llm_mode: str = "mock"):
        self.llm_mode = llm_mode

    @abstractmethod
    def run(self, control_mode: str, attack: bool, trial_seed: int = 0) -> Outcome:
        """Run one trial.

        control_mode: "none" | "naive" | "zta"
          - "none"  – baseline, no controls attached
          - "naive" – simple existing-defence controls (the SOTA comparison point)
          - "zta"   – full Zero Trust controls under evaluation
        trial_seed: integer used to select the attack difficulty variant and to
          model any stochastic behaviour of the controls in a reproducible way.
        """
        ...
