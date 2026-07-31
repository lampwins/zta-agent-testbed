"""Interval estimation and aggregation for a small, clustered corpus.

Two statistical facts shape everything here.

**The corpus is small.** A point estimate from 19 malicious cases is compatible
with a wide range of true rates: zero misses out of 19 has a 95% Wilson upper
bound near 17%, so "0% miss rate" quoted bare claims far more than the data
supports. Every headline rate therefore carries an interval.

**Repeats are clustered, not independent.** Running 35 cases five times gives 175
decisions but only 35 independent units. Treating the decisions as the sample
inflates the effective n by five and shrinks every interval accordingly -- and it
shows up as rates landing on suspiciously round multiples of one case. The
primary unit here is therefore the case, aggregated by majority vote across
repeats, with the decision-level rate reported alongside as a secondary figure.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Sequence, Tuple

#: Ties in a majority vote resolve toward the most restrictive outcome. A PDP
#: that is split 2-2-1 across repeats has not endorsed the permissive reading.
_RESTRICTIVENESS = {"DENY": 0, "CHALLENGE": 1, "ALLOW": 2, "ERROR": 3}


@dataclass
class Rate:
    """A proportion with its Wilson score interval."""

    numerator: int
    denominator: int
    lower: float
    upper: float

    @property
    def value(self) -> float:
        return self.numerator / self.denominator if self.denominator else 0.0

    def pct(self) -> str:
        return f"{self.value:.0%}"

    def ci(self) -> str:
        if not self.denominator:
            return "n/a"
        return f"[{self.lower:.0%}-{self.upper:.0%}]"

    def render(self) -> str:
        return f"{self.pct()} {self.ci()}"


def wilson(successes: int, trials: int, z: float = 1.96) -> Tuple[float, float]:
    """Wilson score interval.

    Preferred over the normal approximation because it stays inside [0, 1] and
    remains meaningful at the boundaries -- which is exactly where this corpus
    lives, since the interesting arms score zero misses.
    """
    if trials <= 0:
        return (0.0, 0.0)
    p = successes / trials
    denom = 1 + z * z / trials
    centre = p + z * z / (2 * trials)
    spread = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials))
    return (max(0.0, (centre - spread) / denom), min(1.0, (centre + spread) / denom))


def rate(successes: int, trials: int) -> Rate:
    low, high = wilson(successes, trials)
    return Rate(numerator=successes, denominator=trials, lower=low, upper=high)


def majority(decisions: Sequence[str]) -> str:
    """Collapse a case's repeats to one verdict, breaking ties restrictively."""
    if not decisions:
        return "ERROR"
    counts = Counter(decisions)
    top = max(counts.values())
    tied = [d for d, c in counts.items() if c == top]
    return min(tied, key=lambda d: _RESTRICTIVENESS.get(d, 9))


def agreement(decisions: Sequence[str]) -> float:
    """Share of repeats agreeing with the majority verdict for one case."""
    if not decisions:
        return 0.0
    return Counter(decisions)[majority(decisions)] / len(decisions)
