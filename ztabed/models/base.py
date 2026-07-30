"""The model-adapter seam.

A `ModelAdapter` is the only place in the testbed that knows about a specific
provider's API. Everything above it speaks the provider-neutral types in
`ztabed.core.llm`, so swapping models is a matter of selecting a different
adapter -- not of touching scenarios, controls, or the runner.

To add a provider, subclass `ModelAdapter`, implement `complete()`, and
register it (see `ztabed/models/registry.py`).
"""
from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from ztabed.core.llm import LLMBackend, LLMTurnRequest, LLMTurnResponse


class AdapterUnavailable(RuntimeError):
    """The adapter cannot be constructed: missing SDK, credentials, or an
    invalid configuration for the selected model."""


class ModelCallError(RuntimeError):
    """A live model call failed after the provider's own retries were
    exhausted. Raised per trial so the runner can record it rather than
    abandoning a long (and paid-for) run."""


@dataclass
class ModelConfig:
    """Provider-neutral generation settings.

    Fields left as None are omitted from the request so the provider's own
    default applies. That matters for reproducibility: an omitted parameter is
    recorded as "provider default" rather than silently pinned to whatever
    this testbed happened to think was reasonable.

    `effort` and `thinking` are research variables, not just cost knobs -- how
    much a model deliberates measurably changes how it handles injected
    instructions. Sweep them rather than assuming one setting.
    """

    model: Optional[str] = None  # None -> the adapter's default_model
    max_tokens: int = 8192
    effort: Optional[str] = None  # "low" | "medium" | "high" | "xhigh" | "max"
    thinking: Optional[str] = None  # "adaptive" | "disabled"; None -> provider default
    temperature: Optional[float] = None  # omitted unless set; rejected by current Claude models
    max_retries: int = 4
    timeout: Optional[float] = None  # seconds
    extra: Dict[str, Any] = field(default_factory=dict)  # provider-specific escape hatch

    def describe(self) -> str:
        parts = [f"max_tokens={self.max_tokens}"]
        parts.append(f"effort={self.effort or 'provider-default'}")
        parts.append(f"thinking={self.thinking or 'provider-default'}")
        if self.temperature is not None:
            parts.append(f"temperature={self.temperature}")
        return " ".join(parts)


@dataclass
class ModelUsage:
    """Accumulated cost/consumption for one (provider, model) pair."""

    provider: str
    model: str
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0
    refusals: int = 0
    errors: int = 0
    estimated_cost_usd: float = 0.0

    def summary(self) -> str:
        line = (
            f"{self.provider}/{self.model}  {self.calls} calls  "
            f"in={self.input_tokens:,}  out={self.output_tokens:,}"
        )
        if self.cache_read_input_tokens:
            line += f"  cache_read={self.cache_read_input_tokens:,}"
        if self.refusals:
            line += f"  refusals={self.refusals}"
        if self.errors:
            line += f"  errors={self.errors}"
        if self.estimated_cost_usd:
            line += f"  ~${self.estimated_cost_usd:,.2f}"
        return line


class UsageLedger:
    """Thread-safe token and cost accounting for every live call in a run.

    Real-mode runs cost money and take minutes; a run that reports a 0% attack
    success rate because every call was refused or rate-limited looks exactly
    like a run where the control worked. The ledger is what tells those apart.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rows: Dict[Tuple[str, str], ModelUsage] = {}

    def record(
        self,
        *,
        provider: str,
        model: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_input_tokens: int = 0,
        cache_creation_input_tokens: int = 0,
        refusal: bool = False,
        error: bool = False,
        cost_usd: float = 0.0,
    ) -> None:
        with self._lock:
            row = self._rows.setdefault((provider, model), ModelUsage(provider=provider, model=model))
            row.calls += 1
            row.input_tokens += input_tokens
            row.output_tokens += output_tokens
            row.cache_read_input_tokens += cache_read_input_tokens
            row.cache_creation_input_tokens += cache_creation_input_tokens
            row.refusals += int(refusal)
            row.errors += int(error)
            row.estimated_cost_usd += cost_usd

    def rows(self) -> List[ModelUsage]:
        with self._lock:
            return [ModelUsage(**vars(row)) for row in self._rows.values()]

    def total_cost_usd(self) -> float:
        return sum(row.estimated_cost_usd for row in self.rows())

    def is_empty(self) -> bool:
        with self._lock:
            return not self._rows


class ModelAdapter(LLMBackend, ABC):
    """Base class for a live-model backend.

    Subclasses declare the provider name and the models they know about, then
    implement `complete()` to translate an `LLMTurnRequest` into a provider
    call and the response back into an `LLMTurnResponse`.

    Two responsibilities beyond translation:
      - record consumption into `self.ledger` (via `record_usage`) so a run's
        cost and refusal count are observable;
      - preserve multi-turn tool-call state, including any provider-native
        blocks that must be echoed back verbatim (store them on
        `Message.raw` / `LLMTurnResponse.raw` tagged via `raw_envelope`).
    """

    provider: ClassVar[str] = ""
    default_model: ClassVar[str] = ""
    known_models: ClassVar[Tuple[str, ...]] = ()
    # USD per million tokens, keyed by model id: {model: (input, output)}
    prices_per_mtok: ClassVar[Dict[str, Tuple[float, float]]] = {}

    def __init__(self, config: Optional[ModelConfig] = None, ledger: Optional[UsageLedger] = None):
        self.config = config or ModelConfig()
        self.model = self.config.model or self.default_model
        self.ledger = ledger

    @abstractmethod
    def complete(self, req: LLMTurnRequest) -> LLMTurnResponse:
        ...

    # ── helpers for subclasses ────────────────────────────────────────────────

    def raw_envelope(self, payload: Any) -> Dict[str, Any]:
        """Tag a provider-native payload with its provenance.

        An adapter must only replay blocks it produced itself, for the same
        model -- replaying another provider's (or another model's) internal
        blocks is at best ignored and at worst rejected.
        """
        return {"provider": self.provider, "model": self.model, "payload": payload}

    def own_payload(self, raw: Any) -> Optional[Any]:
        """Return the payload from `raw` if this adapter produced it, else None."""
        if isinstance(raw, dict) and raw.get("provider") == self.provider and raw.get("model") == self.model:
            return raw.get("payload")
        return None

    def cost_usd(self, input_tokens: int, output_tokens: int) -> float:
        price = self.prices_per_mtok.get(self.model)
        if price is None:
            return 0.0
        return (input_tokens / 1_000_000) * price[0] + (output_tokens / 1_000_000) * price[1]

    def record_usage(
        self,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_input_tokens: int = 0,
        cache_creation_input_tokens: int = 0,
        refusal: bool = False,
        error: bool = False,
    ) -> None:
        if self.ledger is None:
            return
        self.ledger.record(
            provider=self.provider,
            model=self.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_input_tokens=cache_read_input_tokens,
            cache_creation_input_tokens=cache_creation_input_tokens,
            refusal=refusal,
            error=error,
            cost_usd=self.cost_usd(input_tokens, output_tokens),
        )

    def describe(self) -> str:
        return f"{self.provider}/{self.model} ({self.config.describe()})"
