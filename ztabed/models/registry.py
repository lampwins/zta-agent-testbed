"""Adapter registry and per-run model session."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Type

from .base import AdapterUnavailable, ModelAdapter, ModelConfig, UsageLedger

_ADAPTERS: Dict[str, Type[ModelAdapter]] = {}


def register_adapter(cls: Type[ModelAdapter]) -> Type[ModelAdapter]:
    """Class decorator that makes an adapter selectable by `--provider`."""
    if not cls.provider:
        raise ValueError(f"{cls.__name__} must set a non-empty `provider` class attribute")
    _ADAPTERS[cls.provider] = cls
    return cls


def available_providers() -> List[str]:
    return sorted(_ADAPTERS)


def get_adapter(provider: str) -> Type[ModelAdapter]:
    try:
        return _ADAPTERS[provider]
    except KeyError:
        raise AdapterUnavailable(
            f"no adapter registered for provider '{provider}'. "
            f"Available: {', '.join(available_providers()) or '(none)'}"
        ) from None


@dataclass
class LiveModelSettings:
    """Which provider and models a real-mode run should use.

    Roles are separated because the scenarios put a second, isolated model
    behind `IntentAuditControl`. Auditing with the same model that is being
    attacked is a legitimate configuration to study, but so is auditing with a
    different (often cheaper) one -- so it is a setting, not a hardcode.
    """

    provider: str = "anthropic"
    agent_model: Optional[str] = None  # None -> the adapter's default_model
    auditor_model: Optional[str] = None  # None -> same as agent_model
    config: ModelConfig = field(default_factory=ModelConfig)


class ModelSession:
    """Holds the backends and the usage ledger for one run.

    Backends are built once per role and shared across trials, so a run
    accumulates its cost in a single ledger and does not rebuild a client per
    trial. Construction is locked because `--concurrency` runs trials on
    threads.
    """

    def __init__(self, settings: Optional[LiveModelSettings] = None, ledger: Optional[UsageLedger] = None):
        self.settings = settings or LiveModelSettings()
        self.ledger = ledger or UsageLedger()
        self._adapter_cls = get_adapter(self.settings.provider)
        self._backends: Dict[str, ModelAdapter] = {}
        self._lock = threading.Lock()

    def _model_for(self, role: str) -> Optional[str]:
        if role == "auditor":
            return self.settings.auditor_model or self.settings.agent_model
        return self.settings.agent_model

    def backend(self, role: str = "assistant") -> ModelAdapter:
        with self._lock:
            backend = self._backends.get(role)
            if backend is None:
                config = replace_model(self.settings.config, self._model_for(role))
                backend = self._adapter_cls(config=config, ledger=self.ledger)
                self._backends[role] = backend
            return backend

    def describe(self) -> str:
        with self._lock:
            roles = self._backends
        if not roles:
            return f"{self.settings.provider} (no backends built yet)"
        return "; ".join(f"{role}={backend.describe()}" for role, backend in sorted(roles.items()))


def replace_model(config: ModelConfig, model: Optional[str]) -> ModelConfig:
    """Copy `config` with `model` overridden (None keeps the adapter default)."""
    fields = dict(vars(config))
    fields["model"] = model
    fields["extra"] = dict(config.extra)
    return ModelConfig(**fields)
