"""Pluggable live-model backends.

`ztabed.models.base.ModelAdapter` is the extension point: implement it for a
provider, decorate the class with `@register_adapter`, and it becomes
selectable as `--provider <name>`. Only the Anthropic adapter ships here.
"""
from .base import (
    AdapterUnavailable,
    ModelAdapter,
    ModelCallError,
    ModelConfig,
    ModelUsage,
    UsageLedger,
)
from .registry import (
    LiveModelSettings,
    ModelSession,
    available_providers,
    get_adapter,
    register_adapter,
)

# Imported for its registration side effect. Add new adapters here.
from . import anthropic_adapter  # noqa: F401  (registers AnthropicAdapter)

__all__ = [
    "AdapterUnavailable",
    "LiveModelSettings",
    "ModelAdapter",
    "ModelCallError",
    "ModelConfig",
    "ModelSession",
    "ModelUsage",
    "UsageLedger",
    "available_providers",
    "get_adapter",
    "register_adapter",
]
