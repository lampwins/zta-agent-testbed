"""Anthropic (Claude) model adapter.

The only vendor-specific module in the testbed. It maps the neutral
conversation types onto the Messages API, including the parts of the tool-use
protocol that must be exact:

  - the assistant turn carrying `tool_use` blocks is replayed verbatim, so the
    `tool_use_id` on each `tool_result` matches and any thinking blocks are
    echoed back unchanged (the API rejects modified ones);
  - all `tool_result` blocks for one assistant turn go back in a *single* user
    message, since splitting them teaches the model to stop calling tools in
    parallel.
"""
from __future__ import annotations

import warnings
from typing import Any, Dict, List, Optional

from ztabed.core.llm import LLMTurnRequest, LLMTurnResponse, Message
from ztabed.core.tools import ToolCallRequest, ToolSpec

from .base import AdapterUnavailable, ModelAdapter, ModelCallError, ModelConfig, UsageLedger
from .registry import register_adapter

# Above this, the SDK refuses a non-streaming request because the response
# would risk an HTTP timeout, so switch to the streaming path.
_STREAM_ABOVE_MAX_TOKENS = 16_000

# Models that reject an explicit thinking:{"type": "disabled"} at any effort.
_ALWAYS_THINKING_PREFIXES = ("claude-fable-", "claude-mythos-")

# Disabling thinking is only accepted at effort "high" or below.
_EFFORT_BLOCKS_DISABLED_THINKING = {"xhigh", "max"}

_VALID_EFFORT = ("low", "medium", "high", "xhigh", "max")
_VALID_THINKING = ("adaptive", "disabled")


@register_adapter
class AnthropicAdapter(ModelAdapter):
    provider = "anthropic"
    default_model = "claude-opus-5"
    known_models = (
        "claude-opus-5",
        "claude-sonnet-5",
        "claude-haiku-4-5",
        "claude-opus-4-8",
        "claude-fable-5",
    )
    # USD per million tokens (input, output). Used for run-cost estimates only;
    # check current pricing at platform.claude.com/docs/en/pricing.
    prices_per_mtok = {
        "claude-fable-5": (10.0, 50.0),
        "claude-opus-5": (5.0, 25.0),
        "claude-opus-4-8": (5.0, 25.0),
        "claude-sonnet-5": (3.0, 15.0),
        "claude-haiku-4-5": (1.0, 5.0),
    }

    def __init__(self, config: Optional[ModelConfig] = None, ledger: Optional[UsageLedger] = None):
        super().__init__(config=config, ledger=ledger)
        self._validate_config()

        try:
            import anthropic
        except ImportError as exc:
            raise AdapterUnavailable(
                "the 'anthropic' package is required for --provider anthropic. "
                "Install it with: pip install anthropic"
            ) from exc

        self._anthropic = anthropic
        client_kwargs: Dict[str, Any] = {"max_retries": self.config.max_retries}
        if self.config.timeout is not None:
            client_kwargs["timeout"] = self.config.timeout
        try:
            # Zero-arg credential resolution: ANTHROPIC_API_KEY, then
            # ANTHROPIC_AUTH_TOKEN, then an `ant auth login` profile. An unset
            # API key does not mean there are no credentials.
            self._client = anthropic.Anthropic(**client_kwargs)
        except Exception as exc:
            raise AdapterUnavailable(f"could not construct an Anthropic client: {exc}") from exc

        self._preflight_credentials()

    def _preflight_credentials(self) -> None:
        """Fail at startup rather than on the first billable call.

        The SDK resolves credentials lazily: constructing a client with none
        succeeds, and the failure only surfaces per request. For a grid that
        fans out 150 trials that turns one missing env var into 150 identical
        errored trials and a table of zeros. Reuse the SDK's own header
        resolution so an API key, an auth token, and an `ant auth login`
        profile are all judged the way a real request would judge them.
        """
        validate = getattr(self._client, "_validate_headers", None)
        if validate is None:  # SDK internals moved; let the first call report it
            return
        try:
            validate(dict(self._client.default_headers), {})
        except TypeError as exc:
            raise AdapterUnavailable(
                "no Anthropic credentials resolved. Set ANTHROPIC_API_KEY, or run `ant auth login`."
            ) from exc

    def _validate_config(self) -> None:
        cfg = self.config
        if cfg.effort is not None and cfg.effort not in _VALID_EFFORT:
            raise AdapterUnavailable(f"effort must be one of {_VALID_EFFORT}, got {cfg.effort!r}")
        if cfg.thinking is not None and cfg.thinking not in _VALID_THINKING:
            raise AdapterUnavailable(f"thinking must be one of {_VALID_THINKING}, got {cfg.thinking!r}")

        if cfg.thinking == "disabled":
            if cfg.effort in _EFFORT_BLOCKS_DISABLED_THINKING:
                raise AdapterUnavailable(
                    f"thinking='disabled' is not accepted at effort={cfg.effort!r} on Claude models "
                    "(only 'high' or below). Raise thinking or lower effort."
                )
            if self.model.startswith(_ALWAYS_THINKING_PREFIXES):
                raise AdapterUnavailable(
                    f"{self.model} always thinks; thinking='disabled' is rejected. "
                    "Omit it or use 'adaptive'."
                )

        if cfg.temperature is not None:
            warnings.warn(
                f"temperature is set ({cfg.temperature}) but current Claude models reject sampling "
                "parameters and will return a 400. Omit it and steer via the prompt instead.",
                stacklevel=3,
            )

    # ── request construction ─────────────────────────────────────────────────

    def _tool_schemas(self, tools: List[ToolSpec]) -> List[dict]:
        return [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema()}
            for t in tools
        ]

    def _assistant_content(self, message: Message) -> Any:
        """Rebuild an assistant turn.

        Prefers this adapter's own response blocks so thinking blocks survive
        the round trip unchanged and tool_use ids line up with the tool_result
        blocks that follow.
        """
        payload = self.own_payload(message.raw)
        if payload:
            return payload

        blocks: List[dict] = []
        if message.content:
            blocks.append({"type": "text", "text": message.content})
        for call in message.tool_calls:
            if call.call_id is None:
                # No provider id to correlate against; the matching tool_result
                # would be rejected, so fall back to a plain text turn.
                continue
            blocks.append(
                {"type": "tool_use", "id": call.call_id, "name": call.name, "input": call.arguments}
            )
        return blocks or [{"type": "text", "text": "(no content)"}]

    def _render_messages(self, history: List[Message]) -> List[dict]:
        messages: List[dict] = []
        pending_results: List[dict] = []

        def flush_results() -> None:
            # All results for one assistant turn must arrive together.
            if pending_results:
                messages.append({"role": "user", "content": list(pending_results)})
                pending_results.clear()

        for message in history:
            if message.role == "tool":
                if message.tool_call_id is None:
                    # Result with nothing to correlate to (e.g. a transcript
                    # replayed from mock mode). Pass it as plain narration.
                    flush_results()
                    label = message.name or "tool"
                    messages.append({"role": "user", "content": f"[{label} result]\n{message.content}"})
                    continue
                block: Dict[str, Any] = {
                    "type": "tool_result",
                    "tool_use_id": message.tool_call_id,
                    "content": message.content,
                }
                if message.is_error:
                    block["is_error"] = True
                pending_results.append(block)
                continue

            flush_results()
            if message.role == "assistant":
                messages.append({"role": "assistant", "content": self._assistant_content(message)})
            else:
                messages.append({"role": "user", "content": message.content})

        flush_results()
        return messages

    def _request_kwargs(self, req: LLMTurnRequest) -> Dict[str, Any]:
        cfg = self.config
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": cfg.max_tokens,
            "system": req.system,
            "messages": self._render_messages(req.history),
        }
        if req.tools:
            kwargs["tools"] = self._tool_schemas(req.tools)
        if cfg.effort is not None:
            kwargs["output_config"] = {"effort": cfg.effort}
        if cfg.thinking is not None:
            kwargs["thinking"] = {"type": cfg.thinking}
        if cfg.temperature is not None:
            kwargs["temperature"] = cfg.temperature
        kwargs.update(cfg.extra)
        return kwargs

    # ── the call ─────────────────────────────────────────────────────────────

    def complete(self, req: LLMTurnRequest) -> LLMTurnResponse:
        kwargs = self._request_kwargs(req)
        try:
            if kwargs["max_tokens"] > _STREAM_ABOVE_MAX_TOKENS:
                with self._client.messages.stream(**kwargs) as stream:
                    response = stream.get_final_message()
            else:
                response = self._client.messages.create(**kwargs)
        except self._anthropic.APIStatusError as exc:
            self.record_usage(error=True)
            raise ModelCallError(
                f"{self.provider}/{self.model} returned {exc.status_code} ({exc.type}): {exc.message}"
            ) from exc
        except self._anthropic.APIConnectionError as exc:
            self.record_usage(error=True)
            raise ModelCallError(f"{self.provider}/{self.model} connection failed: {exc}") from exc
        except Exception as exc:
            # The SDK also raises plain TypeError/ValueError for things it
            # validates client-side. Those are still failed calls and belong in
            # the ledger, so the run's error count matches what actually
            # happened. Kept off `_parse` so bugs in our own parsing still raise.
            self.record_usage(error=True)
            raise ModelCallError(f"{self.provider}/{self.model} call failed: {type(exc).__name__}: {exc}") from exc

        return self._parse(response)

    def _parse(self, response: Any) -> LLMTurnResponse:
        usage = getattr(response, "usage", None)
        refused = response.stop_reason == "refusal"
        self.record_usage(
            input_tokens=getattr(usage, "input_tokens", 0) or 0,
            output_tokens=getattr(usage, "output_tokens", 0) or 0,
            cache_read_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            cache_creation_input_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            refusal=refused,
        )

        if refused:
            # Safety classifiers declined the request: HTTP 200, but `content`
            # is empty or partial. Attack scenarios trip this occasionally, and
            # a refused trial is not the same result as a defeated attack --
            # surface it rather than scoring it as a blocked attack.
            return LLMTurnResponse(
                text=None,
                stop_reason=response.stop_reason,
                refused=True,
                refusal_detail=_refusal_detail(response),
                raw=self.raw_envelope(list(response.content)),
            )

        text_parts: List[str] = []
        tool_calls: List[ToolCallRequest] = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCallRequest(name=block.name, arguments=dict(block.input or {}), call_id=block.id)
                )

        return LLMTurnResponse(
            text="\n".join(text_parts) or None,
            tool_calls=tool_calls,
            stop_reason=response.stop_reason,
            raw=self.raw_envelope(list(response.content)),
        )


def _refusal_detail(response: Any) -> Optional[str]:
    details = getattr(response, "stop_details", None)
    if details is None:
        return None
    category = getattr(details, "category", None)
    explanation = getattr(details, "explanation", None)
    return " ".join(part for part in (category, explanation) if part) or None
