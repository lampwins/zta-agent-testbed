# ztabed — Zero Trust Agent security testbed

A small A/B framework for reproducing AI-agent attack vectors and measuring
whether a Zero Trust control catches them, without breaking the legitimate
use case.

## Concepts

- **Scenario** (`ztabed/scenarios/`): one attack vector + its legitimate-use
  counterpart. Each scenario builds an `Agent` whose underlying behavior
  (the mock LLM "policy", or the system prompt in real mode) is **identical**
  whether or not controls are attached — that's what makes the comparison
  an A/B test and not just "two different agents."
- **Control** (`ztabed/controls/`): a Zero Trust enforcement point that
  gates a tool call before it executes (`Control.evaluate`). A run is
  "baseline" with zero controls attached, "hardened" with one or more.
- **Model adapter** (`ztabed/models/`): the seam between the testbed and a
  live model API. Scenarios, controls, and the runner only ever speak the
  provider-neutral types in `ztabed/core/llm.py`, so which model is under
  test is a `--provider`/`--model` choice rather than a code change.
- **ABRunner** (`ztabed/core/runner.py`): runs a scenario across the full
  3x2 grid — {none, naive, zta} x {attack, benign} — and reports, per
  condition: attack success rate, block rate, and legitimate-task
  completion rate (the false-positive/usability cost of the control).

## Scenarios included

| name | attack vector | control under test |
|---|---|---|
| `prompt_injection` | instructions hidden in fetched web content hijack the agent | `IntentAuditControl` — agent's planned action is summarized and checked by an isolated auditor against the original request |
| `confused_deputy` | a tampered invoice redirects/inflates a payment | `LeastPrivilegeControl` — tool args are capped/matched against scope derived from the original trusted request |
| `agent_impersonation` | a forged envelope claims to be a trusted peer agent | `IdentityVerificationControl` — HMAC-signed envelopes, verified against a known-sender registry |
| `malicious_tool` | a rogue tool registration (e.g. compromised MCP server) silently exfiltrates data | `ToolProvenanceControl` — only tools from an allowlisted source/trust level may execute |

## Usage

```bash
cd zta-agent-testbed

python -m ztabed.cli list
python -m ztabed.cli run --scenario prompt_injection --trials 20
python -m ztabed.cli run --scenario all --trials 20 --save
```

`--save` writes raw per-trial outcomes as JSON to `results/` for offline
analysis (e.g. loading into pandas for the paper).

### Running against a live model

```bash
python3 -m venv .venv            # mock mode needs no dependencies; real mode does
source .venv/bin/activate
pip install -r requirements.txt

export ANTHROPIC_API_KEY=...     # or run `ant auth login`

python -m ztabed.cli models      # registered adapters and their model ids

python -m ztabed.cli run --scenario prompt_injection --mode real --trials 5
python -m ztabed.cli run --scenario all --mode real --trials 10 \
    --model claude-opus-5 --auditor-model claude-haiku-4-5 \
    --effort low --concurrency 6 --save
```

Live-model flags:

| flag | effect |
|---|---|
| `--provider` | which model adapter to use (default `anthropic`) |
| `--model` | model id for the agent under test (default: the adapter's own default) |
| `--auditor-model` | model id for the isolated auditor in `zta` runs (default: same as `--model`) |
| `--effort` | `low`…`max`; omitted means the provider's default |
| `--thinking` | `adaptive` or `disabled`; omitted means the provider's default |
| `--max-tokens` | output cap per call — **covers thinking plus text** (default 8192) |
| `--concurrency` | trials to run in parallel; real runs are I/O-bound and slow |
| `--max-retries` | provider-level retries for rate limits and 5xx (default 4) |

Credentials are resolved by the provider SDK, so an unset `ANTHROPIC_API_KEY`
is fine if an `ant auth login` profile is active. A missing credential or an
invalid `--effort`/`--thinking` combination fails before the first billable
call, and a run in which every trial refused or errored exits non-zero rather
than printing a table of zeros that reads like a clean result.

## Adding your own attack vector or control

1. Add a `Control` subclass in `ztabed/controls/` implementing `evaluate(ctx) -> PolicyDecision`.
2. Add a `Scenario` subclass in `ztabed/scenarios/` with a vulnerable mock
   policy and a `run(control_mode, attack, trial_seed)` that wires the control
   in only for the relevant `control_mode`.
3. Register it in `ztabed/scenarios/__init__.py`'s `ALL_SCENARIOS` dict.

Score outcomes from **observable side effects** (what landed in the email
sink, the transfer log, the exfil log), not from the mock policy's scripted
branch. Side-effect scoring is what lets one scenario measure a live model,
which will not follow the script.

## Adding a model provider

1. Subclass `ModelAdapter` (`ztabed/models/base.py`), set `provider`,
   `default_model`, `known_models`, and `prices_per_mtok`, and implement
   `complete(LLMTurnRequest) -> LLMTurnResponse`.
2. Decorate it with `@register_adapter` and import the module in
   `ztabed/models/__init__.py` so the registration side effect runs. It is
   then selectable as `--provider <name>`.
3. Import the provider SDK lazily inside `__init__` and raise
   `AdapterUnavailable` if it (or a credential) is missing, so mock-mode runs
   never need the dependency.

An adapter owes the rest of the testbed three things:

- **Tool-call correlation.** Put the provider's call id on
  `ToolCallRequest.call_id`; the agent hands it back on the matching
  `Message.tool_call_id`.
- **Verbatim replay.** If the provider requires its own response blocks to be
  echoed back unchanged on the next turn (Anthropic's thinking blocks, for
  example), stash them via `raw_envelope()` and read them back with
  `own_payload()`. The envelope is provenance-tagged so one adapter never
  replays another adapter's internal blocks.
- **Usage accounting.** Call `record_usage()` on every call, including
  refusals and errors.

`AnthropicAdapter` is the reference implementation.

## Notes on `--mode real`

Real mode uses live model calls with deliberately naive system prompts (the
point is to test whether the *control*, not a hand-tuned prompt, catches the
attack). Everything else about a scenario — the tools, the injected payloads,
the controls, the scoring — is identical to mock mode, so the two modes
measure the same thing.

Mock mode remains the recommended setting for reproducible, free,
deterministic measurement; real mode is for checking that a control's effect
survives contact with an actual model.

Things worth knowing before reading real-mode numbers:

- **`--effort` and `--thinking` are independent variables, not just cost
  knobs.** How much a model deliberates measurably changes how it handles
  injected instructions. Sweep them; don't pick one and report the result as
  "the" susceptibility of a model.
- **Unmeasured trials are reported separately.** A refused request
  (`stop_reason: "refusal"`, which attack scenarios do trip) or a failed call
  produces no measurement, and is *not* counted as the control blocking the
  attack. The table annotates those conditions with `[N% refused]` /
  `[N% errored]`, and `blocked_by_control` is read from an actual control
  denial rather than inferred from the attack failing.
- **The scripted false-positive rates are mock-only.** Two scenarios model a
  control's FP rate with a seed-based branch (`trial_seed % 13 == 0` and
  friends). Those branches are skipped in real mode, where the FP rate is
  whatever the control actually does.
- **Token usage and an estimated cost are printed per scenario and per run.**
  Prices in `AnthropicAdapter.prices_per_mtok` are a snapshot; check current
  pricing before quoting a figure.
- **Tool argument schemas are derived from the handler signatures**, so the
  model is told what each tool takes. They are advisory rather than `strict` —
  an agent under attack passing the wrong arguments is a result worth
  observing, so a bad call comes back as an error tool result instead of
  crashing the trial.
- **Sampling parameters are omitted by default.** Current Claude models reject
  `temperature`/`top_p`/`top_k` with a 400; `--temperature` exists for
  adapters that accept it, and warns otherwise.
- **Full transcripts are saved.** In real mode each trial's conversation lands
  in `Outcome.details["transcript"]`, so `--save` output is auditable.
