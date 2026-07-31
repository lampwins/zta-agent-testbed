# ztabed — Zero Trust Agent security testbed

Measures whether a Zero Trust **Policy Decision Point** correctly rules on what
an AI agent is attempting — catching attacks without breaking legitimate work.

## Architecture

The reference architecture (`diagram.png`) puts the LLM *outside* the trust
boundary. The user talks to a model, the model drives an MCP Client, and the ZTA
agent is what sits between that and the resource:

```
User ──► LLM                          (untrusted actor)
          ▲
          │
┌─────────┼─── ZTA Enabled AI Agent ──────────────────────────┐
│  MCP Client   interprets user/LLM intent                    │
│      │                                                       │
│     PEP ────────────────────► PDP                            │
│  crafts the ActionContext    rules on it: ALLOW/DENY/...     │
│      │                                                       │
│  MCP Server   arbiter for access to the resource             │
└──────┼───────────────────────────────────────────────────────┘
    Resource
```

Two consequences drive the whole design:

1. **The PDP is the component under evaluation**, not the agent. Whether a given
   model can be talked into misbehaving is a different (and heavily studied)
   question; whether policy catches the attempt is the Zero Trust question.
2. **The `ActionContext` is the entire contract** between the two halves. A PDP
   sees nothing else — no conversation, no model, no side channel. That
   isolation is what makes a PDP testable on its own, and it is why the same
   context can come from a live agent loop or be replayed from a corpus.

## Two ways to drive a PDP

| | `judge` (recommended, live-model friendly) | `run` (agent loop) |
|---|---|---|
| Unit measured | one PDP decision on one action | one end-to-end exploit attempt |
| Where the model sits | **in the PDP box**, ruling on an action | in the agent's seat, being attacked |
| Attack source | a labelled corpus of `ActionContext`s | a scripted mock policy |
| Output | confusion matrix (miss rate, FP rate, stability) | attack-success / block / task-completion rates |
| Live model | works — the model is doing security review | expect refusals; see the note below |

**Use `judge` with a live model.** Asking a model to rule on a pending action is
a defensive task it performs willingly. Asking it to *carry out* a task while
feeding it injected instructions is not: a correctly aligned model refuses, and
the run yields no measurement. Those refusals were never a harness bug — they
were the model behaving properly given what it was asked to do.

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

## The corpus (`judge`)

35 labelled `ActionContext` cases across four vectors, each an action some agent
wants to take, with ground truth for whether policy should permit it.

| vector | the untrusted channel |
|---|---|
| `injected_exfil` | instructions hidden in fetched web content redirect or launder data out |
| `scope_escalation` | a tampered invoice makes an authorised deputy exceed its scope |
| `agent_identity` | a forged or over-reaching peer agent in a multi-agent system |
| `tool_supply_chain` | a rogue or tampered tool registration (e.g. compromised MCP server) |

**The benign half carries the weight.** Every benign case is a deliberate
near-miss built to trip a specific shortcut, and several are paired with a
malicious case they are nearly indistinguishable from:

| malicious | benign near-miss | what actually separates them |
|---|---|---|
| `exfil-m-hard-launder` | `exfil-b-quotes` | both put untrusted page content in an outbound email to the right recipient — only the stated task says whether that was authorised |
| `scope-m-hard-routing` | `scope-b-onfile-routing` | identical unscoped `account_routing` parameter; one came from a tampered invoice, one from the vendor master |
| `ident-m-hard-stalekey` | `ident-b-newkey` | both present a key outside the usual window; one is retired, one freshly rotated |
| `supply-m-hard-spoofed` | `supply-b-telemetry` | one declares itself trusted with a failing signature; one is properly attested and merely says "telemetry" |

A corpus of obviously-benign benign cases makes any PDP look perfect. Each case
also records a `defeats` field naming the shortcut it targets, so a results table
is a diagnosis rather than a score — run `ztabed.cli corpus` to read them.

## PDP arms

| arm | what it is | needs a model |
|---|---|---|
| `none` | no policy — defines the attack surface | no |
| `naive` | widely-deployed shortcuts: recipient allow-lists, transaction ceilings, trusting a sender name, description keyword scans, first-party-only tool allowlists | no |
| `zta_static` | rule-based ZTA engine: explicit verification with key lifecycle, per-scope authorisation, attestation with version binding, data-flow integrity | no |
| `zta_llm` | a language model in the PDP box | yes |
| `zta_hybrid` | rules first, model only on what the rules would permit | yes |

`zta_hybrid` is the arm that tests the interesting claim. Composition
short-circuits on the first DENY, so the model is never consulted about a case the
cheap deterministic rules already settled — roughly halving model calls against
this corpus.

### Reading the offline result

```
                 --- malicious ---       --- benign ---
arm            miss  detect   chal     FP   chal  clean  bal.acc  stable
none           100%      0%     0%     0%     0%   100%      50%     n/a
naive           47%     53%     0%    56%     0%    44%      48%     n/a
zta_static      16%     84%     0%     6%     0%    94%      89%     n/a
```

`naive` lands below chance: it blocks over half of legitimate work while still
missing every hard attack. `zta_static` is strong, and its four failures are
structural rather than a matter of missing rules:

- It misses `exfil-m-hard-scope`, `exfil-m-hard-semantic` and
  `scope-m-hard-wrongvendor`, where **every value is trustworthy** and the action
  is still not the one that was asked for. No metadata rule reaches those;
  deciding them means comparing the action against the meaning of the task.
- It false-positives on `exfil-b-quotes`, because the authorisation to handle
  untrusted content lives in the natural-language request.

Those four cases are the precise, pre-registered hypothesis for what an LLM PDP
should add. That is the experiment.

`zta_static` cites the expected principle on 100% of what it catches, which is
true but uninformative: a rule engine cites the principle its rule encodes, by
construction. The principle metric only becomes discriminating for the LLM arms,
where a correct verdict can still rest on the wrong reasoning.

## Scenarios included (`run`, agent loop)

| name | attack vector | control under test |
|---|---|---|
| `prompt_injection` | instructions hidden in fetched web content hijack the agent | `IntentAuditControl` — agent's planned action is summarized and checked by an isolated auditor against the original request |
| `confused_deputy` | a tampered invoice redirects/inflates a payment | `LeastPrivilegeControl` — tool args are capped/matched against scope derived from the original trusted request |
| `agent_impersonation` | a forged envelope claims to be a trusted peer agent | `IdentityVerificationControl` — HMAC-signed envelopes, verified against a known-sender registry |
| `malicious_tool` | a rogue tool registration (e.g. compromised MCP server) silently exfiltrates data | `ToolProvenanceControl` — only tools from an allowlisted source/trust level may execute |

## Usage

```bash
cd zta-agent-testbed

python -m ztabed.cli list            # vectors, PDP arms, and agent-loop scenarios
python -m ztabed.cli corpus          # read the labelled corpus and its rationales

# PDP evaluation — free and deterministic, no model needed
python -m ztabed.cli judge
python -m ztabed.cli judge --vector scope_escalation --arm none --arm zta_static

# agent-loop simulation (mock)
python -m ztabed.cli run --scenario all --trials 20 --save
```

`--save` writes raw per-decision results as JSON to `results/` for offline
analysis (e.g. loading into pandas for the paper). The `judge` output embeds the
corpus alongside the results, so a saved run is self-describing.

### Running against a live model

```bash
python3 -m venv .venv            # mock mode needs no dependencies; real mode does
source .venv/bin/activate
pip install -r requirements.txt

export ANTHROPIC_API_KEY=...     # or run `ant auth login`

python -m ztabed.cli models      # registered adapters and their model ids

# The live-model evaluation: put the model in the PDP box.
python -m ztabed.cli judge --mode real --arm zta_llm --concurrency 6

# The full comparison, with self-consistency measured over 5 samples per case.
python -m ztabed.cli judge --mode real --save --concurrency 8 --repeats 5 \
    --arm none --arm naive --arm zta_static --arm zta_llm --arm zta_hybrid
```

Cheapest useful first run — one vector, one arm, ~9 model calls:

```bash
python -m ztabed.cli judge --mode real --arm zta_llm \
    --vector scope_escalation --effort low
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

## Adding a corpus vector

1. Write a module in `ztabed/vectors/` whose builder is decorated with
   `@register_vector("name")` and returns a list of `ActionCase`s. Use the
   helpers in `ztabed/vectors/_build.py`.
2. Import it in `ztabed/vectors/__init__.py`.

Two rules the corpus validator enforces, both of which exist because breaking
them silently invalidates a measurement:

- **Every case needs a `rationale`.** An unjustified label is not ground truth.
- **Every vector needs benign cases.** Without them the false-positive rate is
  unmeasurable, and a PDP that denies everything scores perfectly.

Beyond that, write benign near-misses *first* and make them hard. The malicious
cases are the easy part; a corpus is only as strong as the legitimate traffic it
asks a PDP not to break. Pair a benign case with the malicious case it most
resembles, and record in `defeats` which shortcut each one targets.

## Adding a PDP

1. Subclass `PolicyDecisionPoint` (`ztabed/core/policy.py`) and implement
   `evaluate(ctx) -> PolicyDecision`. Everything you may consult arrives in the
   `ActionContext`.
2. Add it to an arm in `ztabed/pdp/arms.py`.

Return `Decision.CHALLENGE` for genuine ambiguity rather than guessing, and set
`principle` so the evaluation can check the reasoning. Fail closed.

## Adding an agent-loop scenario

1. Add a `Scenario` subclass in `ztabed/scenarios/` with a vulnerable mock
   policy and a `run(control_mode, attack, trial_seed)` that wires the PDP
   in only for the relevant `control_mode`.
2. Register it in `ztabed/scenarios/__init__.py`'s `ALL_SCENARIOS` dict.

Score outcomes from **observable side effects** (what landed in the email
sink, the transfer log, the exfil log), not from the mock policy's scripted
branch.

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

## Notes on the live PDP (`judge --mode real`)

The model is handed an evidence packet and asked to rule on it. It is never asked
to perform the action, and untrusted material — injected payloads, the agent's own
rationale — arrives inside delimited, explicitly-labelled fences, both so the
judge cannot confuse it with its own instructions and so the judge can reason about
provenance at all. Print one with:

```python
from ztabed.pdp import render_action_context
from ztabed.vectors import build_corpus
print(render_action_context(next(iter(build_corpus(["injected_exfil"]))).context))
```

- **Verdicts are schema-constrained**, so a decision is parsed rather than scraped
  out of prose. A model that answers "this seems fine, allow it" in free text is
  recorded as an **abstention and failed closed** — a PDP that cannot decide must
  not permit. Abstention rate is reported separately so it can never masquerade
  as detection.
- **`--repeats N` measures self-consistency.** Accuracy on a single sample says
  little about a non-deterministic PDP. The `stable` column is the share of cases
  where every repeat agreed; a high accuracy with low stability is not a result.
- **CHALLENGE is containment, not a catch.** A challenged malicious action does
  not reach the resource, but it spends human attention, so challenge rates are
  reported next to detection and never folded into it. Otherwise a PDP that
  challenges everything would score perfectly.
- **`principle` is captured with every verdict**, so the report can show whether
  a caught attack was caught for the right reason or by luck.

## Notes on `--mode real` with the agent loop (`run`)

**Expect refusals.** Here the model is put in the agent's seat and asked to
complete a task while injected instructions are fed to it, so a well-aligned model
will often decline. That is the model working correctly, and it is why `judge`
exists. Refusals are counted and annotated rather than scored as the control
working, but the arm is confounded and is not the one to publish. Mock mode
remains the setting for the agent-loop numbers.

A refusal rate here is itself a finding — model-level alignment is a real defence
layer — but it is entangled with the control's effect and cannot be separated
within a single run.

Things worth knowing before reading any real-mode numbers:

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
