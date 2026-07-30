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
- **ABRunner** (`ztabed/core/runner.py`): runs a scenario across the full
  2x2 grid — {baseline, hardened} x {attack, benign} — and reports, per
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
pip install -r requirements.txt   # only needed for --mode real

python -m ztabed.cli list
python -m ztabed.cli run --scenario prompt_injection --trials 20
python -m ztabed.cli run --scenario all --trials 20 --save

# against a real Claude model instead of scripted mock agents
export ANTHROPIC_API_KEY=...
python -m ztabed.cli run --scenario prompt_injection --mode real --trials 5
```

`--save` writes raw per-trial outcomes as JSON to `results/` for offline
analysis (e.g. loading into pandas for the paper).

## Adding your own attack vector or control

1. Add a `Control` subclass in `ztabed/controls/` implementing `evaluate(ctx) -> PolicyDecision`.
2. Add a `Scenario` subclass in `ztabed/scenarios/` with a vulnerable mock
   policy and a `run(hardened, attack)` that wires the control in only
   when `hardened=True`.
3. Register it in `ztabed/scenarios/__init__.py`'s `ALL_SCENARIOS` dict.

## Notes on `--mode real`

Real mode uses live Claude API calls with deliberately naive system
prompts (the point is to test whether the *control*, not a hand-tuned
prompt, catches the attack). Tool argument schemas are intentionally
loose (`additionalProperties: true`) since exact tool-input schemas are
not the variable under study. Mock mode is recommended for reproducible,
free, deterministic measurement; real mode for spot-checking realism.
