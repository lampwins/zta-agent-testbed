from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ztabed.core.evaluate import PDPEvaluator, print_report
from ztabed.core.runner import ABRunner
from ztabed.models import (
    AdapterUnavailable,
    LiveModelSettings,
    ModelConfig,
    ModelSession,
    available_providers,
    get_adapter,
)
from ztabed.pdp import ALL_ARMS, ARM_DESCRIPTIONS, arm_needs_model, build_arm
from ztabed.scenarios import ALL_SCENARIOS
from ztabed.vectors import available_vectors, build_corpus

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def _add_model_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group(
        "live model options (--mode real)",
        "effort and thinking change how much the model deliberates, which measurably "
        "changes how it handles injected instructions -- treat them as variables to "
        "sweep, not just cost knobs.",
    )
    group.add_argument("--provider", default="anthropic", choices=available_providers(),
                       help="model adapter to use (default: anthropic)")
    group.add_argument("--model", default=None,
                       help="model id for the agent under test (default: the adapter's default)")
    group.add_argument("--auditor-model", default=None,
                       help="model id for the isolated auditor in ZTA runs (default: same as --model)")
    group.add_argument("--effort", default=None, choices=["low", "medium", "high", "xhigh", "max"],
                       help="reasoning effort (default: the provider's own default)")
    group.add_argument("--thinking", default=None, choices=["adaptive", "disabled"],
                       help="thinking mode (default: the provider's own default)")
    group.add_argument("--max-tokens", type=int, default=8192,
                       help="output token cap per call; covers thinking plus text (default: 8192)")
    group.add_argument("--temperature", type=float, default=None,
                       help="sampling temperature; current Claude models reject this and will 400")
    group.add_argument("--max-retries", type=int, default=4,
                       help="provider-level retries for rate limits and 5xx (default: 4)")
    group.add_argument("--timeout", type=float, default=None, help="per-request timeout in seconds")


def _build_model_session(args) -> ModelSession:
    settings = LiveModelSettings(
        provider=args.provider,
        agent_model=args.model,
        auditor_model=args.auditor_model,
        config=ModelConfig(
            max_tokens=args.max_tokens,
            effort=args.effort,
            thinking=args.thinking,
            temperature=args.temperature,
            max_retries=args.max_retries,
            timeout=args.timeout,
        ),
    )
    return ModelSession(settings)


def main() -> None:
    parser = argparse.ArgumentParser(prog="ztabed", description="Zero Trust agent security testbed: A/B attack scenarios.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List available scenarios, corpus vectors, and PDP arms")
    sub.add_parser("models", help="List registered model adapters and the models they know about")

    corpus_cmd = sub.add_parser("corpus", help="Inspect or export the labelled ActionContext corpus")
    corpus_cmd.add_argument("--vector", action="append", default=None,
                            choices=available_vectors(), help="restrict to a vector (repeatable)")
    corpus_cmd.add_argument("--json", action="store_true", help="emit the corpus as JSON")

    judge_cmd = sub.add_parser(
        "judge",
        help="Replay the labelled corpus through PDP arms (the live-model evaluation)",
    )
    judge_cmd.add_argument("--arm", action="append", default=None, choices=list(ALL_ARMS),
                           help="PDP arm to evaluate (repeatable; default: all offline arms)")
    judge_cmd.add_argument("--vector", action="append", default=None, choices=available_vectors(),
                           help="restrict the corpus to a vector (repeatable)")
    judge_cmd.add_argument("--repeats", type=int, default=1,
                           help="decisions per case; >1 measures a live PDP's self-consistency")
    judge_cmd.add_argument("--concurrency", type=int, default=1,
                           help="decisions to run in parallel (default: 1)")
    judge_cmd.add_argument("--save", action="store_true", help="Save raw per-decision results to results/")
    _add_model_args(judge_cmd)

    run_cmd = sub.add_parser("run", help="Run an A/B trial for one or all scenarios")
    run_cmd.add_argument("--scenario", default="all", choices=["all"] + list(ALL_SCENARIOS.keys()))
    run_cmd.add_argument("--trials", type=int, default=10, help="Trials per condition ({none,naive,zta} x {attack,benign})")
    run_cmd.add_argument("--mode", default="mock", choices=["mock", "real"],
                         help="mock = deterministic scripted agents, real = live model calls")
    run_cmd.add_argument("--concurrency", type=int, default=1,
                         help="trials to run in parallel; mainly useful for --mode real (default: 1)")
    run_cmd.add_argument("--save", action="store_true", help="Save raw per-trial results to results/")
    _add_model_args(run_cmd)

    args = parser.parse_args()

    if args.command == "list":
        print("corpus vectors (for `judge` -- the live-model evaluation)")
        for name in available_vectors():
            count = len(build_corpus([name]))
            print(f"  {name:<22}{count} labelled cases")
        print("\nPDP arms")
        for arm in ALL_ARMS:
            tag = " (needs --mode real)" if arm_needs_model(arm) else ""
            print(f"  {arm:<22}{ARM_DESCRIPTIONS[arm]}{tag}")
        print("\nagent-loop scenarios (for `run` -- best used with --mode mock)")
        for name, cls in ALL_SCENARIOS.items():
            print(f"  {name:<22}{cls.description}")
        return

    if args.command == "corpus":
        corpus = build_corpus(args.vector)
        problems = corpus.check()
        if args.json:
            print(json.dumps([c.summary() for c in corpus], indent=2))
        else:
            for case in corpus:
                flag = "MAL " if case.is_malicious else "ben "
                print(f"{flag}{case.case_id:<28}{case.difficulty:<8}{case.context.tool.name}")
                print(f"     {case.rationale}")
                if case.defeats:
                    print(f"     defeats: {case.defeats}")
            print(f"\n{len(corpus)} cases: {corpus.balance()}")
        if problems:
            print("\ncorpus problems:", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
            raise SystemExit(1)
        return

    if args.command == "judge":
        arms = args.arm or ["none", "naive", "zta_static"]
        needs_model = any(arm_needs_model(a) for a in arms)

        model_session = None
        if needs_model:
            if args.mode != "real":
                print(
                    f"error: arm(s) {[a for a in arms if arm_needs_model(a)]} need a live model; "
                    "pass --mode real",
                    file=sys.stderr,
                )
                raise SystemExit(2)
            try:
                model_session = _build_model_session(args)
                model_session.backend("pdp")
            except AdapterUnavailable as exc:
                print(f"error: {exc}", file=sys.stderr)
                raise SystemExit(2)

        corpus = build_corpus(args.vector)
        factory = (lambda: model_session.backend("pdp")) if model_session else None
        evaluator = PDPEvaluator(
            corpus=corpus,
            arms=arms,
            arm_factory=lambda arm: build_arm(arm, factory),
            repeats=args.repeats,
            concurrency=args.concurrency,
            model_session=model_session,
        )
        try:
            result = evaluator.run()
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(1)
        print_report(result, save_dir=RESULTS_DIR if args.save else None)

        stalled = [m.arm for m in result.arms if m.error_rate >= 1.0]
        if stalled:
            print(f"\nerror: no decisions completed for arm(s): {', '.join(stalled)}", file=sys.stderr)
            raise SystemExit(1)
        return

    if args.command == "models":
        for provider in available_providers():
            adapter = get_adapter(provider)
            print(f"{provider} (default: {adapter.default_model})")
            for model in adapter.known_models:
                price = adapter.prices_per_mtok.get(model)
                cost = f"  ${price[0]:g}/${price[1]:g} per Mtok in/out" if price else ""
                marker = " *" if model == adapter.default_model else "  "
                print(f" {marker} {model}{cost}")
        return

    if args.command == "run":
        model_session = None
        if args.mode == "real":
            try:
                model_session = _build_model_session(args)
                # Build the agent backend now so a misconfiguration fails before
                # the first (billable) call rather than mid-run.
                model_session.backend("assistant")
            except AdapterUnavailable as exc:
                print(f"error: {exc}", file=sys.stderr)
                raise SystemExit(2)

        names = list(ALL_SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]
        results = []
        for name in names:
            runner = ABRunner(
                ALL_SCENARIOS[name],
                trials=args.trials,
                llm_mode=args.mode,
                model_session=model_session,
                concurrency=args.concurrency,
            )
            results.append(runner.run_and_print(save_dir=RESULTS_DIR if args.save else None))

        if model_session is not None and not model_session.ledger.is_empty():
            print("\n── run total ──")
            for row in model_session.ledger.rows():
                print(f"  {row.summary()}")
            print(f"  estimated cost: ~${model_session.ledger.total_cost_usd():,.2f}")

        # A run where nothing was measured must not look like a clean pass to a
        # calling script -- the table would be all zeros either way.
        unmeasured = [
            f"{r.scenario_name}/{c.label}"
            for r in results for c in r.conditions if c.unmeasured_rate >= 1.0
        ]
        if unmeasured:
            print(
                f"\nerror: {len(unmeasured)} condition(s) produced no measurement at all "
                f"(every trial refused or errored): {', '.join(unmeasured[:6])}"
                + (" ..." if len(unmeasured) > 6 else ""),
                file=sys.stderr,
            )
            raise SystemExit(1)


if __name__ == "__main__":
    main()
