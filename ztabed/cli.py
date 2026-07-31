from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ztabed.core.artifact import action_context_schema, write_artifact
from ztabed.core.evaluate import PDPEvaluator, print_report
from ztabed.core.payloads import get_payload_set, load_payload_file
from ztabed.core.runner import ABRunner
from ztabed.models import (
    AdapterUnavailable,
    LiveModelSettings,
    ModelConfig,
    ModelSession,
    available_providers,
    get_adapter,
)
from ztabed.pdp import (
    ALL_ARMS,
    ARM_DESCRIPTIONS,
    PDP_SYSTEM_PROMPT,
    PROMPT_VARIANTS,
    STEERING_CLAUSES,
    VERDICT_SCHEMA,
    arm_needs_model,
    arm_rules,
    available_clauses,
    available_rules,
    build_arm,
    build_pdp_prompt,
    prompt_digest,
    render_action_context,
    resolve_prompt,
)
from ztabed.scenarios import ALL_SCENARIOS
from ztabed.vectors import available_vectors, build_corpus

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def _add_model_args(parser: argparse.ArgumentParser) -> None:
    """Shared live-model flags.

    `--mode` lives here rather than on each subcommand so the two cannot drift
    apart. It also has to be declared explicitly wherever `--model` exists:
    argparse resolves unique prefixes, so an undeclared `--mode real` is silently
    absorbed as `--model real` and a run goes out against a model of that name.
    """
    group = parser.add_argument_group(
        "live model options (--mode real)",
        "effort and thinking change how much the model deliberates, which measurably "
        "changes how it handles injected instructions -- treat them as variables to "
        "sweep, not just cost knobs.",
    )
    group.add_argument("--mode", default="mock", choices=["mock", "real"],
                       help="mock = no model calls; real = use a live model. Required by "
                            "`judge` arms that need a model, and selects the backend for `run`.")
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
    # Prefix abbreviation is disabled throughout. `--mode` is a unique prefix of
    # `--model`, so with abbreviation on argparse silently reads `--mode real` as
    # `--model real`, and a metered run goes out against a model that does not
    # exist -- recording the wrong configuration in the saved results. A testbed
    # whose job is measurement should never quietly reinterpret its own flags.
    # Subparsers do not inherit this from the top-level parser, so it is passed
    # to each one via `subcommand()`.
    parser = argparse.ArgumentParser(
        prog="ztabed",
        description="Zero Trust agent security testbed: PDP evaluation and agent-loop A/B trials.",
        allow_abbrev=False,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def subcommand(name: str, **kwargs) -> argparse.ArgumentParser:
        return sub.add_parser(name, allow_abbrev=False, **kwargs)

    subcommand("list", help="List available scenarios, corpus vectors, and PDP arms")
    subcommand("models", help="List registered model adapters and the models they know about")

    corpus_cmd = subcommand("corpus", help="Inspect or export the labelled ActionContext corpus")
    corpus_cmd.add_argument("--vector", action="append", default=None,
                            choices=available_vectors(), help="restrict to a vector (repeatable)")
    corpus_cmd.add_argument("--json", action="store_true", help="emit the corpus as JSON")

    judge_cmd = subcommand(
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
    judge_cmd.add_argument("--audit", action="store_true",
                           help="evaluate every PDP instead of stopping at the first denial, giving "
                                "per-rule attribution. Free for deterministic arms; multiplies calls "
                                "for model-backed ones.")
    judge_cmd.add_argument("--add-rule", action="append", default=[], choices=available_rules(),
                           help="add a rule to every rule-based arm (ablation; repeatable)")
    judge_cmd.add_argument("--drop-rule", action="append", default=[], choices=available_rules(),
                           help="remove a rule from every rule-based arm (ablation; repeatable)")
    judge_cmd.add_argument("--prompt-variant", default="full", choices=sorted(PROMPT_VARIANTS),
                           help="judge-prompt preset for the live arms (default: full, the "
                                "published prompt)")
    judge_cmd.add_argument("--drop-clause", action="append", default=[], choices=available_clauses(),
                           help="remove a steering clause from the judge prompt on top of the "
                                "chosen variant (repeatable)")
    judge_cmd.add_argument("--save", action="store_true", help="Save raw per-decision results to results/")
    _add_model_args(judge_cmd)

    ablate_cmd = subcommand(
        "ablate",
        help="Sweep one arm's rules, reporting what each rule buys and costs",
    )
    ablate_cmd.add_argument("--arm", default="zta_static", choices=list(ALL_ARMS),
                            help="arm to ablate (default: zta_static)")
    ablate_cmd.add_argument("--add-rule", action="append", default=[], choices=available_rules(),
                            help="also sweep adding this rule (repeatable)")
    ablate_cmd.add_argument("--vector", action="append", default=None, choices=available_vectors())
    ablate_cmd.add_argument("--save", action="store_true")

    export_cmd = subcommand("export", help="Write the corpus artifact (JSONL + manifest) for release")
    export_cmd.add_argument("--out", default="artifact", help="output directory (default: artifact/)")

    subcommand("schema", help="Emit the ActionContext schema, judge prompt, and verdict schema")

    prompts_cmd = subcommand(
        "prompts", help="Show the judge prompt's ablatable clauses and its variants")
    prompts_cmd.add_argument("--variant", default=None, choices=sorted(PROMPT_VARIANTS),
                             help="print the full text of one variant")
    prompts_cmd.add_argument("--drop-clause", action="append", default=[],
                             choices=available_clauses())

    run_cmd = subcommand("run", help="Run an A/B trial for one or all scenarios")
    run_cmd.add_argument("--scenario", default="all", choices=["all"] + list(ALL_SCENARIOS.keys()))
    run_cmd.add_argument("--trials", type=int, default=10, help="Trials per condition ({none,naive,zta} x {attack,benign})")
    run_cmd.add_argument("--concurrency", type=int, default=1,
                         help="trials to run in parallel; mainly useful for --mode real (default: 1)")
    run_cmd.add_argument("--payload-set", default=None,
                         help="named injection payload set (default: the built-in texts)")
    run_cmd.add_argument("--payloads", default=None, metavar="FILE",
                         help="load payload sets from a JSON file, so a published attack "
                              "construction can be run as a positive control")
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

    if args.command == "prompts":
        if args.variant or args.drop_clause:
            prompt, label, dropped = resolve_prompt(args.variant or "full", args.drop_clause)
            print(f"# variant: {label}")
            print(f"# digest:  {prompt_digest(prompt)}")
            print(f"# dropped: {', '.join(dropped) or 'none'}\n")
            print(prompt)
            return
        print("Steering clauses in the judge prompt")
        print("Each was added to stop the model reducing to the matching deterministic rule,")
        print("which makes each one a candidate explanation for the model arm's advantage.\n")
        for c in STEERING_CLAUSES:
            print(f"  {c.key}  (principle: {c.principle})")
            print(f"    text:      {c.text().strip()}")
            print(f"    rationale: {c.rationale}\n")
        print("Variants")
        for name in sorted(PROMPT_VARIANTS):
            prompt = build_pdp_prompt(PROMPT_VARIANTS[name])
            dropped = ", ".join(PROMPT_VARIANTS[name]) or "none"
            marker = "  <- published prompt" if name == "full" else ""
            print(f"  {name:<18} {prompt_digest(prompt)}  {len(prompt):>5} chars  "
                  f"dropped: {dropped}{marker}")
        return

    if args.command == "ablate":
        corpus = build_corpus(args.vector)
        base = arm_rules(args.arm)
        # Each variant is the arm with exactly one rule removed, plus the arm
        # with each candidate rule added. Comparing a variant against the
        # baseline isolates what that one rule contributes.
        variants = [("baseline", (), ())]
        variants += [(f"-{r}", (), (r,)) for r in base]
        variants += [(f"+{r}", (r,), ()) for r in args.add_rule]

        rows = []
        for label, add, drop in variants:
            res = PDPEvaluator(
                corpus, [args.arm],
                arm_factory=lambda a, _a=add, _d=drop: build_arm(a, None, add_rules=_a, drop_rules=_d),
                audit=True,
            ).run()
            rows.append((label, res.arms[0]))

        print(f"\n=== ablation of {args.arm} over {len(corpus)} cases ===")
        print("Each row is the arm with one rule removed (-) or added (+), against the baseline.")
        print("A rule earns its place only if its catches outweigh the legitimate work it refuses.\n")
        head = f"{'variant':<26}{'miss':>18}{'FP':>18}{'bal.acc':>9}{'Δmiss':>8}{'ΔFP':>7}"
        print(head)
        print("-" * len(head))
        base_metrics = rows[0][1]
        for label, m in rows:
            d_miss = m.miss.value - base_metrics.miss.value
            d_fp = m.false_positive.value - base_metrics.false_positive.value
            delta = "" if label == "baseline" else f"{d_miss:>+8.0%}{d_fp:>+7.0%}"
            print(f"{label:<26}{m.miss.render():>18}{m.false_positive.render():>18}"
                  f"{m.balanced_accuracy:>9.0%}{delta}")

        print("\nper-rule attribution on the baseline arm")
        print(f"  {'rule':<24}{'catches':>9}{'benignDENY':>12}  unique catches")
        for a in base_metrics.rule_attribution:
            print(f"  {a.rule:<24}{a.denied_malicious:>9}{a.denied_benign:>12}"
                  f"  {', '.join(a.unique_catches) or '-'}")
        return

    if args.command == "export":
        corpus = build_corpus()
        problems = corpus.check()
        if problems:
            print("refusing to export a corpus with problems:", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            raise SystemExit(1)
        out = Path(args.out)
        paths = write_artifact(corpus, out)
        for p in paths:
            print(f"wrote {p}")
        print(f"\ncorpus digest: {corpus.digest()}")
        return

    if args.command == "schema":
        print(json.dumps({
            "action_context_schema": action_context_schema(),
            "verdict_schema": VERDICT_SCHEMA,
            "pdp_system_prompt": PDP_SYSTEM_PROMPT,
            "pdp_prompt_digest": prompt_digest(PDP_SYSTEM_PROMPT),
            "pdp_prompt_variants": {
                name: {
                    "dropped_clauses": list(PROMPT_VARIANTS[name]),
                    "digest": prompt_digest(build_pdp_prompt(PROMPT_VARIANTS[name])),
                    "prompt": build_pdp_prompt(PROMPT_VARIANTS[name]),
                }
                for name in sorted(PROMPT_VARIANTS)
            },
            "steering_clauses": [
                {"key": c.key, "principle": c.principle, "text": c.text(),
                 "rationale": c.rationale}
                for c in STEERING_CLAUSES
            ],
            "worked_example": {
                "case_id": "exfil-m-hard-launder",
                "rendered_evidence_packet": render_action_context(
                    next(c for c in build_corpus() if c.case_id == "exfil-m-hard-launder").context
                ),
            },
        }, indent=2))
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
        add, drop = tuple(args.add_rule), tuple(args.drop_rule)
        try:
            judge_prompt, prompt_label, clauses_dropped = resolve_prompt(
                args.prompt_variant, args.drop_clause
            )
        except KeyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(2)
        if clauses_dropped and not needs_model:
            print("note: --prompt-variant/--drop-clause only affect the live arms "
                  f"({', '.join(a for a in ALL_ARMS if arm_needs_model(a))}); none selected.",
                  file=sys.stderr)
        if (add or drop) and any(arm_needs_model(a) for a in arms) and args.audit:
            print("note: --audit with a live arm consults the model on every case, "
                  "including ones the rules already settled.", file=sys.stderr)
        evaluator = PDPEvaluator(
            corpus=corpus,
            arms=arms,
            arm_factory=lambda arm: build_arm(
                arm, factory, add_rules=add, drop_rules=drop, system_prompt=judge_prompt
            ),
            repeats=args.repeats,
            concurrency=args.concurrency,
            model_session=model_session,
            audit=args.audit,
            prompt_variant=prompt_label,
            prompt_digest=prompt_digest(judge_prompt),
            prompt_clauses_dropped=clauses_dropped,
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

        if args.payloads:
            loaded = load_payload_file(Path(args.payloads))
            print(f"loaded payload sets: {', '.join(loaded)}")
        try:
            payloads = get_payload_set(args.payload_set)
        except KeyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            raise SystemExit(2)
        if payloads.name == "builtin" and args.mode == "real":
            print("note: using the built-in injection texts, which were written for this "
                  "testbed. A 0% attack success rate against them is not evidence of model "
                  "resistance without a published construction as a positive control "
                  "(--payloads).", file=sys.stderr)

        names = list(ALL_SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]
        results = []
        for name in names:
            runner = ABRunner(
                ALL_SCENARIOS[name],
                trials=args.trials,
                llm_mode=args.mode,
                model_session=model_session,
                concurrency=args.concurrency,
                payloads=payloads,
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
