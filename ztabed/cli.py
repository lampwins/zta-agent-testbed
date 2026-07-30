from __future__ import annotations

import argparse
from pathlib import Path

from ztabed.core.runner import ABRunner
from ztabed.scenarios import ALL_SCENARIOS

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def main() -> None:
    parser = argparse.ArgumentParser(prog="ztabed", description="Zero Trust agent security testbed: A/B attack scenarios.")
    sub = parser.add_subparsers(dest="command", required=True)

    list_cmd = sub.add_parser("list", help="List available scenarios")

    run_cmd = sub.add_parser("run", help="Run an A/B trial for one or all scenarios")
    run_cmd.add_argument("--scenario", default="all", choices=["all"] + list(ALL_SCENARIOS.keys()))
    run_cmd.add_argument("--trials", type=int, default=10, help="Trials per condition (baseline/hardened x attack/benign)")
    run_cmd.add_argument("--mode", default="mock", choices=["mock", "real"], help="mock = deterministic scripted agents, real = live Claude API calls")
    run_cmd.add_argument("--save", action="store_true", help="Save raw per-trial results to results/")

    args = parser.parse_args()

    if args.command == "list":
        for name, cls in ALL_SCENARIOS.items():
            print(f"{name:<22}{cls.description}")
        return

    if args.command == "run":
        names = list(ALL_SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]
        for name in names:
            runner = ABRunner(ALL_SCENARIOS[name], trials=args.trials, llm_mode=args.mode)
            runner.run_and_print(save_dir=RESULTS_DIR if args.save else None)


if __name__ == "__main__":
    main()
