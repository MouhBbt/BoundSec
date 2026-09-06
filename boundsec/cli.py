"""
BoundSec - command-line interface.

Sub-commands:

  fuzz          Run one fuzzing campaign against a target (gym / HTTP / live model).
  experiment    Run the research evaluation suite (exp1-4) and write results/.
  figures       Regenerate all figures from a results directory.
  benchmark     Quick strategy comparison table against the gym (no files).
  operators     List the mutation operators and their attack families.
  seeds         List the seed corpus.
  version       Print version.

The CLI is a thin wrapper: every real capability lives in the library so it can
be scripted or imported.  Against the gym everything runs fully offline; live
targets activate automatically when an API key is present.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(
    name="boundsec",
    help="🔍 [bold]BoundSec[/bold] — coverage-guided security fuzzing for LLM agents",
    rich_markup_mode="rich",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

_STRATEGY_HELP = "static_replay | random_mutation | guided_no_bandit | coverage_guided"


# ---------------------------------------------------------------------------
# fuzz
# ---------------------------------------------------------------------------


@app.command()
def fuzz(
    target: Annotated[str, typer.Option("--target", "-t",
        help="Target: 'gym:<profile>' (naive|basic|hardened|frontier), an HTTP URL, or 'live:<model>'")]
        = "gym:basic",
    strategy: Annotated[str, typer.Option("--strategy", "-s", help=_STRATEGY_HELP)]
        = "coverage_guided",
    budget: Annotated[int, typer.Option("--budget", "-b", help="Query budget")] = 400,
    seed: Annotated[int, typer.Option("--seed", help="RNG seed (reproducibility)")] = 0,
    detector: Annotated[str, typer.Option("--detector", "-d",
        help="heuristic | canary | ensemble | llm_judge")] = "heuristic",
    output: Annotated[Path | None, typer.Option("--output", "-o",
        help="Write JSON campaign record")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run one fuzzing campaign against a target agent."""
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    from boundsec.analysis.results import record_from_result
    from boundsec.core.engine import CampaignConfig, FuzzingEngine, build_strategy
    from boundsec.payloads.seeds import load_seeds

    tgt, tgt_name = _resolve_target(target, seed)
    det = _resolve_detector(detector)
    seeds = load_seeds()
    cfg = CampaignConfig(budget=budget, seed=seed, label=f"{strategy}/{tgt_name}")
    strat = build_strategy(strategy, seeds, cfg)
    engine = FuzzingEngine(tgt, det, strat, cfg)

    console.print(Panel(
        f"[bold cyan]BoundSec[/bold cyan] campaign\n"
        f"[dim]Target:[/dim] {tgt_name}   [dim]Strategy:[/dim] {strategy}\n"
        f"[dim]Detector:[/dim] {det.name}   [dim]Budget:[/dim] {budget}   [dim]Seed:[/dim] {seed}",
        title="🔍 Starting", border_style="cyan"))

    async def _go():
        with Progress(SpinnerColumn(), TextColumn("[cyan]Fuzzing"), BarColumn(bar_width=36),
                      MofNCompleteColumn(), TimeElapsedColumn(), console=console) as pg:
            task = pg.add_task("fuzz", total=budget)
            def cb(step, tot, cov, finds):
                pg.update(task, completed=step,
                          description=f"[cyan]cov={cov} finds={finds}")
            res = await engine.run(progress_cb=cb)
            pg.update(task, completed=budget)
        return res

    result = asyncio.run(_go())
    _print_campaign_summary(result, tgt_name, verbose)

    if output:
        rec = record_from_result(result, profile=tgt_name, target=tgt.name)
        rec.to_json(output)
        console.print(f"\n[bold cyan]📄 Record saved:[/bold cyan] {output}")

    raise typer.Exit(code=2 if result.n_findings else 0)


# ---------------------------------------------------------------------------
# experiment
# ---------------------------------------------------------------------------


@app.command()
def experiment(
    budget: Annotated[int, typer.Option("--budget", "-b")] = 600,
    seeds: Annotated[int, typer.Option("--seeds", "-n", help="Replicate seeds per cell")] = 15,
    out: Annotated[Path, typer.Option("--out", "-o")] = Path("results"),
    only: Annotated[str | None, typer.Option("--only", help="exp1|exp2|exp3|exp4")] = None,
    figures: Annotated[bool, typer.Option("--figures/--no-figures",
        help="Regenerate figures afterwards")] = True,
    figures_dir: Annotated[Path, typer.Option("--figures-dir")] = Path("figures"),
) -> None:
    """Run the research evaluation suite and (optionally) regenerate figures."""
    import matplotlib
    matplotlib.use("Agg")
    from boundsec.analysis.experiment import (
        ExperimentConfig,
        exp1_strategy,
        exp2_detectors,
        exp3_defenses,
        exp4_ablation,
        run_all,
    )
    from boundsec.analysis.figures import generate_all

    cfg = ExperimentConfig(budget=budget, n_seeds=seeds, out_dir=out, verbose=True)
    runners = {"exp1": exp1_strategy, "exp2": exp2_detectors,
               "exp3": exp3_defenses, "exp4": exp4_ablation}
    if only:
        asyncio.run(runners[only](cfg))
    else:
        asyncio.run(run_all(cfg))
    if figures:
        console.print("[dim]Regenerating figures…[/dim]")
        generate_all(out, figures_dir)
        console.print(f"[bold cyan]📊 Figures:[/bold cyan] {figures_dir}/")


# ---------------------------------------------------------------------------
# figures
# ---------------------------------------------------------------------------


@app.command()
def figures(
    results: Annotated[Path, typer.Argument(help="Results directory")] = Path("results"),
    out: Annotated[Path, typer.Option("--out", "-o")] = Path("figures"),
) -> None:
    """Regenerate all figures from an existing results directory."""
    import matplotlib
    matplotlib.use("Agg")
    from boundsec.analysis.figures import generate_all
    if not results.exists():
        console.print(f"[red]No results at {results}. Run `boundsec experiment` first.[/red]")
        raise typer.Exit(1)
    generate_all(results, out)
    n = len(list(out.glob("*.png")))
    console.print(f"[bold cyan]📊 {n} figures written to[/bold cyan] {out}/")


# ---------------------------------------------------------------------------
# benchmark (quick table, no files)
# ---------------------------------------------------------------------------


@app.command()
def benchmark(
    profile: Annotated[str, typer.Option("--profile", "-p")] = "hardened",
    budget: Annotated[int, typer.Option("--budget", "-b")] = 400,
    seeds: Annotated[int, typer.Option("--seeds", "-n")] = 5,
) -> None:
    """Quick strategy comparison against one gym profile (prints a table)."""
    import numpy as np

    from boundsec.analysis.metrics import compare_strategies
    from boundsec.core.engine import CampaignConfig, FuzzingEngine, build_strategy
    from boundsec.core.oracle import HeuristicDetector
    from boundsec.payloads.seeds import load_seeds
    from boundsec.targets.gym import GymAgent

    strategies = ["static_replay", "random_mutation", "guided_no_bandit", "coverage_guided"]
    results: dict[str, list[int]] = {s: [] for s in strategies}

    async def run(strat, sd):
        cfg = CampaignConfig(budget=budget, seed=sd)
        eng = FuzzingEngine(GymAgent(profile, seed=sd), HeuristicDetector(),
                            build_strategy(strat, load_seeds(), cfg), cfg)
        return (await eng.run()).n_findings

    with console.status(f"Running {len(strategies)}×{seeds} campaigns against gym:{profile}…"):
        for strat in strategies:
            for sd in range(seeds):
                results[strat].append(asyncio.run(run(strat, sd)))

    tbl = Table(title=f"Strategy comparison — gym:{profile} (budget={budget}, {seeds} seeds)",
                box=box.ROUNDED)
    tbl.add_column("Strategy"); tbl.add_column("Mean findings", justify="right")
    tbl.add_column("vs. static (Â₁₂)", justify="right"); tbl.add_column("p", justify="right")
    base = results["static_replay"]
    for strat in strategies:
        vals = results[strat]
        cmp = compare_strategies(vals, base, strat, "static_replay")
        a12 = "—" if strat == "static_replay" else f"{cmp.a12:.2f}"
        p = "—" if strat == "static_replay" else f"{cmp.p_value:.3f}"
        style = "bold cyan" if strat == "coverage_guided" else ""
        tbl.add_row(f"[{style}]{strat}[/{style}]" if style else strat,
                    f"{np.mean(vals):.1f}", a12, p)
    console.print(tbl)


# ---------------------------------------------------------------------------
# operators / seeds / version
# ---------------------------------------------------------------------------


@app.command()
def operators() -> None:
    """List the mutation operators grouped by attack family."""
    from boundsec.core.operators import all_operators
    tbl = Table(title="Mutation operators", box=box.ROUNDED, show_lines=False)
    tbl.add_column("Operator", style="cyan"); tbl.add_column("Attack family")
    tbl.add_column("Multi-turn", justify="center")
    for op in sorted(all_operators(), key=lambda o: o.family.value):
        tbl.add_row(op.name, op.family.value, "✓" if op.multi_turn else "")
    console.print(tbl)
    console.print(f"[dim]{len(all_operators())} operators[/dim]")


@app.command()
def seeds() -> None:
    """List the seed attack corpus."""
    from boundsec.payloads.seeds import load_seeds
    tbl = Table(title="Seed corpus", box=box.ROUNDED)
    tbl.add_column("ID", style="dim"); tbl.add_column("Objective")
    tbl.add_column("Technique"); tbl.add_column("Turns", justify="center")
    tbl.add_column("Description")
    for s in load_seeds():
        tbl.add_row(s.case_id, s.objective.value if s.objective else "—",
                    s.technique.value, str(s.n_turns), s.description)
    console.print(tbl)
    console.print(f"[dim]{len(load_seeds())} seeds[/dim]")


@app.command()
def version() -> None:
    """Print version."""
    from boundsec import __version__
    console.print(f"BoundSec {__version__}")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _resolve_target(spec: str, seed: int):
    from boundsec.targets.gym import GymAgent, profile_names
    if spec.startswith("gym:"):
        prof = spec.split(":", 1)[1] or "basic"
        if prof not in profile_names():
            console.print(f"[red]Unknown gym profile '{prof}'. Choices: {profile_names()}[/red]")
            raise typer.Exit(1)
        return GymAgent(prof, seed=seed), f"gym:{prof}"
    if spec.startswith("live:"):
        from boundsec.targets.live import LiveModelAgent, make_client_from_env
        client = make_client_from_env()
        if client is None:
            console.print("[red]live: target needs OPENAI_API_KEY or GROQ_API_KEY.[/red]")
            raise typer.Exit(1)
        model = spec.split(":", 1)[1] or client.default_model
        return LiveModelAgent(client, model=model), f"live:{model}"
    # else HTTP
    from boundsec.targets.live import HTTPAgentTarget
    return HTTPAgentTarget(spec), spec


def _resolve_detector(name: str):
    from boundsec.core.oracle import (
        CanaryDetector,
        EnsembleDetector,
        HeuristicDetector,
        LLMJudgeDetector,
    )
    if name == "heuristic":
        return HeuristicDetector()
    if name == "canary":
        return CanaryDetector()
    if name == "ensemble":
        return EnsembleDetector([HeuristicDetector(), CanaryDetector()])
    if name == "llm_judge":
        from boundsec.targets.live import make_client_from_env
        client = make_client_from_env()
        if client is None:
            console.print("[yellow]llm_judge needs an API key; falling back to heuristic.[/yellow]")
            return HeuristicDetector()
        return LLMJudgeDetector(client)
    console.print(f"[yellow]Unknown detector '{name}', using heuristic.[/yellow]")
    return HeuristicDetector()


def _print_campaign_summary(result, target_name: str, verbose: bool) -> None:
    from collections import Counter
    color = "red" if result.n_findings else "green"
    console.print()
    console.print(Panel(
        f"[bold {color}]{result.n_findings} unique vulnerabilities[/bold {color}]  "
        f"in {result.queries_used} queries\n"
        f"[dim]Coverage:[/dim] {result.final_coverage} slots   "
        f"[dim]Corpus:[/dim] {result.corpus_size}   "
        f"[dim]Time:[/dim] {result.wall_time_s:.1f}s",
        title=f"🔍 Report — {target_name}", border_style=color))

    if result.n_findings:
        by_class: Counter = Counter()
        by_sev: Counter = Counter()
        for obs in result.unique_findings.values():
            if obs.verdict.top_class:
                by_class[obs.verdict.top_class.value] += 1
            by_sev[obs.verdict.severity.value] += 1
        tbl = Table(box=box.SIMPLE, show_header=True)
        tbl.add_column("Vulnerability class"); tbl.add_column("Count", justify="right")
        tbl.add_column("Example evidence")
        for cls, n in by_class.most_common():
            ex = next((o.verdict.evidence[0] for o in result.unique_findings.values()
                       if o.verdict.top_class and o.verdict.top_class.value == cls
                       and o.verdict.evidence), "—")
            tbl.add_row(cls, str(n), ex[:60])
        console.print(tbl)
        sev_str = "  ".join(f"[bold]{k}[/bold]:{v}" for k, v in by_sev.items())
        console.print(f"[dim]By severity:[/dim] {sev_str}")

    if verbose and result.scheduler_stats:
        console.print("\n[dim]Top operators (by learned value):[/dim]")
        for row in result.scheduler_stats[:6]:
            console.print(f"  {row['operator']:20s} value={row['value']:.3f} "
                          f"pulls={row['pulls']} bugs={row['bugs']}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
