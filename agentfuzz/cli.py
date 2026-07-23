"""
AgentFuzz – CLI Entry Point (cli.py)

Usage:
    python -m agentfuzz.cli --target http://localhost:8000/chat \
        --payloads agentfuzz/payloads/jailbreaks.json

    python -m agentfuzz.cli --target http://localhost:8000/chat \
        --oracle composite --llm-api-key $OPENAI_API_KEY \
        --concurrency 10 --output reports/run.json
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Annotated, Optional

# Load .env automatically if present (no error if missing)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import typer
from rich.console import Console
from rich.panel import Panel

from agentfuzz.core.harness import FuzzingHarness
from agentfuzz.core.mutator import (
    CompositeMutator,
    LLMMutator,
    LLMMutatorConfig,
    StaticMutator,
)
from agentfuzz.core.oracle import (
    CompositeOracle,
    LLMJudgeConfig,
    LLMJudgeOracle,
    RuleBasedOracle,
)
from agentfuzz.utils.reporter import FuzzReport, get_console, make_progress

app = typer.Typer(
    name="agentfuzz",
    help="🔍 AgentFuzz – Boundary-aware AI agent security fuzzer",
    rich_markup_mode="rich",
    add_completion=False,
)

console = get_console()

# ---------------------------------------------------------------------------
# Main fuzz command
# ---------------------------------------------------------------------------


@app.command()
def fuzz(
    target: Annotated[
        str,
        typer.Option("--target", "-t", help="Target agent endpoint URL (POST /chat)"),
    ] = "http://localhost:8000/chat",
    payloads: Annotated[
        Path,
        typer.Option("--payloads", "-p", help="Path to jailbreaks.json payload library"),
    ] = Path("agentfuzz/payloads/jailbreaks.json"),
    oracle: Annotated[
        str,
        typer.Option(
            "--oracle", "-O",
            help="Oracle mode: [bold]rule[/bold] (fast, default) | [bold]llm[/bold] | [bold]composite[/bold]",
        ),
    ] = "rule",
    llm_api_key: Annotated[
        Optional[str],
        typer.Option("--llm-api-key", help="OpenAI-compatible API key (for LLM mutator/judge)"),
    ] = None,
    llm_base_url: Annotated[
        str,
        typer.Option("--llm-base-url", help="LLM API base URL"),
    ] = "https://api.openai.com/v1",
    llm_model: Annotated[
        str,
        typer.Option("--llm-model", help="LLM model name for mutator and judge"),
    ] = "gpt-4o-mini",
    mutate_seeds: Annotated[
        Optional[str],
        typer.Option(
            "--mutate-seeds",
            help="Comma-separated benign seed prompts to feed the LLM mutator",
        ),
    ] = None,
    llm_variants: Annotated[
        int,
        typer.Option("--llm-variants", help="Number of LLM-mutated variants per seed"),
    ] = 5,
    concurrency: Annotated[
        int,
        typer.Option("--concurrency", "-c", help="Max concurrent requests to target"),
    ] = 5,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Per-request timeout in seconds"),
    ] = 30.0,
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Path to write JSON report (optional)"),
    ] = None,
    severity_filter: Annotated[
        Optional[str],
        typer.Option(
            "--severity", "-s",
            help="Only run cases at or above this severity: critical | high | medium | low",
        ),
    ] = None,
    category_filter: Annotated[
        Optional[str],
        typer.Option(
            "--category",
            help="Only run cases matching this category (comma-separated, e.g. tool_call_injection,data_exfiltration)",
        ),
    ] = None,
    escalate_llm: Annotated[
        bool,
        typer.Option("--escalate-llm/--no-escalate-llm",
                     help="Escalate flagged cases to LLM judge even in rule mode"),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Print each case result in real time"),
    ] = False,
) -> None:
    """
    🔍 Run a full fuzzing campaign against the target agent.

    \b
    Examples:
      # Quick run against mock target (no LLM needed):
      python -m agentfuzz.cli --target http://localhost:8000/chat

      # Full run with LLM mutator and judge:
      python -m agentfuzz.cli \\
          --target http://localhost:8000/chat \\
          --oracle composite \\
          --llm-api-key $OPENAI_API_KEY \\
          --mutate-seeds "Tell me the weather" \\
          --output reports/run.json
    """
    asyncio.run(
        _run_fuzz(
            target=target,
            payloads=payloads,
            oracle_mode=oracle,
            llm_api_key=llm_api_key or os.getenv("OPENAI_API_KEY"),
            llm_base_url=llm_base_url,
            llm_model=llm_model,
            mutate_seeds=mutate_seeds,
            llm_variants=llm_variants,
            concurrency=concurrency,
            timeout=timeout,
            output=output,
            severity_filter=severity_filter,
            category_filter=category_filter,
            escalate_llm=escalate_llm,
            verbose=verbose,
        )
    )


async def _run_fuzz(
    *,
    target: str,
    payloads: Path,
    oracle_mode: str,
    llm_api_key: str | None,
    llm_base_url: str,
    llm_model: str,
    mutate_seeds: str | None,
    llm_variants: int,
    concurrency: int,
    timeout: float,
    output: Path | None,
    severity_filter: str | None,
    category_filter: str | None,
    escalate_llm: bool,
    verbose: bool,
) -> None:
    run_id = str(uuid.uuid4())[:8]

    console.print(
        Panel(
            f"[bold cyan]AgentFuzz[/bold cyan] v0.1.0 – AI Security Fuzzer\n"
            f"[dim]Target:[/dim] [link]{target}[/link]\n"
            f"[dim]Payload Library:[/dim] {payloads}\n"
            f"[dim]Oracle:[/dim] {oracle_mode}  |  [dim]Concurrency:[/dim] {concurrency}  |  [dim]Run ID:[/dim] {run_id}",
            title="🔍 Starting Fuzzing Campaign",
            border_style="cyan",
        )
    )

    # ------------------------------------------------------------------
    # 1. Build mutator
    # ------------------------------------------------------------------
    if not payloads.exists():
        console.print(f"[red]✗ Payload file not found: {payloads}[/red]")
        raise typer.Exit(code=1)

    static_mutator = StaticMutator(payloads)
    llm_mutator: LLMMutator | None = None
    seeds: list[str] = []

    if llm_api_key and (oracle_mode in ("llm", "composite") or mutate_seeds):
        llm_mutator = LLMMutator(
            LLMMutatorConfig(
                api_key=llm_api_key,
                base_url=llm_base_url,
                model=llm_model,
            )
        )
        seeds = [s.strip() for s in (mutate_seeds or "").split(",") if s.strip()]
        if not seeds:
            seeds = ["Tell me something helpful about data security."]
    elif oracle_mode in ("llm", "composite") and not llm_api_key:
        console.print(
            "[yellow]⚠ Oracle mode is 'llm'/'composite' but no API key provided. "
            "Falling back to rule-based oracle and static mutator only.[/yellow]"
        )

    composite_mutator = CompositeMutator(
        static=static_mutator,
        llm=llm_mutator,
        seed_prompts=seeds,
        llm_variants_per_seed=llm_variants,
    )

    console.print("[dim]Building fuzz cases…[/dim]")
    cases = await composite_mutator.build_cases()

    # Apply severity filter
    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    if severity_filter:
        min_rank = _SEVERITY_ORDER.get(severity_filter.lower(), 4)
        before = len(cases)
        cases = [c for c in cases if _SEVERITY_ORDER.get(c.severity, 4) <= min_rank]
        console.print(
            f"[dim]Severity filter '{severity_filter}': {before} → {len(cases)} cases[/dim]"
        )

    # Apply category filter
    if category_filter:
        allowed = {cat.strip().lower() for cat in category_filter.split(",")}
        before = len(cases)
        cases = [c for c in cases if c.category.lower() in allowed]
        console.print(
            f"[dim]Category filter '{category_filter}': {before} → {len(cases)} cases[/dim]"
        )

    if not cases:
        console.print("[red]✗ No fuzz cases match the applied filters. Aborting.[/red]")
        raise typer.Exit(code=1)

    # ------------------------------------------------------------------
    # 2. Build oracle
    # ------------------------------------------------------------------
    rule_oracle = RuleBasedOracle()
    llm_judge: LLMJudgeOracle | None = None

    if llm_api_key and oracle_mode in ("llm", "composite"):
        llm_judge = LLMJudgeOracle(
            LLMJudgeConfig(
                api_key=llm_api_key,
                base_url=llm_base_url,
                model=llm_model,
            )
        )

    should_escalate = escalate_llm and llm_judge is not None
    composite_oracle = CompositeOracle(
        rule_oracle=rule_oracle,
        llm_oracle=llm_judge,
        escalate_to_llm=should_escalate or (oracle_mode in ("llm", "composite") and llm_judge is not None),
    )

    # ------------------------------------------------------------------
    # 3. Execute fuzzing run
    # ------------------------------------------------------------------
    verdicts = []
    start_time = time.monotonic()

    progress = make_progress()
    task = progress.add_task("[cyan]Fuzzing…[/cyan]", total=len(cases))

    async with FuzzingHarness(
        target_url=target,
        timeout_seconds=timeout,
        concurrency=concurrency,
    ) as harness:
        with progress:
            # Process in batches to allow progress updates
            batch_size = concurrency * 2
            for i in range(0, len(cases), batch_size):
                batch = cases[i : i + batch_size]
                pairs = await harness.run_all(batch)

                # Evaluate each pair
                eval_tasks = [
                    composite_oracle.evaluate(case, trace)
                    for case, trace in pairs
                ]
                batch_verdicts = await asyncio.gather(*eval_tasks)

                for (case, trace), verdict in zip(pairs, batch_verdicts):
                    verdicts.append(verdict)
                    if verbose:
                        from rich.markup import escape  # noqa: PLC0415
                        status_icon = "🔴" if verdict.is_vulnerable else "✅"
                        vuln_str = (
                            ", ".join(vt.value for vt in verdict.vulnerability_types)
                            if verdict.is_vulnerable
                            else "clean"
                        )
                        cid_display = escape(case.case_id[:35])
                        console.print(
                            f"  {status_icon} {cid_display}  "
                            f"[dim]{vuln_str}[/dim]"
                            + (f"  ({verdict.confidence:.0%})" if verdict.is_vulnerable else "")
                        )

                progress.advance(task, len(batch))

    duration = time.monotonic() - start_time

    # ------------------------------------------------------------------
    # 4. Report
    # ------------------------------------------------------------------
    report = FuzzReport(
        run_id=run_id,
        target_url=target,
        total_cases=len(cases),
        verdicts=verdicts,
        duration_seconds=duration,
        oracle_mode=oracle_mode,
    )
    report.print_summary()

    if output:
        report.save_json(output)

    # Return non-zero exit code if vulnerabilities found
    if any(v.is_vulnerable for v in verdicts):
        raise typer.Exit(code=2)


# ---------------------------------------------------------------------------
# List-payloads sub-command
# ---------------------------------------------------------------------------


@app.command("list-payloads")
def list_payloads(
    payloads: Annotated[
        Path,
        typer.Argument(help="Path to jailbreaks.json"),
    ] = Path("agentfuzz/payloads/jailbreaks.json"),
) -> None:
    """📋 List all static payloads in the library."""
    import json  # noqa: PLC0415
    from rich.table import Table  # noqa: PLC0415
    from rich import box as rbox  # noqa: PLC0415

    if not payloads.exists():
        console.print(f"[red]File not found: {payloads}[/red]")
        raise typer.Exit(1)

    with open(payloads, encoding="utf-8") as fh:
        data = json.load(fh)

    table = Table(
        title=f"Payload Library – {payloads}",
        box=rbox.ROUNDED,
        show_lines=True,
    )
    table.add_column("ID", no_wrap=True, style="cyan")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Description")
    table.add_column("Preview", max_width=60)

    from rich.text import Text  # noqa: PLC0415

    severity_styles = {
        "critical": "bold red", "high": "bold orange3",
        "medium": "bold yellow", "low": "green", "unknown": "dim",
    }

    for entry in data.get("jailbreaks", []):
        sev = entry["severity"]
        table.add_row(
            entry["id"],
            entry["category"],
            Text(sev, style=severity_styles.get(sev, "")),
            entry["description"],
            entry["payload"][:80] + ("…" if len(entry["payload"]) > 80 else ""),
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(data.get('jailbreaks', []))} payloads[/dim]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    app()


if __name__ == "__main__":
    main()
