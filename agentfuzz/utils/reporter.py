"""
AgentFuzz – Reporter (reporter.py)

Outputs a structured JSON report and a rich formatted terminal summary.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich import box

if TYPE_CHECKING:
    from agentfuzz.core.harness import FuzzCase, AgentTrace
    from agentfuzz.core.oracle import Verdict

# Singleton console so all modules share the same output stream
_console: Console | None = None


def get_console() -> Console:
    global _console
    if _console is None:
        _console = Console(stderr=False, highlight=True)
    return _console


# ---------------------------------------------------------------------------
# Severity colour map
# ---------------------------------------------------------------------------

_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high":     "bold orange3",
    "medium":   "bold yellow",
    "low":      "bold green",
    "unknown":  "dim",
}

_VULN_EMOJI: dict[str, str] = {
    "system_prompt_leak":     "🔓",
    "unauthorized_tool_call": "⚙️ ",
    "dangerous_command_exec": "💣",
    "path_traversal":         "📂",
    "jailbreak_success":      "🚨",
    "data_exfiltration":      "📤",
    "schema_validation_fail": "📋",
    "token_exhaustion":       "⏱️ ",
    "role_confusion":         "🎭",
    "indirect_injection":     "💉",
    "behavioral_anomaly":     "⚠️ ",
}


# ---------------------------------------------------------------------------
# Progress bar factory
# ---------------------------------------------------------------------------


def make_progress() -> Progress:
    """Return a rich Progress bar suitable for a fuzzing run."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=get_console(),
        transient=False,
    )


# ---------------------------------------------------------------------------
# Report Models
# ---------------------------------------------------------------------------


class FuzzReport:
    """
    Aggregates verdicts from a complete fuzzing run and renders:
      - A rich terminal summary (tables, panels, color)
      - A machine-readable JSON report
    """

    def __init__(
        self,
        run_id: str,
        target_url: str,
        total_cases: int,
        verdicts: "list[Verdict]",
        duration_seconds: float,
        oracle_mode: str = "rule_based",
    ) -> None:
        self.run_id = run_id
        self.target_url = target_url
        self.total_cases = total_cases
        self.verdicts = verdicts
        self.duration_seconds = duration_seconds
        self.oracle_mode = oracle_mode
        self.timestamp = datetime.now(tz=timezone.utc).isoformat()

        self.vulnerable: list[Verdict] = [v for v in verdicts if v.is_vulnerable]
        self.clean: list[Verdict] = [v for v in verdicts if not v.is_vulnerable]

    # ------------------------------------------------------------------
    # Terminal output
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        console = get_console()
        vuln_count = len(self.vulnerable)
        total = self.total_cases

        # Header banner
        console.print()
        title_style = "bold red" if vuln_count else "bold green"
        console.print(
            Panel(
                f"[{title_style}]AgentFuzz Security Report[/{title_style}]\n"
                f"[dim]Run ID:[/dim] {self.run_id}\n"
                f"[dim]Target:[/dim] {self.target_url}\n"
                f"[dim]Timestamp:[/dim] {self.timestamp}\n"
                f"[dim]Duration:[/dim] {self.duration_seconds:.2f}s  |  "
                f"[dim]Oracle:[/dim] {self.oracle_mode}",
                title="🔍 AgentFuzz",
                border_style="bold blue",
            )
        )

        # Stats row
        stats_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        stats_table.add_column(style="bold")
        stats_table.add_column()

        stats_table.add_row("Total Cases", str(total))
        stats_table.add_row(
            "[bold red]Vulnerabilities Found[/bold red]",
            f"[bold red]{vuln_count}[/bold red]" if vuln_count else "[green]0[/green]",
        )
        stats_table.add_row("[green]Clean[/green]", str(len(self.clean)))
        stats_table.add_row(
            "Vulnerability Rate",
            f"{(vuln_count / total * 100):.1f}%" if total else "N/A",
        )
        console.print(stats_table)

        if not self.vulnerable:
            console.print(
                Panel(
                    "[bold green]✅  No vulnerabilities detected![/bold green]\n"
                    "The target agent passed all fuzz tests.",
                    border_style="green",
                )
            )
            return

        # Vulnerability summary table
        vuln_table = Table(
            title=f"[bold red]🚨 {vuln_count} Vulnerabilities Detected[/bold red]",
            box=box.ROUNDED,
            show_lines=True,
            border_style="red",
        )
        vuln_table.add_column("ID", style="dim", no_wrap=True, max_width=30)
        vuln_table.add_column("Category", max_width=22)
        vuln_table.add_column("Severity", max_width=10)
        vuln_table.add_column("Vulnerability Types", max_width=40)
        vuln_table.add_column("Confidence", max_width=10)
        vuln_table.add_column("Evidence (first)", max_width=50)

        # Sort by severity then confidence
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        for verdict in sorted(
            self.vulnerable,
            key=lambda v: (severity_order.get(v.severity, 5), -v.confidence),
        ):
            sev_style = _SEVERITY_STYLES.get(verdict.severity, "")
            vuln_labels = "\n".join(
                f"{_VULN_EMOJI.get(vt.value, '?')} {vt.value}"
                for vt in verdict.vulnerability_types
            )
            first_evidence = verdict.evidence[0] if verdict.evidence else "—"
            vuln_table.add_row(
                Text(verdict.case_id, style="dim"),
                verdict.category,
                Text(verdict.severity, style=sev_style),
                vuln_labels or "—",
                f"{verdict.confidence:.0%}",
                Text(first_evidence[:80], overflow="ellipsis"),
            )

        console.print(vuln_table)

        # Category breakdown
        category_counts: dict[str, int] = {}
        for v in self.vulnerable:
            category_counts[v.category] = category_counts.get(v.category, 0) + 1

        cat_table = Table(title="Vulnerability Breakdown by Category", box=box.SIMPLE)
        cat_table.add_column("Category")
        cat_table.add_column("Count", justify="right")
        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            cat_table.add_row(cat, str(count))
        console.print(cat_table)

    # ------------------------------------------------------------------
    # JSON output
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": {
                "run_id": self.run_id,
                "timestamp": self.timestamp,
                "target_url": self.target_url,
                "oracle_mode": self.oracle_mode,
                "duration_seconds": round(self.duration_seconds, 3),
                "total_cases": self.total_cases,
                "vulnerable_count": len(self.vulnerable),
                "clean_count": len(self.clean),
                "vulnerability_rate_pct": (
                    round(len(self.vulnerable) / self.total_cases * 100, 2)
                    if self.total_cases
                    else 0.0
                ),
            },
            "vulnerabilities": [
                {
                    "case_id": v.case_id,
                    "payload_id": v.payload_id,
                    "category": v.category,
                    "severity": v.severity,
                    "vulnerability_types": [vt.value for vt in v.vulnerability_types],
                    "confidence": round(v.confidence, 4),
                    "evidence": v.evidence,
                    "oracle_source": v.oracle_source,
                    "trace_summary": v.raw_trace_summary,
                }
                for v in sorted(
                    self.vulnerable,
                    key=lambda v: (
                        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(v.severity, 4),
                        -v.confidence,
                    ),
                )
            ],
            "clean_cases": [v.case_id for v in self.clean],
        }

    def save_json(self, output_path: Path) -> None:
        """Write the report as pretty-printed JSON to *output_path*."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False)
        get_console().print(
            f"\n[bold cyan]📄 Report saved:[/bold cyan] {output_path}"
        )
