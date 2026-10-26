"""
Console UI presentation components powered by Rich.
"""

import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        # Fallback gracefully if standard streams do not support reconfigure
        sys.stdout.flush()

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sober.core.scorer import SoberAuditReport
from sober.detectors import Severity

console = Console()

LOGO = r"""[bold cyan]   ____ ____  ____  _____ ____  [/]
[bold cyan]  / ___/ __ \| __ )| ____|  _ \ [/]
[bold cyan]  \___ \ | | |  _ \|  _| | |_) |[/]
[bold cyan]   ___) | |_| | |_) | |___|  _ < [/]
[bold cyan]  |____/\____/|____/|_____|_| \_\[/]
  [dim]🍸 The Vibe Coding Hangover Cure • Audit & Sanitize AI Code[/]"""


def print_banner():
    """Render the official SOBER header."""
    console.print()
    console.print(Panel(LOGO, border_style="cyan", padding=(0, 2)))
    console.print()


def render_report(report: SoberAuditReport):
    """Render comprehensive audit results in Rich tables and score cards."""
    if not report.issues:
        console.print(
            Panel(
                f"[bold green]✨ PERFECT SOBRIETY (Score: 100% • A+)[/]\n\n"
                f"[dim]Scanned {report.files_scanned} files in {report.duration_seconds:.2f}s.[/]\n"
                f"No AI hallucinations, ghost code, secrets, or anti-patterns detected.",
                title="[bold green]STATUS: 🧊 CRYSTAL SOBER[/]",
                border_style="green",
            )
        )
        return

    # Issues Table
    table = Table(
        title="[bold red]⚠️ AI Hangover Debris & Vulnerabilities Detected[/]",
        border_style="dim",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Sev", justify="center", width=10)
    table.add_column("Location", style="cyan", width=26)
    table.add_column("Category & Description", style="white")
    table.add_column("Suggested Fix", style="dim green", width=34)

    severity_styles = {
        Severity.CRITICAL: "[bold white on red] CRITICAL [/]",
        Severity.HIGH: "[bold red]HIGH[/]",
        Severity.MEDIUM: "[yellow]MEDIUM[/]",
        Severity.LOW: "[dim cyan]LOW[/]",
    }

    for issue in report.issues:
        sev_tag = severity_styles.get(issue.severity, str(issue.severity))
        loc = f"{issue.file_path}:{issue.line_number}"
        desc = f"[bold]{issue.title}[/]\n[dim]{issue.description}[/]"
        if issue.code_snippet:
            desc += f"\n[dim red]> {issue.code_snippet[:65]}[/]"
        table.add_row(sev_tag, loc, desc, issue.fix_suggestion)

    console.print(table)
    console.print()

    # Sober Score Dashboard
    score_panel_content = Text()
    score_panel_content.append("Sober Score: ", style="bold")
    score_panel_content.append(f"{report.score}% ", style=f"bold {report.color}")
    score_panel_content.append(f"[{report.grade}]\n", style=f"bold {report.color}")
    score_panel_content.append(f"State: {report.status_label}\n\n", style=f"bold {report.color}")
    score_panel_content.append(f"• Critical Issues: {report.critical_count}    ", style="bold red" if report.critical_count else "dim")
    score_panel_content.append(f"• High: {report.high_count}    ", style="yellow" if report.high_count else "dim")
    score_panel_content.append(f"• Medium: {report.medium_count}    ", style="dim")
    score_panel_content.append(f"• Low (Debris): {report.low_count}\n", style="dim")
    score_panel_content.append(f"• Auto-Fixable with --cure: {report.auto_fixable_count}\n\n", style="bold green" if report.auto_fixable_count else "dim")
    score_panel_content.append(f"Scanned {report.files_scanned} files in {report.duration_seconds:.2f}s.", style="dim")

    console.print(
        Panel(
            score_panel_content,
            title="[bold cyan]📊 SOBRIETY HEALTH TELEMETRY[/]",
            border_style=report.color,
            padding=(1, 2),
        )
    )


def render_cure_results(cured_files: dict):
    """Print results of the auto-cure sanitizer."""
    if not cured_files:
        console.print("[dim]No auto-fixable debug debris found.[/]")
        return

    table = Table(title="[bold green]💊 Auto-Cure Sanitization Report[/]", border_style="green")
    table.add_column("File Sanitized", style="cyan")
    table.add_column("Lines Removed", justify="right", style="green")

    total_removed = 0
    for f, count in cured_files.items():
        table.add_row(f, str(count))
        total_removed += count

    console.print()
    console.print(table)
    console.print(f"\n[bold green]✔ Successfully sanitized {total_removed} leftover debug statement(s).[/]\n")
