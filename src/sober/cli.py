"""
CLI Entrypoint for SOBER - The Vibe Coding Hangover Cure.
"""

import json
import sys
import time
from pathlib import Path
from typing import Optional

import typer

from sober import __version__
from sober.core.sanitizer import apply_cure
from sober.core.scanner import get_all_code_files, get_git_modified_files
from sober.core.scorer import SoberAuditReport
from sober.detectors.duplicates import audit_duplicates
from sober.detectors.ghost_code import audit_ghost_code
from sober.detectors.hallucinations import audit_hallucinations
from sober.detectors.security import audit_security
from sober.ui.console import console, print_banner, render_cure_results, render_report

app = typer.Typer(
    help="🍸 The Vibe Coding Hangover Cure. Audit, sanitize, and proofread AI-generated code before pushing to production.",
    add_completion=False,
)


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]sober[/] version [bold green]{__version__}[/]")
        raise typer.Exit()


@app.callback()
def common(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", help="Show version and exit.", callback=version_callback, is_eager=True
    ),
):
    pass


@app.command(name="scan")
def scan(
    path: Path = typer.Argument(
        Path("."),
        help="Target repository or folder path to audit (defaults to current directory).",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    all_files: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="Audit all codebase files instead of only uncommitted / modified git changes.",
    ),
    cure: bool = typer.Option(
        False,
        "--cure",
        "-c",
        help="Automatically sanitize and strip leftover debug statements & AI debris.",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        "-s",
        help="Fail with exit code 1 if the Sober Score is below 95% (ideal for pre-commit / CI).",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output raw JSON results for CI/CD integrations.",
    ),
):
    """Scan code for AI hallucinations, ghost code, security leaks, and slop."""
    start_time = time.time()

    if not json_output:
        print_banner()

    # 1. Discover files
    files = []
    if not all_files:
        files = get_git_modified_files(path)
        if not files and not json_output:
            console.print("[dim]No uncommitted git changes detected. Auditing all repository files...[/]\n")
            files = get_all_code_files(path)
    else:
        files = get_all_code_files(path)

    if not files:
        if json_output:
            print(json.dumps({"error": "No supported source files found to audit."}))
        else:
            console.print("[bold yellow]No supported source files (.py, .ts, .tsx, .js, .jsx) found to audit.[/]")
        raise typer.Exit(0)

    # 2. Run Detectors
    all_issues = []

    # Per-file audits
    for f in files:
        all_issues.extend(audit_hallucinations(f, path))
        all_issues.extend(audit_ghost_code(f, path))
        all_issues.extend(audit_security(f, path))

    # Cross-file audits
    all_issues.extend(audit_duplicates(files, path))

    duration = time.time() - start_time
    report = SoberAuditReport(all_issues, files_scanned=len(files), duration_seconds=duration)

    # 3. Output results
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        render_report(report)

    # 4. Optional auto-cure
    if cure:
        cured = apply_cure(report.issues, path)
        if not json_output:
            render_cure_results(cured)

    # 5. Strict mode exit
    if strict and (report.score < 95 or report.critical_count > 0):
        if not json_output:
            console.print(f"\n[bold red]❌ STRICT CHECK FAILED: Sober Score is {report.score}% (<95%).[/]\n")
        raise typer.Exit(1)


def main():
    app()


if __name__ == "__main__":
    main()
