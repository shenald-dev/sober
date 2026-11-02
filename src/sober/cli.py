"""
CLI Entrypoint for SOBER - The Vibe Coding Hangover Cure.
"""

import json
import time
from pathlib import Path
from typing import Optional

import typer

from sober import __version__
from sober.core.config import load_config
from sober.core.git_helper import (
    get_git_diff_range_files,
    get_git_hook_status,
    get_git_hooks_dir,
    install_git_hook,
    uninstall_git_hook,
)
from sober.core.manifest import ManifestInspector
from sober.core.sanitizer import apply_cure
from sober.core.scanner import FileToAudit, get_all_code_files, get_git_modified_files
from sober.core.scorer import SoberAuditReport
from sober.detectors.chatter import audit_chatter
from sober.detectors.duplicates import audit_duplicates
from sober.detectors.ghost_code import audit_ghost_code
from sober.detectors.hallucinations import audit_hallucinations
from sober.detectors.security import audit_security
from sober.ui.console import (
    console,
    print_banner,
    render_cure_results,
    render_hook_status,
    render_report,
)

app = typer.Typer(
    help="🍸 The Vibe Coding Hangover Cure. Audit, sanitize, and proofread AI-generated code before pushing to production.",
    add_completion=False,
    no_args_is_help=False,
)

hook_app = typer.Typer(help="Manage Git pre-commit hooks for automated sobriety checks.", add_completion=False)
app.add_typer(hook_app, name="hook")


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]sober[/] version [bold green]{__version__}[/]")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    _version: Optional[bool] = typer.Option(
        None, "--version", "-v", help="Show version and exit.", callback=version_callback, is_eager=True
    ),
):
    if ctx.invoked_subcommand is None:
        scan(Path("."))


def _execute_audit(
    files: list[FileToAudit],
    path: Path,
    json_output: bool = False,
    sarif_output: bool = False,
    markdown_output: bool = False,
    cure: bool = False,
    strict: bool = False,
    min_score_override: Optional[float] = None,
):
    """Core audit runner for scan and diff commands."""
    start_time = time.time()
    config = load_config(path)
    manifest = ManifestInspector(path)

    # Filter out files ignored by config
    filtered_files = []
    for f in files:
        rel = str(f.path.relative_to(path) if f.path.is_relative_to(path) else f.path)
        if not config.is_path_ignored(rel):
            filtered_files.append(f)
    files = filtered_files

    if not files:
        if json_output:
            print(json.dumps({"error": "No supported source files found to audit."}))
        elif sarif_output:
            empty_report = SoberAuditReport([], files_scanned=0, duration_seconds=0.0)
            print(json.dumps(empty_report.to_sarif(), indent=2))
        elif markdown_output:
            empty_report = SoberAuditReport([], files_scanned=0, duration_seconds=0.0)
            print(empty_report.to_markdown())
        else:
            console.print("[bold yellow]No supported source files (.py, .ts, .tsx, .js, .jsx) found to audit.[/]")
        return

    # Run detectors
    all_issues = []
    for f in files:
        if config.is_detector_enabled("hallucinations"):
            all_issues.extend(audit_hallucinations(f, path, manifest_inspector=manifest, config=config))
        if config.is_detector_enabled("ghost_code"):
            all_issues.extend(audit_ghost_code(f, path))
        if config.is_detector_enabled("security"):
            all_issues.extend(audit_security(f, path, custom_secret_patterns=config.custom_secret_patterns))
        if config.is_detector_enabled("chatter"):
            all_issues.extend(audit_chatter(f, path))

    if config.is_detector_enabled("duplicates"):
        all_issues.extend(audit_duplicates(files, path))

    duration = time.time() - start_time
    report = SoberAuditReport(all_issues, files_scanned=len(files), duration_seconds=duration)

    # Render outputs
    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
    elif sarif_output:
        print(json.dumps(report.to_sarif(), indent=2))
    elif markdown_output:
        print(report.to_markdown())
    else:
        render_report(report)

    # Optional auto-cure
    if cure:
        cured = apply_cure(report.issues, path)
        if not (json_output or sarif_output or markdown_output):
            render_cure_results(cured)

    # Strict mode validation
    effective_min_score = min_score_override if min_score_override is not None else config.min_score
    should_fail = False

    if strict:
        if report.score < effective_min_score:
            should_fail = True
        if config.fail_on_critical and report.critical_count > 0:
            should_fail = True

    if should_fail:
        if not (json_output or sarif_output or markdown_output):
            console.print(
                f"\n[bold red]❌ STRICT CHECK FAILED: Sober Score is {report.score}% (<{effective_min_score}%) or critical issues detected.[/]\n"
            )
        raise typer.Exit(1)


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
        help="Fail with exit code 1 if the Sober Score is below threshold or has critical issues.",
    ),
    min_score: Optional[float] = typer.Option(
        None,
        "--min-score",
        help="Override minimum score threshold for strict mode (default: 95.0).",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output raw JSON results for CI/CD integrations.",
    ),
    sarif_output: bool = typer.Option(
        False,
        "--sarif",
        help="Output SARIF 2.1.0 format for GitHub Code Scanning Alerts.",
    ),
    markdown_output: bool = typer.Option(
        False,
        "--markdown",
        "-m",
        help="Output GitHub Flavored Markdown summary suitable for PR comments.",
    ),
):
    """Scan code for AI hallucinations, ghost code, security leaks, and slop."""
    if not (json_output or sarif_output or markdown_output):
        print_banner()

    files = []
    if not all_files:
        files = get_git_modified_files(path)
        if not files and not (json_output or sarif_output or markdown_output):
            console.print("[dim]No uncommitted git changes detected. Auditing all repository files...[/]\n")
            files = get_all_code_files(path)
    else:
        files = get_all_code_files(path)

    _execute_audit(
        files=files,
        path=path,
        json_output=json_output,
        sarif_output=sarif_output,
        markdown_output=markdown_output,
        cure=cure,
        strict=strict,
        min_score_override=min_score,
    )


@app.command(name="diff")
def diff_command(
    revision: str = typer.Argument(
        ...,
        help="Git revision or commit range to audit (e.g. 'HEAD~1', 'main..HEAD', 'origin/main').",
    ),
    path: Path = typer.Option(
        Path("."),
        "--path",
        "-p",
        help="Target repository root directory.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    cure: bool = typer.Option(False, "--cure", "-c", help="Auto-sanitize detected debug statements."),
    strict: bool = typer.Option(False, "--strict", "-s", help="Fail if sobriety threshold not met."),
    min_score: Optional[float] = typer.Option(None, "--min-score", help="Override minimum score threshold."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw JSON."),
    sarif_output: bool = typer.Option(False, "--sarif", help="Output SARIF 2.1.0."),
    markdown_output: bool = typer.Option(False, "--markdown", "-m", help="Output Markdown report."),
):
    """Audit code changes introduced across a specific git commit range or branch."""
    if not (json_output or sarif_output or markdown_output):
        print_banner()
        console.print(f"[bold cyan]Auditing changes in git range:[/] [yellow]{revision}[/]\n")

    files = get_git_diff_range_files(path, revision)
    _execute_audit(
        files=files,
        path=path,
        json_output=json_output,
        sarif_output=sarif_output,
        markdown_output=markdown_output,
        cure=cure,
        strict=strict,
        min_score_override=min_score,
    )


@app.command(name="cure")
def cure_command(
    path: Path = typer.Argument(
        Path("."),
        help="Target folder to sanitize debug debris and AI chatter.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    all_files: bool = typer.Option(False, "--all", "-a", help="Cure all files instead of only uncommitted changes."),
):
    """Standalone sanitization tool: auto-strip leftover debug statements, debuggers, and AI chatter."""
    print_banner()
    files = get_all_code_files(path) if all_files else get_git_modified_files(path)
    if not files and not all_files:
        files = get_all_code_files(path)

    all_issues = []
    for f in files:
        all_issues.extend(audit_ghost_code(f, path))
        all_issues.extend(audit_chatter(f, path))

    cured = apply_cure(all_issues, path)
    render_cure_results(cured)


@hook_app.command(name="install")
def hook_install(
    path: Path = typer.Argument(Path("."), help="Target Git repository root path."),
):
    """Install a native Git pre-commit hook that runs sober scan before every commit."""
    success, msg = install_git_hook(path)
    if success:
        console.print(f"[bold green]✔ Successfully installed sober pre-commit hook at {msg}[/]\n")
    else:
        console.print(f"[bold red]❌ {msg}[/]\n")
        raise typer.Exit(1)


@hook_app.command(name="uninstall")
def hook_uninstall(
    path: Path = typer.Argument(Path("."), help="Target Git repository root path."),
):
    """Remove the sober Git pre-commit hook."""
    success, msg = uninstall_git_hook(path)
    if success:
        console.print(f"[bold green]✔ {msg}[/]\n")
    else:
        console.print(f"[bold yellow]{msg}[/]\n")


@hook_app.command(name="status")
def hook_status(
    path: Path = typer.Argument(Path("."), help="Target Git repository root path."),
):
    """Check the status of the Git pre-commit hook."""
    installed = get_git_hook_status(path)
    hooks_dir = get_git_hooks_dir(path)
    hook_path = str(hooks_dir / "pre-commit") if hooks_dir else ""
    render_hook_status(installed, hook_path)


@app.command(name="init")
def init_command(
    path: Path = typer.Argument(Path("."), help="Target directory to create sober.toml."),
):
    """Initialize a starter sober.toml configuration file."""
    target_file = path / "sober.toml"
    if target_file.exists():
        console.print(f"[bold yellow]Configuration file {target_file} already exists.[/]")
        raise typer.Exit(0)

    starter_config = """# SOBER Configuration File
# Documentation: https://github.com/shenald-dev/sober

[sober]
min_score = 95.0
fail_on_critical = true
max_workers = 10

# Paths to ignore during audits
ignore_paths = [
    "tests/*",
    "docs/*",
    "migrations/*",
]

# Allowed internal or proprietary packages that should never trigger hallucination alerts
allowed_packages = [
    "@my-org/*",
    # "internal_company_sdk",
]

# Disable specific detectors if needed
# disabled_detectors = ["duplicates"]

# Custom proprietary secret regex patterns
# [[sober.custom_secret_patterns]]
# name = "Company Internal API Token"
# pattern = "comp_[A-Za-z0-9]{32}"
"""
    target_file.write_text(starter_config, encoding="utf-8")
    console.print(f"[bold green]✔ Initialized starter configuration at {target_file}[/]")


def main():
    app()


if __name__ == "__main__":
    main()
