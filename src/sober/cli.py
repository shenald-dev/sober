"""
CLI Entrypoint for SOBER - The Vibe Coding Hangover Cure.
"""

import json
from pathlib import Path

import typer

from sober import __version__
from sober.core.ci import init_github_actions_workflow
from sober.core.config import load_config
from sober.core.engine import AuditEngine
from sober.core.git_helper import (
    get_git_diff_range_files,
    get_git_hook_status,
    get_git_hooks_dir,
    get_git_staged_files,
    get_staged_contents,
    install_git_hook,
    uninstall_git_hook,
)
from sober.core.remediation import generate_agent_remediation_prompt
from sober.core.rules import all_rules
from sober.core.sanitizer import apply_cure
from sober.core.scanner import FileToAudit, get_all_code_files, get_git_modified_files
from sober.core.scorer import SoberAuditReport
from sober.core.watcher import LiveSoberWatcher
from sober.detectors import Severity
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

ci_app = typer.Typer(help="Manage CI/CD workflows and automated GitHub Actions gates.", add_completion=False)
app.add_typer(ci_app, name="ci")

_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]sober[/] version [bold green]{__version__}[/]")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def _main_callback(
    ctx: typer.Context,
    _version: bool | None = typer.Option(
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
    min_score_override: float | None = None,
    offline: bool = False,
    use_cache: bool = True,
    contents: dict | None = None,
    fail_on: str | None = None,
) -> SoberAuditReport:
    """Core audit runner for scan, diff, and explain commands (engine-backed)."""
    quiet = json_output or sarif_output or markdown_output
    config = load_config(path)

    if not files:
        empty_report = SoberAuditReport([], files_scanned=0, duration_seconds=0.0)
        if json_output:
            print(json.dumps(empty_report.to_dict()))
        elif sarif_output:
            print(json.dumps(empty_report.to_sarif(), indent=2))
        elif markdown_output:
            print(empty_report.to_markdown())
        else:
            console.print("[bold yellow]No supported source files (.py, .ts, .tsx, .js, .jsx) found to audit.[/]")
        return empty_report

    engine = AuditEngine(path, config=config, offline=offline, use_cache=use_cache)
    report = engine.audit(files, contents=contents)

    if json_output:
        print(json.dumps(report.to_dict(), indent=2))
    elif sarif_output:
        print(json.dumps(report.to_sarif(), indent=2))
    elif markdown_output:
        print(report.to_markdown())
    else:
        render_report(report)

    if cure:
        cured = apply_cure(report.issues, path)
        if not quiet:
            render_cure_results(cured)

    effective_min_score = min_score_override if min_score_override is not None else config.min_score
    effective_fail_on = fail_on or config.fail_on_severity
    should_fail = False
    if strict:
        if report.score < effective_min_score:
            should_fail = True
        if config.fail_on_critical and report.critical_count > 0:
            should_fail = True
        if effective_fail_on:
            threshold = _SEVERITY_RANK.get(Severity(effective_fail_on.upper()))
            if threshold is not None and any(_SEVERITY_RANK[i.severity] <= threshold for i in report.issues):
                should_fail = True

    if should_fail:
        if not quiet:
            console.print(
                f"\n[bold red]❌ STRICT CHECK FAILED: Sober Score is {report.score}% (<{effective_min_score}%) or critical issues detected.[/]\n"
            )
        raise typer.Exit(1)

    return report


@app.command(name="scan")
def scan(
    path: Path = typer.Argument(Path("."), help="Target repository or folder path to audit.",
                                exists=True, file_okay=False, dir_okay=True, resolve_path=True),
    all_files: bool = typer.Option(False, "--all", "-a", help="Audit all codebase files instead of only uncommitted git changes."),
    staged: bool = typer.Option(False, "--staged", help="Audit exactly the staged (index) content that will be committed."),
    cure: bool = typer.Option(False, "--cure", "-c", help="Automatically sanitize leftover debug statements, fences & AI debris."),
    strict: bool = typer.Option(False, "--strict", "-s", help="Fail with exit code 1 if the Sober Score is below threshold or has critical issues."),
    min_score: float | None = typer.Option(None, "--min-score", help="Override minimum score threshold for strict mode (default: 95.0)."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Fail in strict mode on any issue at or above this severity (CRITICAL, HIGH, MEDIUM, LOW)."),
    offline: bool = typer.Option(False, "--offline", help="Disable external network queries (PyPI/npm) for air-gapped audits."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable the incremental audit-result cache for this run."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw JSON results for CI/CD integrations."),
    sarif_output: bool = typer.Option(False, "--sarif", help="Output SARIF 2.1.0 format for GitHub Code Scanning Alerts."),
    markdown_output: bool = typer.Option(False, "--markdown", "-m", help="Output GitHub Flavored Markdown summary for PR comments."),
):
    """Scan code for AI hallucinations, slopsquatting, ghost code, security leaks, and hangover slop."""
    quiet = json_output or sarif_output or markdown_output
    if not quiet:
        print_banner()

    contents = None
    if staged:
        files = get_git_staged_files(path)
        contents = get_staged_contents(path, files)
        if not files and not quiet:
            console.print("[dim]No staged changes detected.[/]\n")
    elif all_files:
        files = get_all_code_files(path)
    else:
        files = get_git_modified_files(path)
        if not files and not quiet:
            console.print("[dim]No uncommitted git changes detected. Auditing all repository files...[/]\n")
            files = get_all_code_files(path)

    _execute_audit(files, path, json_output, sarif_output, markdown_output, cure, strict,
                   min_score, offline, use_cache=not no_cache, contents=contents, fail_on=fail_on)


@app.command(name="diff")
def _diff_command(
    revision: str = typer.Argument(..., help="Git revision or commit range to audit (e.g. 'HEAD~1', 'main..HEAD')."),
    path: Path = typer.Option(Path("."), "--path", "-p", help="Target repository root directory.",
                              exists=True, file_okay=False, dir_okay=True, resolve_path=True),
    cure: bool = typer.Option(False, "--cure", "-c", help="Auto-sanitize detected debug statements."),
    strict: bool = typer.Option(False, "--strict", "-s", help="Fail if sobriety threshold not met."),
    min_score: float | None = typer.Option(None, "--min-score", help="Override minimum score threshold."),
    fail_on: str | None = typer.Option(None, "--fail-on", help="Fail on any issue at or above this severity."),
    offline: bool = typer.Option(False, "--offline", help="Perform offline manifest audit without external network calls."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable the incremental audit-result cache."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output raw JSON."),
    sarif_output: bool = typer.Option(False, "--sarif", help="Output SARIF 2.1.0."),
    markdown_output: bool = typer.Option(False, "--markdown", "-m", help="Output Markdown report."),
):
    """Audit code changes introduced across a specific git commit range or branch."""
    if not (json_output or sarif_output or markdown_output):
        print_banner()
        console.print(f"[bold cyan]Auditing changes in git range:[/] [yellow]{revision}[/]\n")
    files = get_git_diff_range_files(path, revision)
    _execute_audit(files, path, json_output, sarif_output, markdown_output, cure, strict,
                   min_score, offline, use_cache=not no_cache, fail_on=fail_on)


@app.command(name="watch")
def _watch_command(
    path: Path = typer.Argument(Path("."), help="Target repository to monitor in real-time.",
                                exists=True, file_okay=False, dir_okay=True, resolve_path=True),
    interval: float = typer.Option(0.5, "--interval", "-i", help="Polling interval in seconds."),
    cure: bool = typer.Option(False, "--cure", "-c", help="Auto-cure detected debug statements and chatter on save."),
):
    """Live continuous watcher daemon for real-time AI vibe-coding feedback."""
    print_banner()
    console.print(f"[bold cyan]👀 SOBER Live Watcher active on {path.resolve()}[/] [dim](Ctrl+C to exit)[/]\n")

    def _on_change():
        console.clear()
        print_banner()
        console.print("[bold yellow]⚡ Change detected! Re-auditing sobriety...[/]\n")
        files = get_git_modified_files(path) or get_all_code_files(path)
        _execute_audit(files, path, cure=cure)

    watcher = LiveSoberWatcher(path, poll_interval=interval)
    try:
        watcher.watch(_on_change)
    except KeyboardInterrupt:
        console.print("\n[bold cyan]SOBER Live Watcher stopped.[/]")


@app.command(name="explain")
def _explain_command(
    path: Path = typer.Argument(Path("."), help="Target repository or folder path to audit.",
                                exists=True, file_okay=False, dir_okay=True, resolve_path=True),
    all_files: bool = typer.Option(False, "--all", "-a", help="Audit all files instead of only uncommitted changes."),
    offline: bool = typer.Option(False, "--offline", help="Air-gapped audit without registry queries."),
):
    """Generate high-density prompt context for autonomous coding agents to self-heal."""
    files = get_all_code_files(path) if all_files else (get_git_modified_files(path) or get_all_code_files(path))
    engine = AuditEngine(path, offline=offline)
    report = engine.audit(files)
    prompt = generate_agent_remediation_prompt(
        issues=report.issues, score=report.score, grade=report.grade,
        status_label=report.status_label, files_scanned=report.files_scanned)
    print(prompt)


@app.command(name="cure")
def _cure_command(
    path: Path = typer.Argument(Path("."), help="Target folder to sanitize debug debris and AI chatter.",
                                exists=True, file_okay=False, dir_okay=True, resolve_path=True),
    all_files: bool = typer.Option(False, "--all", "-a", help="Cure all files instead of only uncommitted changes."),
):
    """Standalone sanitization tool: auto-strip leftover debug statements, debuggers, and AI chatter."""
    print_banner()
    files = get_all_code_files(path) if all_files else (get_git_modified_files(path) or get_all_code_files(path))
    engine = AuditEngine(path, offline=True, use_cache=False)
    report = engine.audit(files)
    cured = apply_cure(report.issues, path)
    render_cure_results(cured)


@app.command(name="rules")
def _rules_command(
    json_output: bool = typer.Option(False, "--json", "-j", help="Output the rule catalog as JSON."),
):
    """List the SOBER detection rule catalog with stable IDs and severities."""
    rules = all_rules()
    if json_output:
        print(json.dumps({"rules": [r.to_dict() for r in rules]}, indent=2))
        return
    from rich.table import Table
    table = Table(title="[bold cyan]SOBER Rule Catalog[/]", border_style="dim", header_style="bold cyan")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Title", style="white")
    for rule in rules:
        table.add_row(rule.id, rule.severity.value, rule.title)
    console.print(table)


@app.command(name="mcp")
def _mcp_command(
    path: Path = typer.Option(Path("."), "--path", "-p", help="Project root to confine MCP tool access to.",
                              exists=True, file_okay=False, dir_okay=True, resolve_path=True),
):
    """Run the native MCP stdio server so AI agents can call sober tools directly."""
    from sober.mcp.server import run
    run(path)


@hook_app.command(name="install")
def _hook_install(path: Path = typer.Argument(Path("."), help="Target Git repository root path.")):
    """Install a native Git pre-commit hook that runs sober scan before every commit."""
    success, msg = install_git_hook(path)
    if success:
        console.print(f"[bold green]✔ Successfully installed sober pre-commit hook at {msg}[/]\n")
    else:
        console.print(f"[bold red]❌ {msg}[/]\n")
        raise typer.Exit(1)


@hook_app.command(name="uninstall")
def _hook_uninstall(path: Path = typer.Argument(Path("."), help="Target Git repository root path.")):
    """Remove the sober Git pre-commit hook."""
    success, msg = uninstall_git_hook(path)
    if success:
        console.print(f"[bold green]✔ {msg}[/]\n")
    else:
        console.print(f"[bold yellow]{msg}[/]\n")


@hook_app.command(name="status")
def _hook_status(path: Path = typer.Argument(Path("."), help="Target Git repository root path.")):
    """Check the status of the Git pre-commit hook."""
    installed = get_git_hook_status(path)
    hooks_dir = get_git_hooks_dir(path)
    hook_path = str(hooks_dir / "pre-commit") if hooks_dir else ""
    render_hook_status(installed, hook_path)


@ci_app.command(name="init")
def _ci_init(path: Path = typer.Argument(Path("."), help="Target repository root path.")):
    """Initialize a GitHub Actions workflow for automated PR sobriety checks."""
    wf_path = init_github_actions_workflow(path)
    console.print(f"[bold green]✔ Generated GitHub Actions workflow at {wf_path}[/]\n")


@app.command(name="init")
def _init_command(path: Path = typer.Argument(Path("."), help="Target directory to create sober.toml.")):
    """Initialize a starter sober.toml configuration file."""
    target_file = path / "sober.toml"
    if target_file.exists():
        console.print(f"[bold yellow]Configuration file {target_file} already exists.[/]")
        raise typer.Exit(0)
    starter_config = """# SOBER Configuration File (v3.0)
# Documentation: https://github.com/shenald-dev/sober

[sober]
min_score = 95.0
fail_on_critical = true
max_workers = 10
offline_mode = false
cache_enabled = true
# fail_on_severity = "HIGH"

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
