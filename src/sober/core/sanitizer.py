"""
Sanitizer engine - cures code by auto-removing leftover debug statements and AI residue.
"""

from pathlib import Path

from sober.detectors import Issue
from sober.detectors.ghost_code import DEBUG_LOG_JS, DEBUG_PRINT_PY, DEBUGGER_JS


def cure_file(file_path: Path) -> tuple[int, list[str]]:
    """Sanitize a single source file by stripping auto-fixable debug statements."""
    if not file_path.exists():
        return 0, []

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return 0, []

    ext = file_path.suffix.lower()
    lines = content.splitlines(keepends=True)
    new_lines = []
    removed_count = 0
    removed_snippets = []

    for line in lines:
        stripped = line.strip()
        should_remove = False

        if ext == ".py" and DEBUG_PRINT_PY.match(stripped) or ext in {".js", ".jsx", ".ts", ".tsx"} and (DEBUG_LOG_JS.match(stripped) or DEBUGGER_JS.match(stripped)):
            should_remove = True

        if should_remove:
            removed_count += 1
            removed_snippets.append(stripped)
        else:
            new_lines.append(line)

    if removed_count > 0:
        file_path.write_text("".join(new_lines), encoding="utf-8")

    return removed_count, removed_snippets


def apply_cure(issues: list[Issue], project_root: Path) -> dict[str, int]:
    """Cure all auto-fixable issues across the project."""
    cured_files = {}
    target_files = {project_root / i.file_path for i in issues if i.auto_fixable}

    for file_path in target_files:
        if file_path.is_file():
            count, _ = cure_file(file_path)
            if count > 0:
                rel = str(file_path.relative_to(project_root) if file_path.is_relative_to(project_root) else file_path)
                cured_files[rel] = count

    return cured_files
