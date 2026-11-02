"""
Git intelligence helper - range diff auditing and pre-commit hook management.
"""

import os
import stat
import subprocess
from pathlib import Path

from sober.core.scanner import SUPPORTED_EXTENSIONS, FileToAudit, is_git_repo

HOOK_SCRIPT = """#!/usr/bin/env sh
# Installed by sober - The Vibe Coding Hangover Cure
# https://github.com/shenald-dev/sober

echo "🍸 Running sober pre-commit sobriety check..."
sober scan --strict
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ sober detected unaddressed AI hangover issues or low sobriety score."
    echo "Run 'sober scan' to view details, or 'sober scan --cure' to auto-fix debug statements."
    exit 1
fi
exit 0
"""


def get_git_diff_range_files(root: Path, revision_range: str) -> list[FileToAudit]:
    """Retrieve modified files and changed line numbers for a specific git revision range (e.g. main..HEAD)."""
    if not is_git_repo(root):
        return []

    files_map: dict[Path, FileToAudit] = {}

    try:
        # 1. Get changed files in revision range
        diff_names = subprocess.run(
            ["git", "diff", "--name-only", revision_range],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if diff_names.returncode == 0:
            for line in diff_names.stdout.splitlines():
                rel_path = line.strip()
                if not rel_path:
                    continue
                file_path = root / rel_path
                if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                    files_map[file_path] = FileToAudit(file_path, is_git_diff=True)

        # 2. Get specific line numbers
        diff_res = subprocess.run(
            ["git", "diff", revision_range, "--unified=0"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if diff_res.returncode == 0:
            current_file: Path | None = None
            for line in diff_res.stdout.splitlines():
                if line.startswith("+++ b/"):
                    rel = line[6:]
                    current_file = root / rel
                elif line.startswith("@@ ") and current_file in files_map:
                    try:
                        hunk_header = line.split("@@")[1].strip()
                        plus_part = hunk_header.split()[1]  # +12,5
                        start_line = int(plus_part[1:].split(",")[0])
                        count = 1
                        if "," in plus_part:
                            count = int(plus_part.split(",")[1])
                        if count > 0:
                            for l_num in range(start_line, start_line + count):
                                files_map[current_file].diff_lines.add(l_num)
                    except (ValueError, IndexError):
                        continue

    except (subprocess.SubprocessError, OSError):
        return list(files_map.values())

    return list(files_map.values())


def get_git_hooks_dir(root: Path) -> Path | None:
    """Find the .git/hooks directory."""
    git_dir = root / ".git"
    if git_dir.is_dir():
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        return hooks_dir
    # Check for git worktree
    if git_dir.is_file():
        try:
            line = git_dir.read_text(encoding="utf-8").strip()
            if line.startswith("gitdir:"):
                common_dir = Path(line.split(":", 1)[1].strip())
                hooks_dir = common_dir / "hooks"
                hooks_dir.mkdir(parents=True, exist_ok=True)
                return hooks_dir
        except Exception:
            return None
    return None


def install_git_hook(root: Path) -> tuple[bool, str]:
    """Install sober pre-commit hook into repository."""
    hooks_dir = get_git_hooks_dir(root)
    if not hooks_dir:
        return False, "Not inside a valid Git repository."

    hook_file = hooks_dir / "pre-commit"
    try:
        hook_file.write_text(HOOK_SCRIPT, encoding="utf-8", newline="\n")
        # Make executable
        st = os.stat(hook_file)
        os.chmod(hook_file, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return True, str(hook_file)
    except OSError as e:
        return False, f"Failed to write hook: {e}"


def uninstall_git_hook(root: Path) -> tuple[bool, str]:
    """Remove sober pre-commit hook from repository."""
    hooks_dir = get_git_hooks_dir(root)
    if not hooks_dir:
        return False, "Not inside a valid Git repository."

    hook_file = hooks_dir / "pre-commit"
    if not hook_file.exists():
        return False, "Pre-commit hook is not installed."

    try:
        hook_file.unlink()
        return True, "Pre-commit hook successfully removed."
    except OSError as e:
        return False, f"Failed to remove hook: {e}"


def get_git_hook_status(root: Path) -> bool:
    """Check if sober pre-commit hook is installed."""
    hooks_dir = get_git_hooks_dir(root)
    if not hooks_dir:
        return False
    hook_file = hooks_dir / "pre-commit"
    if hook_file.is_file():
        try:
            content = hook_file.read_text(encoding="utf-8", errors="replace")
            return "sober" in content
        except Exception:
            return False
    return False
