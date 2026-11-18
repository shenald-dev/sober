"""
Git intelligence helper - range diff auditing, staged-content auditing and
pre-commit hook management.
"""

import logging
import os
import stat
import subprocess
from pathlib import Path

from sober.core.scanner import SUPPORTED_EXTENSIONS, FileToAudit, is_git_repo

logger = logging.getLogger(__name__)

HOOK_SCRIPT = """#!/usr/bin/env sh
# Installed by sober - The Vibe Coding Hangover Cure
# https://github.com/shenald-dev/sober

echo "🍸 Running sober pre-commit sobriety check (staged content)..."
sober scan --staged --strict
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ sober detected unaddressed AI hangover issues or low sobriety score."
    echo "Run 'sober scan' to view details, or 'sober scan --cure' to auto-fix debug statements."
    exit 1
fi
exit 0
"""


def _parse_diff_path(line: str) -> str | None:
    """Parse the file path from a git diff +++ line, handling quotes and spaces."""
    if not line.startswith("+++ "):
        return None
    path_str = line[4:]
    if "\t" in path_str:
        path_str = path_str.split("\t", 1)[0]
    if path_str.startswith('"') and path_str.endswith('"'):
        path_str = path_str[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    if path_str.startswith("b/"):
        return path_str[2:]
    return None


def _parse_hunk_lines(diff_stdout: str, files_map: dict, root: Path):
    current_file: Path | None = None
    for line in diff_stdout.splitlines():
        if line.startswith("+++ "):
            rel = _parse_diff_path(line)
            current_file = (root / rel) if rel else None
        elif line.startswith("@@ ") and current_file in files_map:
            try:
                hunk_header = line.split("@@")[1].strip()
                plus_part = hunk_header.split()[1]
                start_line = int(plus_part[1:].split(",")[0])
                count = 1
                if "," in plus_part:
                    count = int(plus_part.split(",")[1])
                if count > 0:
                    for l_num in range(start_line, start_line + count):
                        files_map[current_file].diff_lines.add(l_num)
            except (ValueError, IndexError):
                continue


def get_git_diff_range_files(root: Path, revision_range: str) -> list[FileToAudit]:
    """Retrieve modified files and changed line numbers for a git revision range."""
    if not is_git_repo(root):
        return []
    files_map: dict[Path, FileToAudit] = {}
    try:
        diff_names = subprocess.run(
            ["git", "diff", "--name-only", "-z", revision_range],
            cwd=str(root), capture_output=True, text=True, check=False)
        if diff_names.returncode == 0:
            for rel_path in diff_names.stdout.split("\0"):
                if not rel_path:
                    continue
                file_path = root / rel_path
                if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                    files_map[file_path] = FileToAudit(file_path, is_git_diff=True)
        diff_res = subprocess.run(
            ["git", "-c", "core.quotepath=false", "diff", revision_range, "--unified=0"],
            cwd=str(root), capture_output=True, text=True, check=False)
        if diff_res.returncode == 0:
            _parse_hunk_lines(diff_res.stdout, files_map, root)
    except (subprocess.SubprocessError, OSError):
        return list(files_map.values())
    return list(files_map.values())


def get_git_staged_files(root: Path) -> list[FileToAudit]:
    """Retrieve staged (index) files and their changed line numbers."""
    if not is_git_repo(root):
        return []
    files_map: dict[Path, FileToAudit] = {}
    try:
        names = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "-z"],
            cwd=str(root), capture_output=True, text=True, check=False)
        if names.returncode == 0:
            for rel_path in names.stdout.split("\0"):
                if not rel_path:
                    continue
                file_path = root / rel_path
                if file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                    files_map[file_path] = FileToAudit(file_path, is_git_diff=True)
        diff_res = subprocess.run(
            ["git", "-c", "core.quotepath=false", "diff", "--cached", "--unified=0"],
            cwd=str(root), capture_output=True, text=True, check=False)
        if diff_res.returncode == 0:
            _parse_hunk_lines(diff_res.stdout, files_map, root)
    except (subprocess.SubprocessError, OSError):
        return list(files_map.values())
    return list(files_map.values())


def get_staged_contents(root: Path, files: list[FileToAudit]) -> dict[Path, str]:
    """Read staged blob contents in a single batched git cat-file invocation."""
    if not files:
        return {}
    rels = []
    for f in files:
        try:
            rels.append(str(f.path.relative_to(root)))
        except ValueError:
            rels.append(str(f.path))
    stdin = "".join(f":{rel}\n" for rel in rels).encode("utf-8")
    try:
        proc = subprocess.run(
            ["git", "cat-file", "--batch"],
            cwd=str(root), input=stdin, capture_output=True, check=False)
    except (subprocess.SubprocessError, OSError):
        return {}
    if proc.returncode != 0:
        return {}
    contents: dict[Path, str] = {}
    buf = proc.stdout
    pos = 0
    for f, rel in zip(files, rels):
        nl = buf.find(b"\n", pos)
        if nl == -1:
            break
        header = buf[pos:nl].decode("utf-8", errors="replace").split()
        pos = nl + 1
        if len(header) >= 3 and header[1] == "blob":
            size = int(header[2])
            contents[f.path] = buf[pos:pos + size].decode("utf-8", errors="replace")
            pos += size + 1
        else:
            contents[f.path] = f.read_text()
    return contents


def get_git_hooks_dir(root: Path) -> Path | None:
    """Find the .git/hooks directory."""
    git_dir = root / ".git"
    if git_dir.is_dir():
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        return hooks_dir
    if git_dir.is_file():
        try:
            line = git_dir.read_text(encoding="utf-8").strip()
            if line.startswith("gitdir:"):
                common_dir_str = line.split(":", 1)[1].strip()
                common_dir = (root / common_dir_str).resolve()
                hooks_dir = common_dir / "hooks"
                hooks_dir.mkdir(parents=True, exist_ok=True)
                return hooks_dir
        except OSError:
            logger.debug("Failed to read gitdir for worktree hooks resolution", exc_info=True)
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
        except OSError:
            logger.debug("Failed to read hook file %s", hook_file, exc_info=True)
            return False
    return False
