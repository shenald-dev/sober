"""
File and Git repository scanner for detecting code to audit.
"""

import os
import subprocess
from pathlib import Path

SUPPORTED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx"}
IGNORED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    "dist",
    "build",
    "venv",
    ".venv",
    "env",
    ".env",
    "target",
    "out",
    "tests",
    "test",
    "__tests__",
}


class FileToAudit:
    def __init__(self, path: Path, is_git_diff: bool = False, diff_lines: set[int] | None = None):
        self.path = path
        self.is_git_diff = is_git_diff
        self.diff_lines = diff_lines or set()

    @property
    def extension(self) -> str:
        return self.path.suffix.lower()

    def read_text(self) -> str:
        try:
            return self.path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            return ""


def is_git_repo(root: Path) -> bool:
    """Check if the directory is inside a Git repository."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        return res.returncode == 0
    except OSError:
        return False


def get_git_modified_files(root: Path) -> list[FileToAudit]:
    """Retrieve modified, staged, and untracked files from git status and diff."""
    if not is_git_repo(root):
        return []

    files_map = {}
    try:
        # 1. Uncommitted and untracked files
        status_res = subprocess.run(
            ["git", "status", "--porcelain", "-uall"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if status_res.returncode == 0:
            for line in status_res.stdout.splitlines():
                if not line.strip():
                    continue
                # Line format: XY filename or XY orig -> new
                parts = line[3:].strip().split(" -> ")
                rel_path = parts[-1].strip()
                file_path = root / rel_path
                if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                    files_map[file_path] = FileToAudit(file_path, is_git_diff=True)

        # 2. Get specific modified line numbers from git diff
        diff_res = subprocess.run(
            ["git", "diff", "HEAD", "--unified=0"],
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
                    # e.g., @@ -10,3 +12,5 @@
                    try:
                        hunk_header = line.split("@@")[1].strip()
                        plus_part = hunk_header.split()[1]  # +12,5
                        start_line = int(plus_part[1:].split(",")[0])
                        count = 1
                        if "," in plus_part:
                            count = int(plus_part.split(",")[1])
                        for l_num in range(start_line, start_line + max(count, 1)):
                            files_map[current_file].diff_lines.add(l_num)
                    except (ValueError, IndexError):
                        continue

    except (subprocess.SubprocessError, OSError):
        return list(files_map.values())

    return list(files_map.values())


def get_all_code_files(root: Path) -> list[FileToAudit]:
    """Recursively discover all supported source files in the project."""
    files: list[FileToAudit] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in place
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")]
        for f in filenames:
            ext = os.path.splitext(f)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                full_path = Path(dirpath) / f
                files.append(FileToAudit(full_path))
    return files
