import subprocess
from pathlib import Path

from sober.core.git_helper import get_git_staged_files, get_staged_contents


def _git(root, *args):
    subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True)


def _repo(tmp_path: Path):
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "t@t.t")
    _git(tmp_path, "config", "user.name", "T")
    f = tmp_path / "m.py"
    f.write_text("x = 1\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "init")
    return f


def test_staged_files_and_lines(tmp_path):
    f = _repo(tmp_path)
    f.write_text("x = 1\ny = 2\n")
    _git(tmp_path, "add", "m.py")
    files = get_git_staged_files(tmp_path)
    assert len(files) == 1
    assert 2 in files[0].diff_lines


def test_staged_content_differs_from_working(tmp_path):
    f = _repo(tmp_path)
    f.write_text("staged = True\n")
    _git(tmp_path, "add", "m.py")
    f.write_text("working = True\n")  # unstaged edit after staging
    files = get_git_staged_files(tmp_path)
    contents = get_staged_contents(tmp_path, files)
    assert "staged = True" in contents[f]
    assert "working" not in contents[f]


def test_staged_empty_when_nothing_staged(tmp_path):
    _repo(tmp_path)
    assert get_git_staged_files(tmp_path) == []


def test_hook_uses_staged(tmp_path):
    from sober.core.git_helper import HOOK_SCRIPT
    assert "--staged" in HOOK_SCRIPT
