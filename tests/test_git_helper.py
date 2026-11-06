import subprocess

from sober.core.git_helper import (
    get_git_diff_range_files,
    get_git_hook_status,
    install_git_hook,
    uninstall_git_hook,
)


def test_parse_diff_path_helper():
    from sober.core.git_helper import _parse_diff_path
    assert _parse_diff_path("+++ b/test.py") == "test.py"
    assert _parse_diff_path("+++ b/space file.py") == "space file.py"
    assert _parse_diff_path('+++ "b/\\"quotes\\".py"') == '"quotes".py'


def test_relative_gitdir(tmp_path):
    from sober.core.git_helper import get_git_hooks_dir
    worktree = tmp_path / "worktree"
    worktree.mkdir()

    common_git = tmp_path / "common_git"
    common_git.mkdir()

    # Write a relative gitdir pointer
    git_file = worktree / ".git"
    git_file.write_text("gitdir: ../common_git\n")

    hooks_dir = get_git_hooks_dir(worktree)
    assert hooks_dir is not None
    assert hooks_dir.is_dir()
    assert hooks_dir.resolve() == (common_git / "hooks").resolve()


def test_git_hook_lifecycle(tmp_path):
    # Initialize git repo
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(tmp_path), check=True)

    # Initial status
    assert get_git_hook_status(tmp_path) is False

    # Install
    success, hook_path = install_git_hook(tmp_path)
    assert success is True
    assert "pre-commit" in hook_path
    assert get_git_hook_status(tmp_path) is True

    # Uninstall
    success, _msg = uninstall_git_hook(tmp_path)
    assert success is True
    assert get_git_hook_status(tmp_path) is False


def test_get_git_diff_range_files(tmp_path):
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(tmp_path), check=True)

    f1 = tmp_path / "file1.py"
    f1.write_text("initial = True\n")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "commit", "-m", "commit 1"], cwd=str(tmp_path), check=True, capture_output=True)

    # Make second commit
    f1.write_text("initial = True\nupdated = True\n")
    f2 = tmp_path / "file2.js"
    f2.write_text("console.log('test');")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "commit", "-m", "commit 2"], cwd=str(tmp_path), check=True, capture_output=True)

    diff_files = get_git_diff_range_files(tmp_path, "HEAD~1..HEAD")
    assert len(diff_files) == 2
    paths = {f.path for f in diff_files}
    assert f1 in paths
    assert f2 in paths
