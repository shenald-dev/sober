import subprocess

from sober.core.git_helper import (
    get_git_diff_range_files,
    get_git_hook_status,
    install_git_hook,
    uninstall_git_hook,
)


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
    success, msg = uninstall_git_hook(tmp_path)
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
