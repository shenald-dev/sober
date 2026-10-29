import subprocess
from pathlib import Path
from sober.core.scanner import is_git_repo, get_all_code_files

def test_is_git_repo_true(tmp_path):
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    assert is_git_repo(tmp_path) is True

def test_is_git_repo_false(tmp_path):
    assert is_git_repo(tmp_path) is False

def test_get_all_code_files(tmp_path):
    # Setup mock files
    (tmp_path / "valid.py").write_text("print('hello')")
    (tmp_path / "valid.ts").write_text("console.log('hello')")
    (tmp_path / "ignored.txt").write_text("ignore me")

    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "hidden.py").write_text("print('hidden')")

    files = get_all_code_files(tmp_path)

    file_paths = {f.path.name for f in files}
    assert len(files) == 2
    assert "valid.py" in file_paths
    assert "valid.ts" in file_paths
    assert "hidden.py" not in file_paths
    assert "ignored.txt" not in file_paths
