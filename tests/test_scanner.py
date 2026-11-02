import subprocess

from sober.core.scanner import FileToAudit, get_all_code_files, get_git_modified_files, is_git_repo


def test_file_to_audit(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("content")

    f_audit = FileToAudit(f)
    assert f_audit.extension == ".py"
    assert f_audit.read_text() == "content"


def test_file_to_audit_non_existent(tmp_path):
    f = tmp_path / "does_not_exist.py"
    f_audit = FileToAudit(f)
    assert f_audit.read_text() == ""


def test_is_git_repo_false(tmp_path):
    # tmp_path should not be a git repo
    assert is_git_repo(tmp_path) is False


def test_get_git_modified_files_not_git_repo(tmp_path):
    files = get_git_modified_files(tmp_path)
    assert files == []


def test_get_all_code_files(tmp_path):
    # Create some valid files
    f1 = tmp_path / "test1.py"
    f1.write_text("")
    f2 = tmp_path / "test2.js"
    f2.write_text("")

    # Create ignored dir
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    f3 = node_modules / "test3.py"
    f3.write_text("")

    # Create valid subdir
    subdir = tmp_path / "src"
    subdir.mkdir()
    f4 = subdir / "test4.ts"
    f4.write_text("")

    # Create ignored file type
    f5 = tmp_path / "test5.txt"
    f5.write_text("")

    files = get_all_code_files(tmp_path)

    assert len(files) == 3
    paths = [f.path for f in files]
    assert f1 in paths
    assert f2 in paths
    assert f4 in paths
    assert f3 not in paths
    assert f5 not in paths


def test_get_git_modified_files_unified_parsing(tmp_path):
    # Initialize a git repo
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(tmp_path), check=True)

    f1 = tmp_path / "test1.py"
    f1.write_text("line1\nline2\nline3\n")

    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(tmp_path), check=True, capture_output=True)

    # Modify the file
    f1.write_text("line1\nnew_line2\nnew_line2_b\nline3\nnew_line_4\n")

    # Do not commit, leave it in working tree
    files = get_git_modified_files(tmp_path)

    assert len(files) == 1
    file_audit = files[0]
    assert file_audit.path == f1
    assert file_audit.is_git_diff is True
    # The new file has diff on line 2, 3 and 5.
    # diff expected: @@ -2 +2,2 @@, @@ -4 +5 @@
    assert 2 in file_audit.diff_lines
    assert 3 in file_audit.diff_lines
    assert 5 in file_audit.diff_lines

    # Add a new untracked file
    f2 = tmp_path / "test2.js"
    f2.write_text("console.log('hello');")

    files = get_git_modified_files(tmp_path)
    assert len(files) == 2
    paths = {f.path for f in files}
    assert f1 in paths
    assert f2 in paths
