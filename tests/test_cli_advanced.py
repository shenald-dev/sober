import json
import subprocess

from typer.testing import CliRunner

from sober.cli import app

runner = CliRunner()


def test_cli_scan_sarif_output(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("import os\n")

    res = runner.invoke(app, ["scan", str(tmp_path), "--all", "--sarif"])
    assert res.exit_code == 0
    sarif = json.loads(res.stdout)
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "sober"


def test_cli_scan_markdown_output(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("import os\n")

    res = runner.invoke(app, ["scan", str(tmp_path), "--all", "--markdown"])
    assert res.exit_code == 0
    assert "## 🟢 SOBER Audit Report" in res.stdout
    assert "Crystal Sober" in res.stdout


def test_cli_hook_management(tmp_path):
    # Setup git repo
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)

    # Status before install
    res = runner.invoke(app, ["hook", "status", str(tmp_path)])
    assert res.exit_code == 0
    assert "DISABLED" in res.stdout

    # Install
    res = runner.invoke(app, ["hook", "install", str(tmp_path)])
    assert res.exit_code == 0
    assert "Successfully installed" in res.stdout

    # Status after install
    res = runner.invoke(app, ["hook", "status", str(tmp_path)])
    assert res.exit_code == 0
    assert "ENABLED" in res.stdout

    # Uninstall
    res = runner.invoke(app, ["hook", "uninstall", str(tmp_path)])
    assert res.exit_code == 0
    assert "successfully removed" in res.stdout


def test_cli_init_command(tmp_path):
    res = runner.invoke(app, ["init", str(tmp_path)])
    assert res.exit_code == 0
    sober_toml = tmp_path / "sober.toml"
    assert sober_toml.exists()
    assert "[sober]" in sober_toml.read_text()

    # Re-running warns that it already exists
    res = runner.invoke(app, ["init", str(tmp_path)])
    assert res.exit_code == 0
    assert "already exists" in res.stdout


def test_cli_cure_standalone(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("""print("DEBUG: test 123")
# Certainly! Here is the updated code
def foo():
    return True
""")

    res = runner.invoke(app, ["cure", str(tmp_path), "--all"])
    assert res.exit_code == 0
    assert "Successfully sanitized" in res.stdout

    cleaned = f.read_text()
    assert "DEBUG: test 123" not in cleaned
    assert "Certainly! Here is" not in cleaned
    assert "return True" in cleaned


def test_cli_diff_command(tmp_path):
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(tmp_path), check=True)

    f = tmp_path / "main.py"
    f.write_text("x = 1\n")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=str(tmp_path), check=True, capture_output=True)

    f.write_text("x = 1\ny = 2\n")
    subprocess.run(["git", "add", "."], cwd=str(tmp_path), check=True)
    subprocess.run(["git", "commit", "-m", "second"], cwd=str(tmp_path), check=True, capture_output=True)

    res = runner.invoke(app, ["diff", "HEAD~1..HEAD", "--path", str(tmp_path)])
    assert res.exit_code == 0
    assert "Auditing changes in git range" in res.stdout
