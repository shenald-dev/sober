from pathlib import Path

from typer.testing import CliRunner

from sober.cli import app

runner = CliRunner()


def test_cli_scan_offline_flag(tmp_path: Path):
    f = tmp_path / "app.py"
    f.write_text("import json\n\ndef main(): pass\n")

    res = runner.invoke(app, ["scan", str(tmp_path), "--all", "--offline"])
    assert res.exit_code == 0
    assert "PERFECT SOBRIETY" in res.stdout or "SOBRIETY HEALTH" in res.stdout


def test_cli_explain_command(tmp_path: Path):
    f = tmp_path / "app.py"
    f.write_text("import random\n\ndef make_token():\n    token = random.randint(100, 999)\n    return token\n")

    res = runner.invoke(app, ["explain", str(tmp_path), "--all"])
    assert res.exit_code == 0
    assert "SOBER AGENT REMEDIATION DIRECTIVE" in res.stdout
    assert "app.py" in res.stdout


def test_cli_explain_clean_repository(tmp_path: Path):
    f = tmp_path / "app.py"
    f.write_text("def hello(): return 42\n")

    res = runner.invoke(app, ["explain", str(tmp_path), "--all"])
    assert res.exit_code == 0
    assert "ALL CHECKS PASSED" in res.stdout


def test_cli_ci_init_command(tmp_path: Path):
    res = runner.invoke(app, ["ci", "init", str(tmp_path)])
    assert res.exit_code == 0
    workflow_path = tmp_path / ".github" / "workflows" / "sober-guard.yml"
    assert workflow_path.exists()
    content = workflow_path.read_text(encoding="utf-8")
    assert "sober scan --all --strict" in content
    assert "upload-sarif" in content


def test_cli_cure_strips_markdown_fences(tmp_path: Path):
    f = tmp_path / "app.py"
    f.write_text("```python\ndef hello():\n    return 'world'\n```\n")

    res = runner.invoke(app, ["cure", str(tmp_path), "--all"])
    assert res.exit_code == 0
    cleaned = f.read_text(encoding="utf-8")
    assert "```" not in cleaned
    assert "def hello():" in cleaned


def test_cli_init_v2(tmp_path: Path):
    res = runner.invoke(app, ["init", str(tmp_path)])
    assert res.exit_code == 0
    config_file = tmp_path / "sober.toml"
    assert config_file.exists()
    content = config_file.read_text(encoding="utf-8")
    assert "offline_mode = false" in content
