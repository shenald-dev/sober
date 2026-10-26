import json
from typer.testing import CliRunner
from sober.cli import app

runner = CliRunner()

def test_cli_version():
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0
    assert "sober version" in res.stdout

def test_cli_scan_clean_dir(tmp_path):
    f = tmp_path / "main.py"
    f.write_text("def hello():\n    return 'world'\n")
    
    res = runner.invoke(app, ["scan", str(tmp_path), "--all"])
    assert res.exit_code == 0
    assert "CRYSTAL SOBER" in res.stdout

def test_cli_scan_json_output(tmp_path):
    f = tmp_path / "main.py"
    f.write_text("def hello():\n    return 'world'\n")
    
    res = runner.invoke(app, ["scan", str(tmp_path), "--all", "--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["sober_score"] == 100
    assert data["grade"] == "A+"

def test_cli_scan_cure_cleans_file(tmp_path):
    f = tmp_path / "debug.py"
    f.write_text("def run():\n    print(f'DEBUG: here')\n    return 10\n")
    
    # Run with --cure
    res = runner.invoke(app, ["scan", str(tmp_path), "--all", "--cure"])
    assert res.exit_code == 0
    assert "Auto-Cure Sanitization Report" in res.stdout
    
    # Verify file was cleaned
    content = f.read_text()
    assert "DEBUG: here" not in content
    assert "return 10" in content

def test_cli_strict_fails_on_critical(tmp_path):
    f = tmp_path / "bad.py"
    f.write_text('OPENAI_KEY = "sk-1234567890abcdef1234567890abcdef123456"\n')
    
    res = runner.invoke(app, ["scan", str(tmp_path), "--all", "--strict"])
    assert res.exit_code == 1
