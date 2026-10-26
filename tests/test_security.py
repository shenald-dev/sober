from sober.core.scanner import FileToAudit
from sober.detectors.security import audit_security
from sober.detectors import Severity

def test_detects_leaked_openai_and_github_keys(tmp_path):
    f = tmp_path / "secrets.py"
    f.write_text("""
OPENAI_KEY = "sk-1234567890abcdef1234567890abcdef123456"
GITHUB_PAT = "ghp_1234567890abcdef1234567890abcdef1234"
""")
    issues = audit_security(FileToAudit(f), tmp_path)
    assert len(issues) == 2
    assert all(i.severity == Severity.CRITICAL for i in issues)
    # Ensure key preview in snippet is masked
    assert "sk-1234567890abcdef1234567890abcdef123456" not in issues[0].code_snippet

def test_detects_shell_and_sql_injections(tmp_path):
    f = tmp_path / "unsafe.py"
    f.write_text("""
import subprocess
def run_cmd(user_arg):
    subprocess.call(f"ls {user_arg}", shell=True)
    query = f"SELECT * FROM users WHERE name = '{user_arg}'"
""")
    issues = audit_security(FileToAudit(f), tmp_path)
    assert len(issues) == 2
    assert any("Command Injection" in i.title for i in issues)
    assert any("SQL Injection" in i.title for i in issues)
