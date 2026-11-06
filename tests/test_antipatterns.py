from pathlib import Path
from sober.core.scanner import FileToAudit
from sober.detectors import Severity
from sober.detectors.antipatterns import audit_antipatterns


def test_audit_missing_http_timeout(tmp_path: Path):
    f = tmp_path / "client.py"
    f.write_text("import requests\n\ndef fetch():\n    return requests.get('https://example.com/api')\n")
    audit = FileToAudit(f)

    issues = audit_antipatterns(audit, tmp_path)
    assert len(issues) == 1
    assert issues[0].category == "Reliability Antipattern"
    assert issues[0].severity == Severity.HIGH
    assert "Omitted HTTP Timeout" in issues[0].title


def test_audit_http_with_timeout_not_flagged(tmp_path: Path):
    f = tmp_path / "client.py"
    f.write_text("import requests\n\ndef fetch():\n    return requests.get('https://example.com/api', timeout=10.0)\n")
    audit = FileToAudit(f)

    issues = audit_antipatterns(audit, tmp_path)
    assert len(issues) == 0


def test_audit_insecure_random_token(tmp_path: Path):
    f = tmp_path / "auth.py"
    f.write_text("import random\n\ndef make_auth_token():\n    token = random.randint(100000, 999999)\n    return token\n")
    audit = FileToAudit(f)

    issues = audit_antipatterns(audit, tmp_path)
    assert len(issues) == 1
    assert issues[0].category == "Cryptographic Antipattern"
    assert "Insecure Pseudo-Random Token Generation" in issues[0].title


def test_audit_secure_token_not_flagged(tmp_path: Path):
    f = tmp_path / "auth.py"
    f.write_text("import secrets\n\ndef make_auth_token():\n    token = secrets.token_urlsafe(32)\n    return token\n")
    audit = FileToAudit(f)

    issues = audit_antipatterns(audit, tmp_path)
    assert len(issues) == 0


def test_audit_js_insecure_random(tmp_path: Path):
    f = tmp_path / "auth.js"
    f.write_text("function genSession() {\n    const session_id = 'sess_' + Math.random();\n    return session_id;\n}\n")
    audit = FileToAudit(f)

    issues = audit_antipatterns(audit, tmp_path)
    assert len(issues) == 1
    assert "Insecure Math.random()" in issues[0].title


def test_audit_js_fetch_missing_timeout(tmp_path: Path):
    f = tmp_path / "api.js"
    f.write_text("async function load() {\n    const res = await fetch('https://api.com/data');\n    return res.json();\n}\n")
    audit = FileToAudit(f)

    issues = audit_antipatterns(audit, tmp_path)
    assert len(issues) == 1
    assert "Omitted Timeout in JavaScript fetch()" in issues[0].title


def test_audit_client_leaked_system_prompt(tmp_path: Path):
    f = tmp_path / "chatComponent.tsx"
    f.write_text("const config = { instructions: 'You are a confidential internal assistant' };\n")
    audit = FileToAudit(f)

    issues = audit_antipatterns(audit, tmp_path)
    assert len(issues) == 1
    assert "Client-Side Exposed System Instructions" in issues[0].title


def test_audit_direct_prompt_injection(tmp_path: Path):
    f = tmp_path / "agent.py"
    f.write_text("""
def run_chat(user_msg):
    messages = [{"role": "user", "content": f"User prompt: {user_msg}"}]
    return client.chat(messages=messages)
""")
    audit = FileToAudit(f)

    issues = audit_antipatterns(audit, tmp_path)
    assert len(issues) >= 1
    assert any(i.category == "LLM Prompt Injection Risk" for i in issues)
