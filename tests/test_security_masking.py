from sober.core.scanner import FileToAudit
from sober.detectors.security import SECRET_PATTERNS, audit_security, mask_secrets


def test_multi_secret_line_fully_masked(tmp_path):
    key_a = "sk-" + "a" * 40
    key_b = "ghp_" + "b" * 36
    f = tmp_path / "leak.py"
    f.write_text(f'PAIR = "{key_a} {key_b}"\n')
    issues = audit_security(FileToAudit(f), tmp_path)
    assert len(issues) >= 2
    for issue in issues:
        assert key_a not in issue.code_snippet
        assert key_b not in issue.code_snippet
        assert key_a not in issue.description
        assert key_b not in issue.description


def test_mask_secrets_helper():
    line = 'x = "sk-' + "c" * 40 + '"'
    out = mask_secrets(line, SECRET_PATTERNS)
    assert "c" * 40 not in out
    assert "..." in out


def test_js_regex_exec_not_flagged(tmp_path):
    f = tmp_path / "parse.js"
    f.write_text("const m = pattern.exec(input);\nconst e = re.exec(s);\n")
    issues = audit_security(FileToAudit(f), tmp_path)
    assert not any("exec()" in i.title for i in issues)


def test_python_exec_still_flagged(tmp_path):
    f = tmp_path / "dyn.py"
    f.write_text("exec(user_code)\n")
    issues = audit_security(FileToAudit(f), tmp_path)
    assert any("exec()" in i.title for i in issues)


def test_security_rule_ids_present(tmp_path):
    f = tmp_path / "k.py"
    f.write_text('OPENAI_KEY = "sk-' + "d" * 40 + '"\n')
    issues = audit_security(FileToAudit(f), tmp_path)
    assert issues[0].rule_id == "SOBER-SEC001"
