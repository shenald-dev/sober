from sober.core.scanner import FileToAudit
from sober.detectors import Severity
from sober.detectors.ghost_code import audit_ghost_code


def test_detects_debug_print_and_console_log(tmp_path):
    py_file = tmp_path / "app.py"
    py_file.write_text('def run():\n    print(f"DEBUG: user is {1}")\n    return 42\n')
    
    js_file = tmp_path / "app.ts"
    js_file.write_text('function run() {\n    console.log("DEBUG: check");\n    debugger;\n    return 42;\n}\n')
    
    py_issues = audit_ghost_code(FileToAudit(py_file), tmp_path)
    assert len(py_issues) == 1
    assert py_issues[0].category == "Debug Debris"
    assert py_issues[0].auto_fixable is True
    
    js_issues = audit_ghost_code(FileToAudit(js_file), tmp_path)
    assert len(js_issues) == 2
    assert any(i.severity == Severity.HIGH for i in js_issues)  # debugger

def test_detects_silent_error_swallows(tmp_path):
    py_file = tmp_path / "unsafe.py"
    py_file.write_text("try:\n    risky()\nexcept:\n    pass\n")
    
    js_file = tmp_path / "unsafe.js"
    js_file.write_text("try { risky(); } catch (err) {}\n")
    
    py_issues = audit_ghost_code(FileToAudit(py_file), tmp_path)
    assert any(i.category == "Silent Error Swallow" for i in py_issues)
    
    js_issues = audit_ghost_code(FileToAudit(js_file), tmp_path)
    assert any(i.category == "Silent Error Swallow" for i in js_issues)

def test_detects_ai_stubs(tmp_path):
    py_file = tmp_path / "stub.py"
    py_file.write_text("def solve():\n    # TODO: implement logic\n    raise NotImplementedError()\n")
    
    issues = audit_ghost_code(FileToAudit(py_file), tmp_path)
    assert len(issues) == 2
    assert all(i.category == "Incomplete AI Stub" for i in issues)
