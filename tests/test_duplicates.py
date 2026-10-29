from pathlib import Path
from sober.core.scanner import FileToAudit
from sober.detectors.duplicates import extract_function_signatures, audit_duplicates

def test_extract_function_signatures():
    py_code = """
def test_ignore_me():
    pass
def do_something():
    pass
async def do_something_async():
    pass
"""
    py_sigs = extract_function_signatures(py_code, ".py")
    assert ("test_ignore_me", 2) in py_sigs
    assert ("do_something", 4) in py_sigs
    assert ("do_something_async", 6) in py_sigs

    js_code = """
function doJsThing() {}
export const doTsThing = () => {}
"""
    js_sigs = extract_function_signatures(js_code, ".js")
    assert ("doJsThing", 2) in js_sigs
    assert ("doTsThing", 3) in js_sigs

def test_audit_duplicates(tmp_path):
    file1 = tmp_path / "file1.py"
    file1.write_text("def unique1():\n    pass\n")

    file2 = tmp_path / "file2.py"
    file2.write_text("def unique1():\n    pass\n")

    file3 = tmp_path / "file3.py"
    file3.write_text("def __init__():\n    pass\n")

    file4 = tmp_path / "file4.py"
    file4.write_text("def __init__():\n    pass\n")

    files = [
        FileToAudit(file1),
        FileToAudit(file2),
        FileToAudit(file3),
        FileToAudit(file4),
    ]

    issues = audit_duplicates(files, tmp_path)
    assert len(issues) == 1
    assert issues[0].category == "Redundant Duplication"
    assert "unique1" in issues[0].title
