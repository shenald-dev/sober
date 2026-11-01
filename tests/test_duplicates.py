from sober.core.scanner import FileToAudit
from sober.detectors.duplicates import audit_duplicates, extract_function_signatures


def test_extract_function_signatures_py():
    code = """
def my_func():
    pass

async def my_async_func():
    pass

class MyClass:
    def method(self):
        pass
"""
    sigs = extract_function_signatures(code, ".py")
    assert ("my_func", 2) in sigs
    assert ("my_async_func", 5) in sigs
    assert ("method", 9) in sigs

def test_extract_function_signatures_py_fallback():
    # Invalid syntax to trigger fallback
    code = """
def my_func(
def broken():
"""
    sigs = extract_function_signatures(code, ".py")
    assert ("my_func", 2) in sigs
    assert ("broken", 3) in sigs

def test_extract_function_signatures_js():
    code = """
function myFunc() {}
export async function myAsyncFunc() {}
const myArrowFunc = () => {}
export const myExportedArrowFunc = async (a, b) => {}
"""
    sigs = extract_function_signatures(code, ".js")
    assert ("myFunc", 2) in sigs
    assert ("myAsyncFunc", 3) in sigs
    assert ("myArrowFunc", 4) in sigs
    assert ("myExportedArrowFunc", 5) in sigs

def test_audit_duplicates(tmp_path):
    f1 = tmp_path / "file1.py"
    f1.write_text("def helper():\n    pass\n")
    f2 = tmp_path / "file2.py"
    f2.write_text("def helper():\n    pass\n")
    f3 = tmp_path / "file3.py"
    f3.write_text("def another_helper():\n    pass\n")

    files = [FileToAudit(f1), FileToAudit(f2), FileToAudit(f3)]
    issues = audit_duplicates(files, tmp_path)

    assert len(issues) == 1
    assert issues[0].category == "Redundant Duplication"
    assert "helper" in issues[0].title
    assert str(f2.name) in issues[0].file_path or str(f1.name) in issues[0].file_path

def test_audit_duplicates_ignores_special_names(tmp_path):
    f1 = tmp_path / "file1.py"
    f1.write_text("def __init__():\n    pass\ndef test_something():\n    pass\n")
    f2 = tmp_path / "file2.py"
    f2.write_text("def __init__():\n    pass\ndef test_something():\n    pass\n")

    files = [FileToAudit(f1), FileToAudit(f2)]
    issues = audit_duplicates(files, tmp_path)

    assert len(issues) == 0

def test_audit_duplicates_empty_code(tmp_path):
    f1 = tmp_path / "file1.py"
    f1.write_text("")
    files = [FileToAudit(f1)]
    issues = audit_duplicates(files, tmp_path)
    assert len(issues) == 0
