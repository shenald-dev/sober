from sober.core.scanner import FileToAudit
from sober.detectors import Severity
from sober.detectors.hallucinations import _REGISTRY_CACHE, audit_hallucinations


def test_python_stdlib_not_flagged(tmp_path):
    f = tmp_path / "valid.py"
    f.write_text("import sys\nimport os\nimport json\nfrom datetime import datetime\n")
    issues = audit_hallucinations(FileToAudit(f), tmp_path)
    assert len(issues) == 0

def test_node_builtins_not_flagged(tmp_path):
    f = tmp_path / "valid.ts"
    f.write_text("import fs from 'fs';\nimport path from 'path';\n")
    issues = audit_hallucinations(FileToAudit(f), tmp_path)
    assert len(issues) == 0

def test_hallucinated_pypi_package_flagged(tmp_path, monkeypatch):
    # Mock registry cache to simulate confirmed 404 for nonexistent package
    _REGISTRY_CACHE["totally-fake-hallucinated-package-xyz123"] = False
    f = tmp_path / "ai_code.py"
    f.write_text("import totally_fake_hallucinated_package_xyz123\n")
    
    issues = audit_hallucinations(FileToAudit(f), tmp_path)
    assert len(issues) == 1
    assert issues[0].severity == Severity.CRITICAL
    assert "totally_fake_hallucinated_package_xyz123" in issues[0].title
