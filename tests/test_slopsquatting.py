from pathlib import Path
from sober.core.scanner import FileToAudit
from sober.detectors import Severity
from sober.detectors.hallucinations import audit_hallucinations
from sober.detectors.slopsquatting import (
    damerau_levenshtein_distance,
    find_slopsquatted_target,
)


def test_damerau_levenshtein_distance():
    assert damerau_levenshtein_distance("requests", "requests") == 0
    assert damerau_levenshtein_distance("reqeusts", "requests") == 1  # transposition
    assert damerau_levenshtein_distance("nummpy", "numpy") == 1      # insertion
    assert damerau_levenshtein_distance("flaskk", "flask") == 1


def test_find_slopsquatted_target_python():
    target, dist = find_slopsquatted_target("reqeusts", ecosystem="python")
    assert target == "requests"
    assert dist == 1

    target, dist = find_slopsquatted_target("nummpy", ecosystem="python")
    assert target == "numpy"
    assert dist == 1

    # Legitimate package
    target, dist = find_slopsquatted_target("requests", ecosystem="python")
    assert target is None


def test_find_slopsquatted_target_npm():
    target, dist = find_slopsquatted_target("reaact", ecosystem="npm")
    assert target == "react"
    assert dist == 1

    target, dist = find_slopsquatted_target("axois", ecosystem="npm")
    assert target == "axios"
    assert dist == 1


def test_hallucination_detector_flags_slopsquatting(tmp_path: Path):
    f = tmp_path / "app.py"
    f.write_text("import reqeusts\n\ndef main():\n    pass\n")
    audit = FileToAudit(f)

    issues = audit_hallucinations(audit, tmp_path)
    assert len(issues) == 1
    assert issues[0].category == "Slopsquatting Risk"
    assert issues[0].severity == Severity.CRITICAL
    assert "resembles 'requests'" in issues[0].title
