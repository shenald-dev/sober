import pytest
from sober.core.scorer import SoberAuditReport
from sober.detectors import Issue, Severity

def test_perfect_score_when_no_issues():
    report = SoberAuditReport([], files_scanned=5, duration_seconds=0.1)
    assert report.score == 100
    assert report.grade == "A+"
    assert "Crystal Sober" in report.status_label

def test_critical_deductions_clamp():
    issues = [
        Issue("Cat", "Title", "Desc", Severity.CRITICAL, "file.py"),
        Issue("Cat", "Title", "Desc", Severity.CRITICAL, "file.py"),
        Issue("Cat", "Title", "Desc", Severity.CRITICAL, "file.py"),
        Issue("Cat", "Title", "Desc", Severity.CRITICAL, "file.py"),
        Issue("Cat", "Title", "Desc", Severity.CRITICAL, "file.py"),
    ]
    report = SoberAuditReport(issues, files_scanned=1, duration_seconds=0.2)
    assert report.score == 0
    assert report.grade == "F"
    assert "Complete Blackout" in report.status_label

def test_mild_score_deduction():
    issues = [
        Issue("Cat", "Title", "Desc", Severity.LOW, "file.py"),
        Issue("Cat", "Title", "Desc", Severity.LOW, "file.py"),
    ]
    report = SoberAuditReport(issues, files_scanned=2, duration_seconds=0.05)
    assert report.score == 96
    assert report.grade == "A+"
