"""
Sober Score engine - computes code sobriety metrics, health grades, and risk summaries.
"""

from typing import Dict, List
from sober.detectors import Issue, Severity


class SoberAuditReport:
    def __init__(self, issues: List[Issue], files_scanned: int, duration_seconds: float):
        self.issues = issues
        self.files_scanned = files_scanned
        self.duration_seconds = duration_seconds
        self.score, self.grade, self.status_label, self.color = self._compute_score()

    def _compute_score(self):
        deductions = 0
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        }

        for issue in self.issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1
            if issue.severity == Severity.CRITICAL:
                deductions += 25
            elif issue.severity == Severity.HIGH:
                deductions += 12
            elif issue.severity == Severity.MEDIUM:
                deductions += 5
            elif issue.severity == Severity.LOW:
                deductions += 2

        score = max(0, 100 - deductions)

        if score >= 95:
            grade = "A+"
            status_label = "🧊 Crystal Sober (Production Ready)"
            color = "green"
        elif score >= 80:
            grade = "B"
            status_label = "☕ Mild Buzz (Minor Slop Detected)"
            color = "cyan"
        elif score >= 60:
            grade = "C"
            status_label = "🍸 Noticeable Hangover (Review Required)"
            color = "yellow"
        else:
            grade = "F"
            status_label = "🚨 Complete Blackout (Do NOT Deploy)"
            color = "red"

        return score, grade, status_label, color

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.LOW)

    @property
    def auto_fixable_count(self) -> int:
        return sum(1 for i in self.issues if i.auto_fixable)

    def to_dict(self) -> Dict:
        return {
            "sober_score": self.score,
            "grade": self.grade,
            "status": self.status_label,
            "files_scanned": self.files_scanned,
            "duration_seconds": round(self.duration_seconds, 3),
            "counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "auto_fixable": self.auto_fixable_count,
            },
            "issues": [i.to_dict() for i in self.issues],
        }
