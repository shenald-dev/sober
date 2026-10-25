"""Detectors for AI-introduced anti-patterns, hallucinations, and risks."""

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Issue:
    def __init__(
        self,
        category: str,
        title: str,
        description: str,
        severity: Severity,
        file_path: str,
        line_number: int = 1,
        code_snippet: str = "",
        fix_suggestion: str = "",
        auto_fixable: bool = False,
    ):
        self.category = category
        self.title = title
        self.description = description
        self.severity = severity
        self.file_path = file_path
        self.line_number = line_number
        self.code_snippet = code_snippet
        self.fix_suggestion = fix_suggestion
        self.auto_fixable = auto_fixable

    def to_dict(self):
        return {
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "fix_suggestion": self.fix_suggestion,
            "auto_fixable": self.auto_fixable,
        }
