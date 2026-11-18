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
        rule_id: str = "",
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
        self.rule_id = rule_id

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
            "rule_id": self.rule_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Issue":
        return cls(
            category=data["category"],
            title=data["title"],
            description=data["description"],
            severity=Severity(data["severity"]),
            file_path=data["file_path"],
            line_number=data.get("line_number", 1),
            code_snippet=data.get("code_snippet", ""),
            fix_suggestion=data.get("fix_suggestion", ""),
            auto_fixable=data.get("auto_fixable", False),
            rule_id=data.get("rule_id", ""),
        )
