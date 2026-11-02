"""
Sober Score engine - computes code sobriety metrics, health grades, risk summaries,
SARIF export for GitHub Code Scanning, and Markdown PR summaries.
"""

from sober.detectors import Issue, Severity


class SoberAuditReport:
    def __init__(self, issues: list[Issue], files_scanned: int, duration_seconds: float):
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

    def to_dict(self) -> dict:
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

    def to_sarif(self) -> dict:
        """Convert audit results to SARIF 2.1.0 format for GitHub Code Scanning."""
        sarif_level_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
        }

        results = []
        rules = {}

        for issue in self.issues:
            rule_id = issue.category.replace(" ", "-").upper()
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": issue.category,
                    "shortDescription": {"text": issue.category},
                    "fullDescription": {"text": f"SOBER check for {issue.category}"},
                    "defaultConfiguration": {"level": sarif_level_map.get(issue.severity, "warning")},
                }

            normalized_path = issue.file_path.replace("\\", "/")
            results.append({
                "ruleId": rule_id,
                "level": sarif_level_map.get(issue.severity, "warning"),
                "message": {"text": f"{issue.title}: {issue.description}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": normalized_path},
                        "region": {"startLine": max(1, issue.line_number)},
                    }
                }],
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "sober",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/shenald-dev/sober",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }],
        }

    def to_markdown(self) -> str:
        """Generate formatted GitHub Markdown report suitable for PR comments."""
        badge = "🟢" if self.score >= 95 else "🟡" if self.score >= 80 else "🔴"
        md = [
            f"## {badge} SOBER Audit Report — {self.score}% [{self.grade}]",
            f"**State:** {self.status_label}  ",
            f"*Scanned {self.files_scanned} files in {self.duration_seconds:.2f}s.*",
            "",
            "| Metric | Count |",
            "| :--- | :---: |",
            f"| 🚨 Critical | **{self.critical_count}** |",
            f"| ⚠️ High | **{self.high_count}** |",
            f"| 🟡 Medium | **{self.medium_count}** |",
            f"| 🧹 Low / Debris | **{self.low_count}** |",
            f"| 💊 Auto-Fixable | **{self.auto_fixable_count}** |",
            "",
        ]

        if not self.issues:
            md.append("✨ **No AI hallucinations, ghost code, or security vulnerabilities detected. Code is Crystal Sober!**")
        else:
            md.append("### 🔍 Issues Found")
            md.append("| Severity | Location | Category | Title |")
            md.append("| :---: | :--- | :--- | :--- |")
            for issue in self.issues:
                loc = f"`{issue.file_path}:{issue.line_number}`"
                md.append(f"| `{issue.severity.value}` | {loc} | {issue.category} | {issue.title} |")

        md.append("\n---")
        md.append("*Generated by [sober](https://github.com/shenald-dev/sober) — The Vibe Coding Hangover Cure.*")
        return "\n".join(md)
