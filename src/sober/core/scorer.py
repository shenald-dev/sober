"""
Sober Score engine - computes code sobriety metrics, health grades, risk summaries,
SARIF 2.1.0 export for GitHub Code Scanning, and Markdown PR summaries.
"""

from sober import __version__
from sober.core.rules import finding_fingerprint, get_rule
from sober.detectors import Issue, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


class SoberAuditReport:
    def __init__(self, issues: list[Issue], files_scanned: int, duration_seconds: float):
        self.issues = issues
        self.files_scanned = files_scanned
        self.duration_seconds = duration_seconds
        self.suppressed_count = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.score, self.grade, self.status_label, self.color = self._compute_score()

    def _compute_score(self):
        deductions = 0
        for issue in self.issues:
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
            grade, status_label, color = "A+", "🧊 Crystal Sober (Production Ready)", "green"
        elif score >= 80:
            grade, status_label, color = "B", "☕ Mild Buzz (Minor Slop Detected)", "cyan"
        elif score >= 60:
            grade, status_label, color = "C", "🍸 Noticeable Hangover (Review Required)", "yellow"
        else:
            grade, status_label, color = "F", "🚨 Complete Blackout (Do NOT Deploy)", "red"

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
            "schema_version": "3.0",
            "sober_score": self.score,
            "grade": self.grade,
            "status": self.status_label,
            "files_scanned": self.files_scanned,
            "duration_seconds": round(self.duration_seconds, 3),
            "suppressed": self.suppressed_count,
            "cache": {"hits": self.cache_hits, "misses": self.cache_misses},
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
        """Convert audit results to SARIF 2.1.0 for GitHub Code Scanning."""
        results = []
        rules: dict[str, dict] = {}

        for issue in self.issues:
            rule_id = issue.rule_id or issue.category.replace(" ", "-").upper()
            if rule_id not in rules:
                catalog_rule = get_rule(rule_id)
                if catalog_rule is not None:
                    rules[rule_id] = {
                        "id": rule_id,
                        "name": catalog_rule.title.replace(" ", ""),
                        "shortDescription": {"text": catalog_rule.title},
                        "fullDescription": {"text": catalog_rule.description},
                        "help": {"text": catalog_rule.help},
                        "defaultConfiguration": {"level": _SARIF_LEVEL.get(catalog_rule.severity, "warning")},
                        "properties": {
                            "security-severity": catalog_rule.security_severity,
                            "tags": list(catalog_rule.tags),
                        },
                    }
                else:
                    rules[rule_id] = {
                        "id": rule_id,
                        "name": issue.category,
                        "shortDescription": {"text": issue.category},
                        "fullDescription": {"text": f"SOBER check for {issue.category}"},
                        "defaultConfiguration": {"level": _SARIF_LEVEL.get(issue.severity, "warning")},
                        "properties": {"security-severity": "5.5"},
                    }

            results.append({
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(issue.severity, "warning"),
                "message": {"text": f"{issue.title}: {issue.description}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": issue.file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": max(1, issue.line_number)},
                    }
                }],
                "partialFingerprints": {
                    "soberFindingHash/v1": finding_fingerprint(rule_id, issue.file_path, issue.code_snippet),
                },
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "sober",
                        "version": __version__,
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
            md.append("| Severity | Rule | Location | Title |")
            md.append("| :---: | :--- | :--- | :--- |")
            for issue in self.issues:
                loc = f"`{issue.file_path}:{issue.line_number}`"
                md.append(f"| `{issue.severity.value}` | `{issue.rule_id}` | {loc} | {issue.title} |")

        md.append("\n---")
        md.append("*Generated by [sober](https://github.com/shenald-dev/sober) — The Vibe Coding Hangover Cure.*")
        return "\n".join(md)
