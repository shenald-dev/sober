"""
MCP tool definitions and handlers for SOBER.

All tool paths are confined to the server root (path-traversal protected). Read-only
tools are annotated readOnlyHint; the mutating cure tool is annotated destructiveHint
and defaults to dry_run. Outputs are sanitized by the detectors (secrets masked).
"""

from __future__ import annotations

from pathlib import Path

from sober.core.engine import AuditEngine
from sober.core.remediation import generate_agent_remediation_prompt
from sober.core.rules import all_rules
from sober.core.sanitizer import apply_cure
from sober.core.scanner import get_all_code_files, get_git_modified_files


def _summary_text(report) -> str:
    lines = [
        f"SOBER score: {report.score}% [{report.grade}] - {report.status_label}",
        f"Files scanned: {report.files_scanned} | suppressed: {report.suppressed_count}",
        f"Critical: {report.critical_count} High: {report.high_count} "
        f"Medium: {report.medium_count} Low: {report.low_count}",
    ]
    for issue in report.issues[:25]:
        lines.append(f"[{issue.severity.value}] {issue.rule_id} {issue.file_path}:{issue.line_number} {issue.title}")
    if len(report.issues) > 25:
        lines.append(f"...and {len(report.issues) - 25} more (see structuredContent).")
    return "\n".join(lines)


class Tool:
    def __init__(self, definition: dict, handler):
        self.definition = definition
        self._handler = handler

    @property
    def name(self) -> str:
        return self.definition["name"]

    def call(self, arguments: dict):
        return self._handler(arguments)


class ToolRegistry:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self._tools = {
            "sober_scan": Tool(self._scan_def(), self._scan),
            "sober_explain": Tool(self._explain_def(), self._explain),
            "sober_cure": Tool(self._cure_def(), self._cure),
            "sober_rules": Tool(self._rules_def(), self._rules),
        }

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def list(self) -> list[dict]:
        return [t.definition for t in self._tools.values()]

    def _resolve(self, rel) -> Path:
        if rel in (None, "", "."):
            return self.root
        if not isinstance(rel, str):
            raise ValueError("path must be a string")
        candidate = (self.root / rel).resolve()
        if not candidate.is_relative_to(self.root):
            raise ValueError("path escapes the server root")
        if not candidate.is_dir():
            raise ValueError("path is not a directory within the root")
        return candidate

    def _files(self, root: Path, scope: str):
        if scope == "all":
            return get_all_code_files(root)
        files = get_git_modified_files(root)
        return files or get_all_code_files(root)

    def _audit(self, args: dict):
        root = self._resolve(args.get("path"))
        scope = args.get("scope", "changes")
        if scope not in ("changes", "all"):
            raise ValueError("scope must be 'changes' or 'all'")
        offline = bool(args.get("offline", True))
        engine = AuditEngine(root, offline=offline, use_cache=True)
        return engine.audit(self._files(root, scope))

    def _scan_def(self) -> dict:
        return {
            "name": "sober_scan",
            "title": "Scan code for AI hangover defects",
            "description": "Audit a project for hallucinated dependencies, secret leaks, reliability antipatterns, ghost code and duplication. Returns a 0-100 sobriety score and structured findings with stable SOBER-* rule IDs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory relative to the server root (default: root)."},
                    "scope": {"type": "string", "enum": ["changes", "all"], "description": "Audit uncommitted changes (default) or all files."},
                    "offline": {"type": "boolean", "description": "Skip live registry queries (default true)."},
                },
                "additionalProperties": False,
            },
            "outputSchema": {
                "type": "object",
                "properties": {
                    "sober_score": {"type": "number"},
                    "grade": {"type": "string"},
                    "issues": {"type": "array"},
                },
                "required": ["sober_score", "grade", "issues"],
            },
            "annotations": {"readOnlyHint": True, "openWorldHint": False},
        }

    def _explain_def(self) -> dict:
        return {
            "name": "sober_explain",
            "title": "Generate agent remediation directive",
            "description": "Produce a high-density, surgical remediation prompt describing every defect with exact locations and prescribed fixes, suitable for an autonomous coding agent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "scope": {"type": "string", "enum": ["changes", "all"]},
                    "offline": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "openWorldHint": False},
        }

    def _cure_def(self) -> dict:
        return {
            "name": "sober_cure",
            "title": "Auto-cure debug debris and AI chatter",
            "description": "Strip leftover debug prints, console logs, debuggers, markdown fences and AI chatter. Defaults to dry_run=true (preview only); set dry_run=false to modify files.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "scope": {"type": "string", "enum": ["changes", "all"]},
                    "dry_run": {"type": "boolean", "description": "Preview changes without writing (default true)."},
                },
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True},
        }

    def _rules_def(self) -> dict:
        return {
            "name": "sober_rules",
            "title": "List SOBER rule catalog",
            "description": "Return the full catalog of SOBER detection rules with IDs, severities, security-severity scores and remediation help.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "openWorldHint": False},
        }

    def _scan(self, args: dict):
        report = self._audit(args)
        return report.to_dict(), _summary_text(report)

    def _explain(self, args: dict):
        report = self._audit(args)
        prompt = generate_agent_remediation_prompt(
            issues=report.issues, score=report.score, grade=report.grade,
            status_label=report.status_label, files_scanned=report.files_scanned)
        return {"sober_score": report.score, "grade": report.grade, "prompt": prompt}, prompt

    def _cure(self, args: dict):
        root = self._resolve(args.get("path"))
        scope = args.get("scope", "changes")
        if scope not in ("changes", "all"):
            raise ValueError("scope must be 'changes' or 'all'")
        dry_run = bool(args.get("dry_run", True))
        engine = AuditEngine(root, offline=True, use_cache=False)
        report = engine.audit(self._files(root, scope))
        fixable = [i for i in report.issues if i.auto_fixable]
        if dry_run:
            preview: dict[str, int] = {}
            for issue in fixable:
                preview[issue.file_path] = preview.get(issue.file_path, 0) + 1
            structured = {"dry_run": True, "would_cure": preview, "total": len(fixable)}
            text = f"DRY RUN: {len(fixable)} auto-fixable line(s) across {len(preview)} file(s). Set dry_run=false to apply."
            return structured, text
        cured = apply_cure(report.issues, root)
        structured = {"dry_run": False, "cured": cured, "total": sum(cured.values())}
        text = f"Cured {sum(cured.values())} line(s) across {len(cured)} file(s)."
        return structured, text

    def _rules(self, args: dict):
        rules = [r.to_dict() for r in all_rules()]
        text = "\n".join(f"{r['id']} [{r['severity']}] {r['title']}" for r in rules)
        return {"rules": rules, "count": len(rules)}, text
