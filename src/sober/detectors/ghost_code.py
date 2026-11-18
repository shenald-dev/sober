"""
Detector for Ghost Code, AI Slop Residue, and Debug Debris.
Catches silent error swallows, abandoned stubs, and leftover console/print statements.
"""

import ast
import logging
import re
from pathlib import Path

from sober.core.context import FileContext
from sober.core.scanner import FileToAudit
from sober.detectors import Issue, Severity

logger = logging.getLogger(__name__)

DEBUG_PRINT_PY = re.compile(
    r'^\s*print\s*\(\s*(f?["\'](DEBUG|TODO|HERE|test|\d{3,})|["\']-{3,}|1111+)', re.IGNORECASE
)
DEBUG_LOG_JS = re.compile(
    r'^\s*console\.(log|debug|warn)\s*\(\s*(["\'](DEBUG|HERE|test|\d{3,})|1111+)', re.IGNORECASE
)
DEBUGGER_JS = re.compile(r"^\s*debugger\s*;?", re.IGNORECASE)
MARKDOWN_FENCE = re.compile(r"^\s*```(?:[a-zA-Z0-9_-]+)?\s*$", re.IGNORECASE)

SILENT_EXCEPT_LINE_PY = re.compile(r"^\s*except(\s+[A-Za-z0-9_]+)?\s*:\s*pass\s*(#.*)?$")
SILENT_CATCH_JS = re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}")
SILENT_PROMISE_CATCH_JS = re.compile(
    r"\.catch\s*\(\s*(?:\(\s*\)\s*=>\s*\{\s*\}|\([^)]*\)\s*=>\s*\{\s*\})\s*\)"
)

STUB_PATTERNS = [
    (re.compile(r"raise\s+NotImplementedError(\(.*\))?", re.IGNORECASE),
     "NotImplementedError placeholder left in production path"),
    (re.compile(r'throw\s+new\s+Error\s*\(\s*["\']Not implemented["\']\s*\)', re.IGNORECASE),
     "Unimplemented Error stub"),
    (re.compile(r"#\s*(TODO|FIXME)\s*:\s*(implement|add logic|fill in|ai generated)", re.IGNORECASE),
     "Unresolved AI implementation TODO"),
    (re.compile(r"//\s*(TODO|FIXME)\s*:\s*(implement|add logic|fill in|ai generated)", re.IGNORECASE),
     "Unresolved AI implementation TODO"),
    (re.compile(r'return\s*\{\s*["\']mock["\']\s*:\s*(?:True|true)\s*\}', re.IGNORECASE),
     "Hardcoded mock return artifact"),
    (re.compile(r"^\s*pass\s*#\s*TODO", re.IGNORECASE), "Unfinished placeholder pass statement"),
]


def audit_ghost_code(file_audit: FileToAudit, project_root: Path,
                     ctx: FileContext | None = None) -> list[Issue]:
    """Audit file for ghost code, leftover debug statements, and incomplete AI stubs."""
    ctx = ctx or FileContext(file_audit)
    if not ctx.content:
        return []
    ext = ctx.extension
    file_rel = ctx.rel_path(project_root)
    issues = []
    if ext == ".py":
        tree = ctx.tree
        if tree is None:
            logger.debug("Failed to parse python file for ghost code check: %s", ctx.path)
        else:
            for node in ast.walk(tree):
                if (isinstance(node, ast.ExceptHandler) and len(node.body) == 1
                        and isinstance(node.body[0], ast.Pass)):
                    lineno = node.lineno
                    if ctx.in_diff(lineno):
                        issues.append(
                            Issue(
                                category="Silent Error Swallow",
                                title="Blank 'except: pass' block",
                                description="AI swallowed exceptions with a blank pass, concealing critical failures in production.",
                                severity=Severity.HIGH,
                                file_path=file_rel,
                                line_number=lineno,
                                code_snippet="except: pass",
                                fix_suggestion="Log exception or handle specific error type gracefully.",
                                rule_id="SOBER-GHO001",
                            )
                        )
    for idx, line in enumerate(ctx.lines, start=1):
        if not ctx.in_diff(idx):
            continue
        stripped = line.strip()
        if MARKDOWN_FENCE.match(stripped):
            issues.append(
                Issue(
                    category="AI Slop Residue",
                    title="Stray markdown code fence",
                    description="AI assistant markdown code block delimiter accidentally copy-pasted into source file.",
                    severity=Severity.LOW,
                    file_path=file_rel,
                    line_number=idx,
                    code_snippet=stripped,
                    fix_suggestion="Remove stray markdown code fence.",
                    auto_fixable=True,
                    rule_id="SOBER-GHO007",
                )
            )
        if ext == ".py" and DEBUG_PRINT_PY.match(stripped):
            issues.append(
                Issue(
                    category="Debug Debris",
                    title="Leftover debug print() statement",
                    description="AI-generated debug print statement left in source code.",
                    severity=Severity.LOW,
                    file_path=file_rel,
                    line_number=idx,
                    code_snippet=stripped,
                    fix_suggestion="Remove or replace with structured logging (logger.debug).",
                    auto_fixable=True,
                    rule_id="SOBER-GHO005",
                )
            )
        if ext in {".js", ".jsx", ".ts", ".tsx"}:
            if DEBUG_LOG_JS.match(stripped):
                issues.append(
                    Issue(
                        category="Debug Debris",
                        title="Leftover console.log() statement",
                        description="Temporary console.log left in production source by AI.",
                        severity=Severity.LOW,
                        file_path=file_rel,
                        line_number=idx,
                        code_snippet=stripped,
                        fix_suggestion="Remove debug log statement.",
                        auto_fixable=True,
                        rule_id="SOBER-GHO006",
                    )
                )
            elif DEBUGGER_JS.match(stripped):
                issues.append(
                    Issue(
                        category="Debug Debris",
                        title="Dangling debugger statement",
                        description="Active debugger breakpoint statement found in code.",
                        severity=Severity.HIGH,
                        file_path=file_rel,
                        line_number=idx,
                        code_snippet=stripped,
                        fix_suggestion="Remove debugger statement before deployment.",
                        auto_fixable=True,
                        rule_id="SOBER-GHO004",
                    )
                )
        if (ext == ".py" and SILENT_EXCEPT_LINE_PY.match(stripped)
                and not any(i.line_number == idx and i.category == "Silent Error Swallow" for i in issues)):
            issues.append(
                Issue(
                    category="Silent Error Swallow",
                    title="Blank 'except: pass' block",
                    description="AI swallowed exceptions without logging, concealing critical failures in production.",
                    severity=Severity.HIGH,
                    file_path=file_rel,
                    line_number=idx,
                    code_snippet=stripped,
                    fix_suggestion="Log exception or handle specific error type gracefully.",
                    rule_id="SOBER-GHO001",
                )
            )
        if ext in {".js", ".jsx", ".ts", ".tsx"}:
            if SILENT_CATCH_JS.search(stripped):
                issues.append(
                    Issue(
                        category="Silent Error Swallow",
                        title="Empty catch {} block",
                        description="Empty catch block silently discarding errors.",
                        severity=Severity.HIGH,
                        file_path=file_rel,
                        line_number=idx,
                        code_snippet=stripped,
                        fix_suggestion="Log error message or rethrow.",
                        rule_id="SOBER-GHO002",
                    )
                )
            elif SILENT_PROMISE_CATCH_JS.search(stripped):
                issues.append(
                    Issue(
                        category="Silent Error Swallow",
                        title="Empty .catch(() => {}) handler",
                        description="Empty promise rejection handler silently swallowing asynchronous errors.",
                        severity=Severity.HIGH,
                        file_path=file_rel,
                        line_number=idx,
                        code_snippet=stripped,
                        fix_suggestion="Add error handling or logging inside .catch().",
                        rule_id="SOBER-GHO003",
                    )
                )
        for pattern, desc in STUB_PATTERNS:
            if pattern.search(stripped):
                issues.append(
                    Issue(
                        category="Incomplete AI Stub",
                        title=desc,
                        description=f"Incomplete stub left by AI assistant: {desc}",
                        severity=Severity.MEDIUM,
                        file_path=file_rel,
                        line_number=idx,
                        code_snippet=stripped,
                        fix_suggestion="Implement production logic before merging.",
                        rule_id="SOBER-GHO008",
                    )
                )
    return issues
