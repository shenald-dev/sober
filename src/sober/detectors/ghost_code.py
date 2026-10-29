"""
Detector for Ghost Code, AI Slop Residue, and Debug Debris.
Catches silent error swallows, abandoned stubs, and leftover console/print statements.
"""

import ast
import re
from pathlib import Path

from sober.core.scanner import FileToAudit
from sober.detectors import Issue, Severity

# Regex patterns for debug debris
DEBUG_PRINT_PY = re.compile(r'^\s*print\s*\(\s*(f?["\'](DEBUG|TODO|HERE|test|\d{3,})|["\']-{3,}|1111+)', re.IGNORECASE)
DEBUG_LOG_JS = re.compile(r'^\s*console\.(log|debug|warn)\s*\(\s*(["\'](DEBUG|HERE|test|\d{3,})|1111+)', re.IGNORECASE)
DEBUGGER_JS = re.compile(r'^\s*debugger\s*;?', re.IGNORECASE)

# Silent error swallow patterns
SILENT_EXCEPT_LINE_PY = re.compile(r'^\s*except(\s+[A-Za-z0-9_]+)?\s*:\s*pass\s*(#.*)?$')
SILENT_CATCH_JS = re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}')

# Incomplete AI stubs
STUB_PATTERNS = [
    (re.compile(r'raise\s+NotImplementedError(\(.*\))?', re.IGNORECASE), "NotImplementedError placeholder left in production path"),
    (re.compile(r'throw\s+new\s+Error\s*\(\s*["\']Not implemented["\']\s*\)', re.IGNORECASE), "Unimplemented Error stub"),
    (re.compile(r'#\s*(TODO|FIXME)\s*:\s*(implement|add logic|fill in|ai generated)', re.IGNORECASE), "Unresolved AI implementation TODO"),
    (re.compile(r'//\s*(TODO|FIXME)\s*:\s*(implement|add logic|fill in|ai generated)', re.IGNORECASE), "Unresolved AI implementation TODO"),
    (re.compile(r'return\s*\{\s*["\']mock["\']\s*:\s*True\s*\}', re.IGNORECASE), "Hardcoded mock return artifact"),
]


def audit_ghost_code(file_audit: FileToAudit, project_root: Path) -> list[Issue]:
    """Audit file for ghost code, leftover debug statements, and incomplete AI stubs."""
    issues = []
    code = file_audit.read_text()
    if not code:
        return issues

    ext = file_audit.extension
    file_rel = str(file_audit.path.relative_to(project_root) if file_audit.path.is_relative_to(project_root) else file_audit.path)
    lines = code.splitlines()

    # 1. Python AST-based checks for silent except blocks
    if ext == ".py":
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                # Check if handler body only has `pass`
                if isinstance(node, ast.ExceptHandler) and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                    lineno = node.lineno
                    if not file_audit.diff_lines or lineno in file_audit.diff_lines:
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
                            )
                        )
        except (SyntaxError, ValueError):
            return issues

    # 2. Line-by-line checks
    for idx, line in enumerate(lines, start=1):
        if file_audit.diff_lines and idx not in file_audit.diff_lines:
            continue

        stripped = line.strip()

        # Debug Statements
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
                    fix_suggestion="Remove or replace with structured logging (logging.debug).",
                    auto_fixable=True,
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
                    )
                )

        # Silent Error Swallows for single-line python or JS
        if ext == ".py" and SILENT_EXCEPT_LINE_PY.match(stripped) and not any(i.line_number == idx and i.category == "Silent Error Swallow" for i in issues):
            # Only add if not already captured by AST
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
                )
            )

        if ext in {".js", ".jsx", ".ts", ".tsx"} and SILENT_CATCH_JS.search(stripped):
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
                )
            )

        # AI Stubs & Incomplete Logic
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
                    )
                )

    return issues
