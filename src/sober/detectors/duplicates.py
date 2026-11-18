"""
Detector for Code Duplication and "Re-inventing the Wheel" Anti-patterns.

Uses normalized AST body hashing (Python) and normalized body text hashing (JS/TS)
so that only genuinely equivalent helpers are flagged, rather than any two functions
that merely share a name.
"""

import ast
import hashlib
import re
from pathlib import Path

from sober.core.context import FileContext
from sober.core.scanner import FileToAudit
from sober.detectors import Issue, Severity

IGNORED_NAMES = {
    "__init__", "setUp", "tearDown", "test_", "main", "render",
    "toString", "toJSON", "handler", "validate", "get", "post", "put", "delete",
    "to_dict", "dict", "parse", "format", "load", "save", "run",
}


def extract_function_signatures(code: str, ext: str) -> list[tuple[str, int]]:
    """Extract declared function and method names with their line numbers."""
    functions = []
    if ext == ".py":
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append((node.name, node.lineno))
        except (SyntaxError, ValueError):
            for idx, line in enumerate(code.splitlines(), start=1):
                m = re.match(r'^\s*def\s+([A-Za-z0-9_]+)\s*\(', line)
                if m:
                    functions.append((m.group(1), idx))
    elif ext in {".js", ".jsx", ".ts", ".tsx"}:
        for idx, line in enumerate(code.splitlines(), start=1):
            m_fn = re.match(r'^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\(', line)
            if m_fn:
                functions.append((m_fn.group(1), idx))
            m_const = re.match(r'^\s*(?:export\s+)?const\s+([A-Za-z0-9_]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>', line)
            if m_const:
                functions.append((m_const.group(1), idx))
    return functions


def _strip_docstring(body: list) -> list:
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        return body[1:]
    return body


def _py_body(node: ast.AST) -> tuple[str, bool] | None:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    body = _strip_docstring(list(node.body))
    if not body:
        return None
    dumped = ast.dump(ast.Module(body=body, type_ignores=[]), annotate_fields=False)
    substantial = len(body) >= 2
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest(), substantial


def _js_body(code: str, lineno: int) -> tuple[str, bool] | None:
    lines = code.splitlines()
    if lineno > len(lines):
        return None
    tail = "\n".join(lines[lineno - 1:])
    start = tail.find("{")
    if start == -1:
        return None
    depth = 0
    end = -1
    for i in range(start, len(tail)):
        if tail[i] == "{":
            depth += 1
        elif tail[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end == -1:
        return None
    body = tail[start + 1:end]
    normalized = re.sub(r"//.*|/\*.*?\*/", "", body, flags=re.DOTALL)
    normalized = " ".join(normalized.split())
    if not normalized:
        return None
    substantial = len(normalized) >= 40 and normalized.count(";") >= 2
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest(), substantial


def _body_info(ctx: FileContext) -> dict[tuple[str, int], tuple[str, bool]]:
    result: dict[tuple[str, int], tuple[str, bool]] = {}
    if ctx.extension == ".py":
        tree = ctx.tree
        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    info = _py_body(node)
                    if info:
                        result[(node.name, node.lineno)] = info
    elif ctx.extension in {".js", ".jsx", ".ts", ".tsx"}:
        for name, lineno in extract_function_signatures(ctx.content, ctx.extension):
            info = _js_body(ctx.content, lineno)
            if info:
                result[(name, lineno)] = info
    return result


def audit_duplicates(files: list[FileToAudit], project_root: Path,
                     contexts: dict | None = None) -> list[Issue]:
    """Detect equivalent helper functions re-implemented across audited files."""
    issues = []
    by_name: dict[str, list[tuple[str, int, str | None]]] = {}
    by_body: dict[str, list[tuple[str, int, str]]] = {}

    for file_audit in files:
        ctx = (contexts or {}).get(file_audit.path) or FileContext(file_audit)
        if not ctx.content:
            continue
        file_rel = ctx.rel_path(project_root)
        sigs = extract_function_signatures(ctx.content, ctx.extension)
        info = _body_info(ctx)
        for name, lineno in sigs:
            if name in IGNORED_NAMES or name.startswith("test_"):
                continue
            entry = info.get((name, lineno))
            h = entry[0] if entry else None
            by_name.setdefault(name, []).append((file_rel, lineno, h))
            if entry and entry[1]:
                by_body.setdefault(entry[0], []).append((file_rel, lineno, name))

    reported: set[tuple[str, int]] = set()

    def emit(file_rel, lineno, name, other_file, other_line, other_name):
        if (file_rel, lineno) in reported:
            return
        reported.add((file_rel, lineno))
        snippet = f"def {name}(...)" if file_rel.endswith(".py") else f"function {name}(...)"
        issues.append(
            Issue(
                category="Redundant Duplication",
                title=f"Duplicated function definition '{name}'",
                description=(
                    f"Function '{name}' is declared in '{file_rel}' (line {lineno}) but an equivalent "
                    f"implementation already exists in '{other_file}' (line {other_line}). "
                    "AI often re-implements existing utilities."
                ),
                severity=Severity.MEDIUM,
                file_path=file_rel,
                line_number=lineno,
                code_snippet=snippet,
                fix_suggestion=f"Import and reuse '{other_name}' from '{other_file}' instead of re-declaring.",
                rule_id="SOBER-DUP001",
            )
        )

    for name, occ in by_name.items():
        if len({o[0] for o in occ}) < 2:
            continue
        first = occ[0]
        for other in occ[1:]:
            if other[0] == first[0]:
                continue
            if first[2] is not None and other[2] is not None and first[2] == other[2]:
                emit(other[0], other[1], name, first[0], first[1], name)

    for occ in by_body.values():
        if len({o[0] for o in occ}) < 2:
            continue
        first = occ[0]
        for other in occ[1:]:
            if other[0] == first[0] or other[2] == first[2]:
                continue
            emit(other[0], other[1], other[2], first[0], first[1], first[2])

    return issues
