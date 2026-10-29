"""
Detector for Code Duplication and "Re-inventing the Wheel" Anti-patterns.
Catches duplicate functions and redundant helper implementations created across files by AI.
"""

import ast
import re
from pathlib import Path

from sober.core.scanner import FileToAudit
from sober.detectors import Issue, Severity


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
            # function foo(...) or const foo = (...) => ...
            m_fn = re.match(r'^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\(', line)
            if m_fn:
                functions.append((m_fn.group(1), idx))
            m_const = re.match(r'^\s*(?:export\s+)?const\s+([A-Za-z0-9_]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>', line)
            if m_const:
                functions.append((m_const.group(1), idx))
    return functions


def audit_duplicates(files: list[FileToAudit], project_root: Path) -> list[Issue]:
    """Scan across audited files to detect duplicated function names and definitions."""
    issues = []
    # Map function_name -> list of (file_rel, line_num)
    registry: dict[str, list[tuple[str, int]]] = {}

    # Common generic lifecycle/test names to ignore
    IGNORED_NAMES = {
        "__init__", "setUp", "tearDown", "test_", "main", "render",
        "toString", "toJSON", "handler", "validate", "get", "post", "put", "delete",
        "to_dict", "dict", "parse", "format", "load", "save", "run"
    }

    for file_audit in files:
        ext = file_audit.extension
        code = file_audit.read_text()
        if not code:
            continue
        file_rel = str(file_audit.path.relative_to(project_root) if file_audit.path.is_relative_to(project_root) else file_audit.path)
        sigs = extract_function_signatures(code, ext)

        for fn_name, line_num in sigs:
            if fn_name in IGNORED_NAMES or fn_name.startswith("test_"):
                continue
            if fn_name not in registry:
                registry[fn_name] = []
            registry[fn_name].append((file_rel, line_num))

    for fn_name, occurrences in registry.items():
        if len(occurrences) > 1:
            # Found in multiple different files
            files_involved = {loc[0] for loc in occurrences}
            if len(files_involved) > 1:
                first_file, first_line = occurrences[0]
                for file_rel, line_num in occurrences[1:]:
                    issues.append(
                        Issue(
                            category="Redundant Duplication",
                            title=f"Duplicated function definition '{fn_name}'",
                            description=f"Function '{fn_name}' is declared in '{file_rel}' (line {line_num}) but already exists in '{first_file}' (line {first_line}). AI often re-implements existing utilities.",
                            severity=Severity.MEDIUM,
                            file_path=file_rel,
                            line_number=line_num,
                            code_snippet=f"def {fn_name}(...)" if file_rel.endswith(".py") else f"function {fn_name}(...)",
                            fix_suggestion=f"Import and reuse '{fn_name}' from '{first_file}' instead of re-declaring.",
                        )
                    )

    return issues
