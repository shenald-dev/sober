"""
Detector for Dangerous AI Code Patterns, Hangover Antipatterns, and LLM Injection Risks.
Catches omitted HTTP timeouts, pseudo-random security tokens, prompt injection vectors,
and unconstrained memory reads frequently introduced by AI coding assistants.
"""

import ast
import re
from pathlib import Path

from sober.core.scanner import FileToAudit
from sober.detectors import Issue, Severity

# Regex patterns for Python and JS/TS HTTP calls lacking timeouts
JS_FETCH_CALL_REGEX = re.compile(
    r'\bfetch\s*\(\s*[^,\)]+\s*\)',
    re.IGNORECASE,
)

# Regex for insecure randomness in security contexts
INSECURE_RANDOM_REGEX = re.compile(
    r'(?:token|secret|key|password|nonce|session_id|auth_code)\s*=\s*.*(?:random\.(?:random|randint|choice|choices)|Math\.random\s*\(\s*\))',
    re.IGNORECASE,
)

# Regex for direct prompt injection in LLM messages
PROMPT_INJECTION_REGEX = re.compile(
    r'''(?:messages\s*=\s*\[.*["']content["']\s*:\s*f["'][^"']*(?:\{[a-zA-Z0-9_]+\})|prompt\s*=\s*f["'][^"']*\{[a-zA-Z0-9_]+\})''',
    re.DOTALL | re.IGNORECASE,
)

# Regex for client-side leaked system instructions
LEAKED_SYSTEM_PROMPT_REGEX = re.compile(
    r'''(?:system_prompt|instructions|systemPrompt)\s*:\s*["'](?:You are a (?:confidential|secret|proprietary|internal)|Do not reveal|Never disclose)[^"']*["']''',
    re.IGNORECASE,
)


def _check_python_ast_antipatterns(code: str, file_rel: str, diff_lines: set[int]) -> list[Issue]:
    """Inspect Python AST for missing timeouts, insecure randomness, and prompt injection."""
    issues = []
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return issues

    for node in ast.walk(tree):
        # 1. Missing HTTP timeout in requests / httpx calls
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id in {"requests", "httpx"} and node.func.attr in {
                    "get", "post", "put", "patch", "delete", "request"
                }:
                    func_name = f"{node.func.value.id}.{node.func.attr}"

            if func_name:
                lineno = node.lineno
                if not diff_lines or lineno in diff_lines:
                    has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
                    if not has_timeout:
                        issues.append(
                            Issue(
                                category="Reliability Antipattern",
                                title=f"Omitted HTTP Timeout in '{func_name}'",
                                description=(
                                    f"AI generated '{func_name}()' without a timeout parameter. "
                                    "If the remote server stalls, this process will hang indefinitely."
                                ),
                                severity=Severity.HIGH,
                                file_path=file_rel,
                                line_number=lineno,
                                code_snippet=f"{func_name}(..., timeout=30.0)",
                                fix_suggestion="Add explicit timeout: e.g. timeout=30.0 or httpx.Timeout(10.0)",
                                auto_fixable=True,
                            )
                        )

        # 2. Insecure randomness for security-sensitive tokens
        if isinstance(node, ast.Assign):
            is_security_var = False
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name_lower = target.id.lower()
                    if any(term in name_lower for term in ["token", "secret", "password", "nonce", "session_id", "api_key"]):
                        is_security_var = True
                        break

            if is_security_var:
                lineno = node.lineno
                if not diff_lines or lineno in diff_lines:
                    # Check if value uses random module instead of secrets
                    uses_insecure_random = False
                    for child in ast.walk(node.value):
                        if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                            if child.value.id == "random" and child.attr in {"random", "randint", "choice", "choices", "sample"}:
                                uses_insecure_random = True
                                break

                    if uses_insecure_random:
                        issues.append(
                            Issue(
                                category="Cryptographic Antipattern",
                                title="Insecure Pseudo-Random Token Generation",
                                description=(
                                    "AI used 'random' module for a security-sensitive credential/token. "
                                    "'random' is pseudo-random and cryptographically insecure."
                                ),
                                severity=Severity.HIGH,
                                file_path=file_rel,
                                line_number=lineno,
                                code_snippet="secrets.token_urlsafe(32)",
                                fix_suggestion="Use 'import secrets; secrets.token_urlsafe(32)' or 'secrets.token_hex(16)'.",
                            )
                        )

    return issues


def audit_antipatterns(file_audit: FileToAudit, project_root: Path) -> list[Issue]:
    """Scan file for dangerous AI code patterns, missing timeouts, and LLM injection vectors."""
    issues = []
    code = file_audit.read_text()
    if not code:
        return issues

    ext = file_audit.extension
    file_rel = str(
        file_audit.path.relative_to(project_root)
        if file_audit.path.is_relative_to(project_root)
        else file_audit.path
    )
    diff_lines = file_audit.diff_lines
    lines = code.splitlines()

    # 1. Python AST Inspection
    if ext == ".py":
        issues.extend(_check_python_ast_antipatterns(code, file_rel, diff_lines))

    # 2. Line-by-line & Regex Inspection (all supported extensions)
    for idx, line in enumerate(lines, start=1):
        if diff_lines and idx not in diff_lines:
            continue

        stripped = line.strip()
        if stripped.startswith(("#", "//", "/*", "*")):
            continue

        # Insecure randomness in JS/TS
        if ext in {".js", ".jsx", ".ts", ".tsx"} and INSECURE_RANDOM_REGEX.search(stripped):
            issues.append(
                Issue(
                    category="Cryptographic Antipattern",
                    title="Insecure Math.random() in Security Context",
                    description="AI generated security token or secret key using Math.random().",
                    severity=Severity.HIGH,
                    file_path=file_rel,
                    line_number=idx,
                    code_snippet=stripped,
                    fix_suggestion="Use 'crypto.randomUUID()' or 'crypto.getRandomValues()'.",
                )
            )

        # Missing timeout in JS/TS bare fetch()
        if ext in {".js", ".jsx", ".ts", ".tsx"}:
            if JS_FETCH_CALL_REGEX.search(stripped):
                issues.append(
                    Issue(
                        category="Reliability Antipattern",
                        title="Omitted Timeout in JavaScript fetch()",
                        description="AI invoked fetch() without an AbortSignal timeout, risking hanging connections.",
                        severity=Severity.MEDIUM,
                        file_path=file_rel,
                        line_number=idx,
                        code_snippet=stripped,
                        fix_suggestion="Add timeout: fetch(url, { signal: AbortSignal.timeout(10000) })",
                    )
                )

        # Client-side leaked system prompt
        if ext in {".js", ".jsx", ".ts", ".tsx"} and LEAKED_SYSTEM_PROMPT_REGEX.search(stripped):
            issues.append(
                Issue(
                    category="AI Safety & IP Leakage",
                    title="Client-Side Exposed System Instructions",
                    description="Confidential system instructions or persona prompt embedded in client-side script.",
                    severity=Severity.HIGH,
                    file_path=file_rel,
                    line_number=idx,
                    code_snippet=stripped,
                    fix_suggestion="Move system prompts to backend server routes; never bundle in client-facing code.",
                )
            )

    # 3. Multi-line direct prompt injection search
    for match in PROMPT_INJECTION_REGEX.finditer(code):
        start_char = match.start()
        lineno = code.count("\n", 0, start_char) + 1
        if not diff_lines or lineno in diff_lines:
            matched_snippet = match.group(0)[:60]
            issues.append(
                Issue(
                    category="LLM Prompt Injection Risk",
                    title="Direct Unsanitized Prompt Interpolation",
                    description=(
                        "AI directly interpolated variables into an LLM prompt template without sanitization, "
                        "exposing the application to prompt injection and jailbreak attacks."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_rel,
                    line_number=lineno,
                    code_snippet=matched_snippet,
                    fix_suggestion="Validate, delimit (e.g. <user_input>), or separate untrusted inputs using structured messages.",
                )
            )

    return issues
