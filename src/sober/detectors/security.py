"""
Detector for AI-introduced Security Vulnerabilities and Secret Leaks.
Flags hardcoded API keys, shell injection vectors, TLS disables, and dangerous execution calls.
"""

import re
from pathlib import Path

from sober.core.scanner import FileToAudit
from sober.detectors import Issue, Severity

SECRET_PATTERNS = [
    (re.compile(r'sk-[A-Za-z0-9_-]{32,}'), "OpenAI / LLM API Key leaked"),
    (re.compile(r'sk-ant-[A-Za-z0-9_-]{32,}'), "Anthropic API Key leaked"),
    (re.compile(r'AIzaSy[A-Za-z0-9_-]{33}'), "Google Gemini / Cloud API Key leaked"),
    (re.compile(r'hf_[A-Za-z0-9]{34,}'), "Hugging Face Access Token leaked"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "GitHub Personal Access Token leaked"),
    (re.compile(r'github_pat_[A-Za-z0-9_]{82}'), "GitHub Fine-Grained Token leaked"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID leaked"),
    (re.compile(r'(?:sk|rk)_live_[0-9a-zA-Z]{24,}'), "Stripe Live Secret Key leaked"),
    (re.compile(r'pcsk_[A-Za-z0-9_]{40,}'), "Pinecone API Key leaked"),
    (re.compile(r'xox[baprs]-[0-9a-zA-Z-]{24,}'), "Slack Token leaked"),
    (re.compile(r'r8_[0-9a-zA-Z]{37}'), "Replicate API Token leaked"),
    (re.compile(r're_[0-9a-zA-Z]{24,}'), "Resend API Key leaked"),
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), "Raw Private Cryptographic Key embedded"),
    (re.compile(r'''(?i)(?:api_key|apikey|secret_key|auth_token)\s*=\s*['"][A-Za-z0-9_\-\.]{24,}['"]'''), "Hardcoded API secret token"),
]

INJECTION_PATTERNS = [
    (re.compile(r'subprocess\.(?:call|Popen|run)\s*\([^)]*shell\s*=\s*True[^)]*\)', re.IGNORECASE), "Shell=True command execution (Command Injection risk)"),
    (re.compile(r'\beval\s*\('), "Unsafe eval() execution"),
    (re.compile(r'\bexec\s*\('), "Unsafe exec() dynamic code execution"),
    (re.compile(r'''f["']SELECT\s+.*WHERE\s+.*\{[^}]+\}''', re.IGNORECASE), "Unparameterized f-string SQL query (SQL Injection risk)"),
    (re.compile(r'''["']SELECT\s+.*WHERE\s+.*['"]\s*\+''', re.IGNORECASE), "Concatenated raw SQL query (SQL Injection risk)"),
    (re.compile(r'pickle\.(?:loads?|load)\s*\(', re.IGNORECASE), "Unsafe pickle deserialization (Arbitrary Code Execution risk)"),
    (re.compile(r'yaml\.(?:unsafe_load|load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader)\))', re.IGNORECASE), "Unsafe YAML deserialization"),
    (re.compile(r'(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\'"]?0[\'"]?)', re.IGNORECASE), "Disabled TLS/SSL Certificate Verification (Man-in-the-Middle risk)"),
    (re.compile(r'jwt\.(?:sign|encode)\s*\([^)]*[\'"](?:secret|mysecret|test|changeme|123456?)[\'"]', re.IGNORECASE), "Hardcoded trivial JWT secret"),
]


def audit_security(
    file_audit: FileToAudit,
    project_root: Path,
    custom_secret_patterns: list[dict[str, str]] | None = None,
) -> list[Issue]:
    """Scan file for secrets, API keys, shell injections, and unsafe code patterns."""
    issues = []
    code = file_audit.read_text()
    if not code:
        return issues

    file_rel = str(file_audit.path.relative_to(project_root) if file_audit.path.is_relative_to(project_root) else file_audit.path)
    lines = code.splitlines()

    # Compile any user-defined secret patterns
    active_secret_patterns = list(SECRET_PATTERNS)
    if custom_secret_patterns:
        for item in custom_secret_patterns:
            name = item.get("name", "Custom Secret Token")
            regex_str = item.get("pattern")
            if regex_str:
                try:
                    active_secret_patterns.append((re.compile(regex_str), name))
                except re.error:
                    continue

    for idx, line in enumerate(lines, start=1):
        if file_audit.diff_lines and idx not in file_audit.diff_lines:
            continue

        stripped = line.strip()

        # 1. Hardcoded Secrets & Tokens
        for pattern, title in active_secret_patterns:
            match = pattern.search(stripped)
            if match:
                matched_str = match.group(0)
                masked = matched_str[:6] + "..." + matched_str[-4:] if len(matched_str) > 10 else "****"
                issues.append(
                    Issue(
                        category="Security & Secrets",
                        title=title,
                        description=f"Potential credential or API key ({masked}) committed directly into source code.",
                        severity=Severity.CRITICAL,
                        file_path=file_rel,
                        line_number=idx,
                        code_snippet=line.replace(matched_str, masked),
                        fix_suggestion="Move credential to an environment variable (.env) and add to .gitignore.",
                    )
                )

        # 2. Vulnerability Vectors
        for pattern, title in INJECTION_PATTERNS:
            if pattern.search(stripped):
                # Don't flag if line is a comment or a regex definition
                if stripped.startswith(("#", "//", "/*", "*")) or "re.compile" in stripped:
                    continue
                issues.append(
                    Issue(
                        category="Vulnerability Vector",
                        title=title,
                        description=f"Insecure pattern introduced by AI: {title}.",
                        severity=Severity.HIGH,
                        file_path=file_rel,
                        line_number=idx,
                        code_snippet=stripped,
                        fix_suggestion="Use parameterized execution or safe library methods.",
                    )
                )

    return issues
