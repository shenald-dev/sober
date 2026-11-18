"""
Detector for AI-introduced Security Vulnerabilities and Secret Leaks.
Flags hardcoded API keys, shell injection vectors, TLS disables, and dangerous execution calls.

Every secret matched on a line is masked in all report surfaces (snippet, JSON, SARIF,
Markdown, MCP), so a line containing multiple credentials never leaks a sibling secret.
"""

import re
from pathlib import Path

from sober.core.context import FileContext
from sober.core.scanner import FileToAudit
from sober.detectors import Issue, Severity

SECRET_PATTERNS = [
    (re.compile(r'sk-[A-Za-z0-9_-]{32,}'), "OpenAI / LLM API Key leaked"),
    (re.compile(r'sk-ant-[A-Za-z0-9_-]{32,}'), "Anthropic API Key leaked"),
    (re.compile(r'AIzaSy[A-Za-z0-9_-]{33}'), "Google Gemini / Cloud API Key leaked"),
    (re.compile(r'gsk_[A-Za-z0-9]{48}'), "Groq API Key leaked"),
    (re.compile(r'sbp_[A-Za-z0-9]{40}'), "Supabase Secret / Service Role Key leaked"),
    (re.compile(r'hf_[A-Za-z0-9]{34,}'), "Hugging Face Access Token leaked"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "GitHub Personal Access Token leaked"),
    (re.compile(r'github_pat_[A-Za-z0-9_]{82}'), "GitHub Fine-Grained Token leaked"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID leaked"),
    (re.compile(r'(?:sk|rk)_live_[0-9a-zA-Z]{24,}'), "Stripe Live Secret Key leaked"),
    (re.compile(r'pcsk_[A-Za-z0-9_]{40,}'), "Pinecone API Key leaked"),
    (re.compile(r'xox[baprs]-[0-9a-zA-Z-]{24,}'), "Slack Token leaked"),
    (re.compile(r'r8_[0-9a-zA-Z]{37}'), "Replicate API Token leaked"),
    (re.compile(r're_[0-9a-zA-Z]{24,}'), "Resend API Key leaked"),
    (re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'), "SendGrid API Key leaked"),
    (re.compile(r'https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,12}/B[0-9A-Za-z_]{8,12}/[0-9A-Za-z_]{20,26}'), "Slack Incoming Webhook URL leaked"),
    (re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,70}'), "Discord Webhook URL leaked"),
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----'), "Raw Private Cryptographic Key embedded"),
    (re.compile(r'''(?i)(?:api_key|apikey|secret_key|auth_token)\s*=\s*['"][A-Za-z0-9_\-\.]{24,}['"]'''), "Hardcoded API secret token"),
    (re.compile(r'''(?i)(?:password|passwd|pwd)\s*=\s*['"](?:admin|password|123456|root|admin123|changeme|default|test)['"]'''), "Hardcoded trivial / default password credential"),
]

INJECTION_PATTERNS = [
    (re.compile(r'subprocess\.(?:call|Popen|run)\s*\([^)]*shell\s*=\s*True[^)]*\)', re.IGNORECASE), "Shell=True command execution (Command Injection risk)"),
    (re.compile(r'(?<![\w.])eval\s*\('), "Unsafe eval() execution"),
    (re.compile(r'(?<![\w.])exec\s*\('), "Unsafe exec() dynamic code execution"),
    (re.compile(r'''f["']SELECT\s+.*WHERE\s+.*\{[^}]+\}''', re.IGNORECASE), "Unparameterized f-string SQL query (SQL Injection risk)"),
    (re.compile(r'''["']SELECT\s+.*WHERE\s+.*['"]\s*\+''', re.IGNORECASE), "Concatenated raw SQL query (SQL Injection risk)"),
    (re.compile(r'pickle\.(?:loads?|load)\s*\(', re.IGNORECASE), "Unsafe pickle deserialization (Arbitrary Code Execution risk)"),
    (re.compile(r'yaml\.(?:unsafe_load|load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|Loader)\))', re.IGNORECASE), "Unsafe YAML deserialization"),
    (re.compile(r'(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\'"]?0[\'"]?)', re.IGNORECASE), "Disabled TLS/SSL Certificate Verification (Man-in-the-Middle risk)"),
    (re.compile(r'jwt\.(?:sign|encode)\s*\([^)]*[\'"](?:secret|mysecret|test|changeme|123456?)[\'"]', re.IGNORECASE), "Hardcoded trivial JWT secret"),
]


def _mask_value(matched: str) -> str:
    return matched[:6] + "..." + matched[-4:] if len(matched) > 10 else "****"


def mask_secrets(line: str, patterns) -> str:
    """Mask every secret matched on a line so no sibling credential leaks."""
    masked = line
    for pattern, _title in patterns:
        for match in pattern.finditer(line):
            masked = masked.replace(match.group(0), _mask_value(match.group(0)))
    return masked


def audit_security(
    file_audit: FileToAudit,
    project_root: Path,
    custom_secret_patterns: list[dict[str, str]] | None = None,
    ctx: FileContext | None = None,
) -> list[Issue]:
    """Scan file for secrets, API keys, shell injections, and unsafe code patterns."""
    ctx = ctx or FileContext(file_audit)
    if not ctx.content:
        return []
    file_rel = ctx.rel_path(project_root)
    issues = []

    active_secret_patterns = list(SECRET_PATTERNS)
    secret_rule_ids = [f"SOBER-SEC{i:03d}" for i in range(1, len(SECRET_PATTERNS) + 1)]
    if custom_secret_patterns:
        for item in custom_secret_patterns:
            name = item.get("name", "Custom Secret Token")
            regex_str = item.get("pattern")
            if regex_str:
                try:
                    active_secret_patterns.append((re.compile(regex_str), name))
                    secret_rule_ids.append("SOBER-SEC900")
                except re.error:
                    continue

    for idx, line in enumerate(ctx.lines, start=1):
        if not ctx.in_diff(idx):
            continue
        stripped = line.strip()

        for (pattern, title), rule_id in zip(active_secret_patterns, secret_rule_ids):
            match = pattern.search(stripped)
            if match:
                matched_str = match.group(0)
                masked = _mask_value(matched_str)
                issues.append(
                    Issue(
                        category="Security & Secrets",
                        title=title,
                        description=f"Potential credential or API key ({masked}) committed directly into source code.",
                        severity=Severity.CRITICAL,
                        file_path=file_rel,
                        line_number=idx,
                        code_snippet=mask_secrets(line, active_secret_patterns),
                        fix_suggestion="Move credential to an environment variable (.env) and add to .gitignore.",
                        rule_id=rule_id,
                    )
                )

        for i, (pattern, title) in enumerate(INJECTION_PATTERNS, start=1):
            if pattern.search(stripped):
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
                        rule_id=f"SOBER-VUL{i:03d}",
                    )
                )

    return issues
