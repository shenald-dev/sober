"""
Stable rule catalog for SOBER.

Every detector finding maps to an immutable rule identifier (e.g. ``SOBER-SEC007``).
Stable IDs power inline suppression (``# sober: ignore[SOBER-SEC007]``), SARIF rule
metadata, GitHub ``security-severity`` scoring and cross-run fingerprinting.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from sober.detectors import Severity

# GitHub code scanning maps numeric security-severity (CVSS-like) to labels:
# >9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, <=3.9 low.
SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: Severity
    description: str
    help: str
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def security_severity(self) -> str:
        return SECURITY_SEVERITY[self.severity]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "security_severity": self.security_severity,
            "description": self.description,
            "help": self.help,
            "tags": list(self.tags),
        }


def _r(rid, title, category, severity, description, help_text, *tags) -> Rule:
    return Rule(rid, title, category, severity, description, help_text, tuple(tags))


_RULES: list[Rule] = [
    _r("SOBER-HAL001", "Hallucinated dependency", "Hallucinated Dependency", Severity.CRITICAL,
       "Imported package does not exist on the public registry or local manifests.",
       "Remove the import, install the real package, or declare it in allowed_packages.",
       "supply-chain", "hallucination"),
    _r("SOBER-HAL002", "Slopsquatting similarity risk", "Slopsquatting Risk", Severity.CRITICAL,
       "Imported name closely resembles a popular package (Damerau-Levenshtein distance <= 2).",
       "Verify the intended package name; correct typos before installing.",
       "supply-chain", "slopsquatting"),
    _r("SOBER-SEC001", "OpenAI / LLM API key leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded OpenAI-style secret key detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC002", "Anthropic API key leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded Anthropic secret key detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC003", "Google Gemini / Cloud API key leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded Google API key detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC004", "Groq API key leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded Groq API key detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC005", "Supabase service key leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded Supabase secret/service-role key detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC006", "Hugging Face token leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded Hugging Face access token detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC007", "GitHub personal access token leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded GitHub classic PAT detected.", "Rotate the token and load it from the environment.", "secret"),
    _r("SOBER-SEC008", "GitHub fine-grained token leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded GitHub fine-grained PAT detected.", "Rotate the token and load it from the environment.", "secret"),
    _r("SOBER-SEC009", "AWS access key ID leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded AWS access key ID detected.", "Use IAM roles or environment credentials.", "secret"),
    _r("SOBER-SEC010", "Stripe live secret key leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded Stripe live secret key detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC011", "Pinecone API key leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded Pinecone API key detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC012", "Slack token leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded Slack token detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC013", "Replicate API token leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded Replicate API token detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC014", "Resend API key leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded Resend API key detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC015", "SendGrid API key leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded SendGrid API key detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC016", "Slack incoming webhook leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded Slack incoming webhook URL detected.", "Move the webhook to an environment variable.", "secret"),
    _r("SOBER-SEC017", "Discord webhook leaked", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded Discord webhook URL detected.", "Move the webhook to an environment variable.", "secret"),
    _r("SOBER-SEC018", "Private cryptographic key embedded", "Security & Secrets", Severity.CRITICAL,
       "Raw private key material embedded in source.", "Store keys in a secret manager; never commit them.", "secret"),
    _r("SOBER-SEC019", "Hardcoded API secret token", "Security & Secrets", Severity.CRITICAL,
       "Generic hardcoded API secret assignment detected.", "Move the credential to an environment variable.", "secret"),
    _r("SOBER-SEC020", "Trivial / default password", "Security & Secrets", Severity.CRITICAL,
       "Hardcoded trivial or default password detected.", "Use a strong secret from the environment.", "secret"),
    _r("SOBER-SEC900", "Custom secret pattern match", "Security & Secrets", Severity.CRITICAL,
       "Matched a user-defined custom secret pattern.", "Remove the credential from source.", "secret", "custom"),
    _r("SOBER-VUL001", "shell=True command execution", "Vulnerability Vector", Severity.HIGH,
       "subprocess invoked with shell=True enables command injection.", "Pass an argument list without shell=True.", "injection"),
    _r("SOBER-VUL002", "Unsafe eval() execution", "Vulnerability Vector", Severity.HIGH,
       "eval() executes arbitrary code.", "Avoid eval; use safe parsers such as ast.literal_eval.", "injection"),
    _r("SOBER-VUL003", "Unsafe exec() execution", "Vulnerability Vector", Severity.HIGH,
       "exec() executes arbitrary dynamic code.", "Avoid exec; refactor to explicit logic.", "injection"),
    _r("SOBER-VUL004", "f-string SQL injection", "Vulnerability Vector", Severity.HIGH,
       "SQL built via f-string interpolation.", "Use parameterized queries.", "injection", "sql"),
    _r("SOBER-VUL005", "Concatenated SQL injection", "Vulnerability Vector", Severity.HIGH,
       "SQL built via string concatenation.", "Use parameterized queries.", "injection", "sql"),
    _r("SOBER-VUL006", "Unsafe pickle deserialization", "Vulnerability Vector", Severity.HIGH,
       "pickle load can execute arbitrary code.", "Use a safe format such as JSON.", "deserialization"),
    _r("SOBER-VUL007", "Unsafe YAML deserialization", "Vulnerability Vector", Severity.HIGH,
       "yaml unsafe loader can execute arbitrary code.", "Use yaml.safe_load.", "deserialization"),
    _r("SOBER-VUL008", "Disabled TLS verification", "Vulnerability Vector", Severity.HIGH,
       "TLS/SSL certificate verification disabled.", "Enable certificate verification.", "tls"),
    _r("SOBER-VUL009", "Trivial JWT secret", "Vulnerability Vector", Severity.HIGH,
       "JWT signed with a trivial hardcoded secret.", "Use a strong secret from the environment.", "jwt"),
    _r("SOBER-REL001", "Omitted HTTP timeout (Python)", "Reliability Antipattern", Severity.HIGH,
       "requests/httpx call without a timeout can hang forever.", "Add an explicit timeout argument.", "reliability"),
    _r("SOBER-REL002", "Omitted fetch timeout (JS)", "Reliability Antipattern", Severity.MEDIUM,
       "fetch() without an AbortSignal timeout can hang.", "Use AbortSignal.timeout(...).", "reliability"),
    _r("SOBER-CRY001", "Insecure pseudo-random token (Python)", "Cryptographic Antipattern", Severity.HIGH,
       "random module used for a security-sensitive value.", "Use the secrets module.", "crypto"),
    _r("SOBER-CRY002", "Insecure Math.random() token (JS)", "Cryptographic Antipattern", Severity.HIGH,
       "Math.random() used for a security-sensitive value.", "Use crypto.randomUUID()/getRandomValues().", "crypto"),
    _r("SOBER-LLM001", "Direct prompt interpolation", "LLM Prompt Injection Risk", Severity.CRITICAL,
       "Untrusted input interpolated directly into an LLM prompt.", "Delimit and validate untrusted input.", "llm", "injection"),
    _r("SOBER-LLM002", "Client-side system prompt leakage", "AI Safety & IP Leakage", Severity.HIGH,
       "Confidential system instructions embedded in client code.", "Keep system prompts server-side.", "llm"),
    _r("SOBER-GHO001", "Silent except: pass", "Silent Error Swallow", Severity.HIGH,
       "Exception swallowed with a blank pass.", "Log or handle the exception.", "ghost-code"),
    _r("SOBER-GHO002", "Empty catch block", "Silent Error Swallow", Severity.HIGH,
       "Empty catch {} discards errors.", "Log or rethrow the error.", "ghost-code"),
    _r("SOBER-GHO003", "Empty promise catch", "Silent Error Swallow", Severity.HIGH,
       "Empty .catch(() => {}) swallows rejections.", "Handle or log the rejection.", "ghost-code"),
    _r("SOBER-GHO004", "Dangling debugger statement", "Debug Debris", Severity.HIGH,
       "Active debugger breakpoint left in code.", "Remove the debugger statement.", "debris"),
    _r("SOBER-GHO005", "Leftover debug print()", "Debug Debris", Severity.LOW,
       "Temporary debug print left in source.", "Remove or replace with structured logging.", "debris"),
    _r("SOBER-GHO006", "Leftover console.log()", "Debug Debris", Severity.LOW,
       "Temporary console.log left in source.", "Remove the debug log.", "debris"),
    _r("SOBER-GHO007", "Stray markdown code fence", "AI Slop Residue", Severity.LOW,
       "Markdown code fence pasted into source.", "Remove the stray fence.", "debris"),
    _r("SOBER-GHO008", "Incomplete AI stub", "Incomplete AI Stub", Severity.MEDIUM,
       "Placeholder/stub left in a production path.", "Implement the production logic.", "stub"),
    _r("SOBER-CHT001", "AI conversational chatter", "AI Conversational Chatter", Severity.LOW,
       "Assistant conversational text left in source.", "Remove the conversational comment.", "debris"),
    _r("SOBER-DUP001", "Redundant function duplication", "Redundant Duplication", Severity.MEDIUM,
       "Equivalent helper re-implemented across files.", "Import and reuse the existing helper.", "duplication"),
]

CATALOG: dict[str, Rule] = {r.id: r for r in _RULES}


def get_rule(rule_id: str) -> Rule | None:
    return CATALOG.get(rule_id)


def all_rules() -> list[Rule]:
    return list(_RULES)


def finding_fingerprint(rule_id: str, file_path: str, snippet: str) -> str:
    """Stable, line-number-independent fingerprint for SARIF partialFingerprints."""
    normalized = " ".join(snippet.split())
    payload = f"{rule_id}|{file_path.replace(chr(92), '/')}|{normalized}"
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:32]
