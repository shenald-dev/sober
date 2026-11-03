from sober.core.remediation import generate_agent_remediation_prompt
from sober.detectors import Issue, Severity


def test_remediation_clean_state():
    prompt = generate_agent_remediation_prompt(
        issues=[],
        score=100.0,
        grade="A+",
        status_label="🧊 Crystal Sober",
        files_scanned=10,
    )
    assert "ALL CHECKS PASSED" in prompt
    assert "100.0%" in prompt


def test_remediation_with_issues():
    issues = [
        Issue(
            category="Security & Secrets",
            title="OpenAI API Key leaked",
            description="Found sk-proj...",
            severity=Severity.CRITICAL,
            file_path="config.py",
            line_number=12,
            code_snippet="sk-proj-1234567890",
            fix_suggestion="Move to .env",
        )
    ]
    prompt = generate_agent_remediation_prompt(
        issues=issues,
        score=75.0,
        grade="C",
        status_label="🍸 Noticeable Hangover",
        files_scanned=5,
    )
    assert "SOBER AGENT REMEDIATION DIRECTIVE" in prompt
    assert "config.py:12" in prompt
    assert "OpenAI API Key leaked" in prompt
    assert "Move to .env" in prompt
