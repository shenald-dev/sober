from pathlib import Path

from sober.core.scanner import FileToAudit
from sober.detectors import Severity
from sober.detectors.security import audit_security


def test_audit_groq_api_key(tmp_path: Path):
    dummy_groq = "gs" + "k_" + "a" * 48
    f = tmp_path / "service.py"
    f.write_text(f"GROQ_KEY = '{dummy_groq}'\n")
    audit = FileToAudit(f)

    issues = audit_security(audit, tmp_path)
    assert len(issues) == 1
    assert issues[0].category == "Security & Secrets"
    assert issues[0].severity == Severity.CRITICAL
    assert "Groq API Key leaked" in issues[0].title


def test_audit_supabase_key(tmp_path: Path):
    dummy_supabase = "sb" + "p_" + "a" * 40
    f = tmp_path / "client.ts"
    f.write_text(f"const supabase = createClient(url, '{dummy_supabase}');\n")
    audit = FileToAudit(f)

    issues = audit_security(audit, tmp_path)
    assert len(issues) == 1
    assert "Supabase Secret / Service Role Key leaked" in issues[0].title


def test_audit_slack_webhook(tmp_path: Path):
    dummy_slack = "https://" + "hooks.slack.com/services/T" + "12345678/B" + "12345678/" + "a" * 24
    f = tmp_path / "notify.py"
    f.write_text(f"WEBHOOK = '{dummy_slack}'\n")
    audit = FileToAudit(f)

    issues = audit_security(audit, tmp_path)
    assert len(issues) == 1
    assert "Slack Incoming Webhook URL leaked" in issues[0].title


def test_audit_discord_webhook(tmp_path: Path):
    dummy_discord = "https://" + "discord.com/api/webhooks/123456789012345678/" + "a" * 68
    f = tmp_path / "notify.py"
    f.write_text(f"DISCORD = '{dummy_discord}'\n")
    audit = FileToAudit(f)

    issues = audit_security(audit, tmp_path)
    assert len(issues) == 1
    assert "Discord Webhook URL leaked" in issues[0].title


def test_audit_trivial_password(tmp_path: Path):
    f = tmp_path / "db.py"
    f.write_text("connect_db(user='admin', password='password')\n")
    audit = FileToAudit(f)

    issues = audit_security(audit, tmp_path)
    assert len(issues) >= 1
    assert any("trivial / default password" in i.title for i in issues)
