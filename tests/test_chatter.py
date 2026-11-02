from sober.core.sanitizer import cure_file
from sober.core.scanner import FileToAudit
from sober.detectors.chatter import audit_chatter


def test_detects_ai_conversational_comments(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("""# Certainly! Here is the updated implementation:
def calculate_tax(amount):
    # As an AI language model, I recommend validating inputs
    rate = 0.05
    # Let me know if you need any adjustments or further enhancements!
    return amount * rate
""")

    issues = audit_chatter(FileToAudit(f), tmp_path)
    assert len(issues) == 3
    assert all(i.category == "AI Conversational Chatter" for i in issues)
    assert all(i.auto_fixable for i in issues)


def test_cure_strips_ai_chatter_comments(tmp_path):
    f = tmp_path / "code.ts"
    f.write_text("""// Here is the complete function:
export function greet(name: string): string {
    // Note: Make sure to replace this placeholder with real database logic
    return `Hello, ${name}`;
}
""")

    count, removed = cure_file(f)
    assert count == 2
    content = f.read_text()
    assert "Here is the complete function" not in content
    assert "Note: Make sure to replace" not in content
    assert "export function greet" in content
